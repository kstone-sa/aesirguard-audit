package audit

import (
	"fmt"
	"testing"
	"time"
)

func TestRecoveringAssemblerBoundariesAndInterleaving(t *testing.T) {
	for _, n := range []int{255, 256, 257, 300} {
		for _, terminal := range []string{"EOE", "PROCTITLE"} {
			t.Run(fmt.Sprintf("%d/%s", n, terminal), func(t *testing.T) {
				a, _ := NewBoundedAssembler(time.Hour, AssemblerLimits{4, 256, 1 << 20})
				now := time.Now()
				var output []AssembledEvent
				limitCount := 0
				// Same ID in another node must remain completely independent.
				a.AddRecovering(mustParseRecord(t, `node=other type=SYSCALL msg=audit(100.1:1): syscall=1`), now)
				for i := 0; i < n; i++ {
					r := mustParseRecord(t, fmt.Sprintf(`node=affected type=PATH msg=audit(100.1:1): item=%d name="/safe"`, i))
					events, limit := a.AddRecovering(r, now)
					output = append(output, events...)
					if limit != nil {
						limitCount++
						if limit.ObservedRecords != 257 || limit.Node != "affected" || limit.CountComplete {
							t.Fatalf("bad limit %#v", limit)
						}
					}
					if a.PendingBytes() > 1<<20 || a.Pending() > 4 {
						t.Fatal("unbounded payload")
					}
				}
				events, limit := a.AddRecovering(mustParseRecord(t, `node=affected type=`+terminal+` msg=audit(100.1:1): proctitle=61`), now)
				if limit != nil {
					limitCount++
					if limit.ObservedRecords != 257 {
						t.Fatal(limit)
					}
				}
				output = append(output, events...)
				oversized := n > 256 || n == 256 && terminal == "PROCTITLE"
				if oversized {
					if limitCount != 1 {
						t.Fatalf("limit count %d", limitCount)
					}
					total := 0
					for _, e := range output {
						if e.Complete || !e.Exceptional {
							t.Fatal("truncated logical event called complete")
						}
						total += len(e.Records)
						for _, r := range e.Records {
							if r.Node != "affected" || r.Raw == "" {
								t.Fatal("lost/cross-node evidence")
							}
						}
					}
					if total != n+1 {
						t.Fatalf("physical evidence %d want %d", total, n+1)
					}
				} else if limitCount != 0 || len(output) != 1 || !output[0].Complete {
					t.Fatalf("normal boundary changed: %#v", output)
				}
				other, _ := a.AddRecovering(mustParseRecord(t, `node=other type=EOE msg=audit(100.1:1):`), now)
				if len(other) != 1 || !other[0].Complete || other[0].Exceptional {
					t.Fatal("unrelated group affected")
				}
				after, _ := a.AddRecovering(mustParseRecord(t, `type=KERNEL msg=audit(100.1:2): device=test`), now)
				if len(after) != 1 || !after[0].Complete {
					t.Fatal("future event blocked")
				}
			})
		}
	}
}

func TestRecoveringAssemblerCountBytesAndHostileKeys(t *testing.T) {
	for _, limits := range []AssemblerLimits{{1, 4, 1024}, {4, 4, 80}} {
		a, _ := NewBoundedAssembler(time.Second, limits)
		now := time.Now()
		for i := 0; i < 100; i++ {
			r := mustParseRecord(t, fmt.Sprintf(`type=PATH msg=audit(100.1:%d): item=0 name="/safe"`, i))
			a.AddRecovering(r, now)
			keys, keyBytes, _ := a.RejectionTracking()
			if a.Pending() > limits.MaxPendingEvents || a.PendingBytes() > limits.MaxPendingBytes || keys > limits.MaxPendingEvents || keyBytes > limits.MaxPendingBytes {
				t.Fatal("unbounded state")
			}
		}
		a.FlushExpired(now.Add(2 * time.Second))
		keys, _, spill := a.RejectionTracking()
		if keys != 0 || spill {
			t.Fatal("exceptional tracking never expires")
		}
		good, _ := a.AddRecovering(mustParseRecord(t, `type=KERNEL msg=audit(100.1:101): a=b`), now.Add(3*time.Second))
		if len(good) != 1 || !good[0].Complete || good[0].Exceptional {
			t.Fatal("not recovered after inactivity fence")
		}
	}
}

func TestRejectedKeyPinsReplayUntilBoundary(t *testing.T) {
	a, _ := NewBoundedAssembler(time.Second, AssemblerLimits{2, 1, 1024})
	now := time.Now()
	for i := 0; i < 3; i++ {
		r := mustParseRecord(t, `type=PATH msg=audit(100.1:1): item=0`)
		r.Source = SourcePosition{Device: 1, Inode: 2, Start: int64(i * 100), Valid: true}
		a.AddRecovering(r, now)
	}
	fallback := SourcePosition{Device: 1, Inode: 2, Start: 300, End: 300, Valid: true}
	if a.SafeSourcePosition(fallback).End != 0 {
		t.Fatal("restart could normalize an exceptional suffix")
	}
	a.AddRecovering(mustParseRecord(t, `type=EOE msg=audit(100.1:1):`), now)
	if a.SafeSourcePosition(fallback).End != 300 {
		t.Fatal("poison event pins progress after boundary")
	}
}
