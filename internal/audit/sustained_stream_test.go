package audit

import (
	"fmt"
	"testing"
	"time"
)

// No FlushExpired call or idle interval: admission alone must expire stale
// evidence and leave conservative isolation while the source stays busy.
func TestRecoveringAssemblerSustainedStreamProgress(t *testing.T) {
	a, err := NewBoundedAssembler(time.Second, AssemblerLimits{1, 256, 1024})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1000, 0)
	delivered := 0
	expiredA := 0
	normalLater := 0
	var lastSafe int64
	for i := 0; i < 35; i++ {
		kind := "KERNEL"
		if i < 3 {
			kind = "PATH"
		}
		r := mustParseRecord(t, fmt.Sprintf("type=%s msg=audit(100.1:%d): item=0", kind, i+1))
		r.Source = SourcePosition{Device: 1, Inode: 2, Start: int64(i * 100), Bytes: 100, Valid: true}
		events, _ := a.AddRecovering(r, start.Add(time.Duration(i)*100*time.Millisecond))
		for _, e := range events {
			delivered += len(e.Records)
			if e.ID == "100.1:1" {
				expiredA++
				if e.Complete || e.Completion != CompletionTimeout {
					t.Fatalf("stale event integrity: %#v", e)
				}
			}
			if i >= 20 && e.ID == r.ID {
				canonical := BuildCanonicalEvent(e, CanonicalOptions{})
				if !e.Complete || e.Exceptional || canonical.Event.Type != "KERNEL" || canonical.Event.Integrity != nil {
					t.Fatalf("valid event remains isolated at %v: %#v", time.Duration(i)*100*time.Millisecond, e)
				}
				normalLater++
			}
		}
		keys, keyBytes, spill := a.RejectionTracking()
		if i == 2 && !spill {
			t.Fatal("fixture failed to enter spill isolation")
		}
		if a.Pending() > 1 || a.PendingBytes() > 1024 || keys > 1 || keyBytes > 1024 {
			t.Fatal("resource budget exceeded")
		}
		fallback := SourcePosition{Device: 1, Inode: 2, Start: int64((i + 1) * 100), End: int64((i + 1) * 100), Valid: true}
		safe := a.SafeSourcePosition(fallback)
		if safe.End < lastSafe {
			t.Fatal("checkpoint-safe position regressed")
		}
		lastSafe = safe.End
		if i >= 20 && (a.Pending() != 0 || keys != 0 || spill || safe.End != fallback.End) {
			t.Fatalf("busy stream pinned: pending=%d rejected=%d spill=%v safe=%d want=%d", a.Pending(), keys, spill, safe.End, fallback.End)
		}
	}
	if expiredA != 1 || delivered != 35 || normalLater != 15 || lastSafe != 3500 {
		t.Fatalf("lost/duplicated evidence: expired=%d records=%d normal=%d safe=%d", expiredA, delivered, normalLater, lastSafe)
	}
}

func TestRecoveringExpirationDeliveredAcrossEarlyReturns(t *testing.T) {
	for _, path := range []string{"rejected", "spill", "eoe_bound", "record_bound"} {
		t.Run(path, func(t *testing.T) {
			maxEvents := 1
			if path == "eoe_bound" || path == "record_bound" {
				maxEvents = 2
			}
			a, _ := NewBoundedAssembler(time.Second, AssemblerLimits{maxEvents, 1, 1024})
			start := time.Unix(1000, 0)
			add := func(kind string, id int, offset time.Duration) ([]AssembledEvent, *AssemblerLimitError) {
				return a.AddRecovering(mustParseRecord(t, fmt.Sprintf("type=%s msg=audit(100.1:%d): item=0", kind, id)), start.Add(offset))
			}
			add("PATH", 1, 0)
			add("PATH", 2, 100*time.Millisecond)
			kind, id := "PATH", 2
			if path == "spill" {
				add("PATH", 3, 200*time.Millisecond)
				kind, id = "KERNEL", 4
			}
			if path == "eoe_bound" {
				kind = "EOE"
			}
			events, _ := add(kind, id, time.Second)
			if len(events) != 2 || events[0].ID != "100.1:1" || events[0].Completion != CompletionTimeout || events[0].Complete {
				t.Fatalf("expired evidence lost or reordered: %#v", events)
			}
			if path == "eoe_bound" && (!events[1].Complete || events[1].Exceptional) {
				t.Fatal("full EOE boundary changed")
			}
			for _, e := range a.FlushAll() {
				if e.ID == "100.1:1" {
					t.Fatal("expired evidence emitted twice")
				}
			}
		})
	}
}

func TestRecoveringKeepsTimelyInterleavingAndEmissionOrder(t *testing.T) {
	for _, recordLimit := range []int{2, 4} {
		a, _ := NewBoundedAssembler(time.Second, AssemblerLimits{2, recordLimit, 1024})
		start := time.Unix(1000, 0)
		add := func(kind string, id int, offset time.Duration) []AssembledEvent {
			events, limit := a.AddRecovering(mustParseRecord(t, fmt.Sprintf("type=%s msg=audit(100.1:%d): item=0", kind, id)), start.Add(offset))
			if limit != nil {
				t.Fatal(limit)
			}
			return events
		}
		add("PATH", 1, 0)
		add("PATH", 2, 100*time.Millisecond)
		if e := add("PATH", 1, 700*time.Millisecond); len(e) != 0 {
			t.Fatal("premature interleaved expiration")
		}
		// Event 2 expires, but the older event 1 remains active and completes on
		// this call. Preserve first-observed order across pre-admission expiry.
		events := add("EOE", 1, 1200*time.Millisecond)
		if len(events) != 2 || events[0].ID != "100.1:1" || !events[0].Complete || events[1].ID != "100.1:2" || events[1].Complete || events[1].Completion != CompletionTimeout {
			t.Fatalf("ordering/integrity changed: %#v", events)
		}
	}
}

func TestSpillDrainTracksLiveTailAndPinsOriginalReplayBoundary(t *testing.T) {
	a, _ := NewBoundedAssembler(time.Second, AssemblerLimits{1, 256, 1024})
	start := time.Unix(1000, 0)
	index := 0
	add := func(kind string, id int, offset time.Duration) []AssembledEvent {
		r := mustParseRecord(t, fmt.Sprintf("type=%s msg=audit(100.1:%d): item=0", kind, id))
		r.Source = SourcePosition{Device: 1, Inode: 2, Start: int64(index * 100), Bytes: 100, Valid: true}
		index++
		events, _ := a.AddRecovering(r, start.Add(offset))
		return events
	}
	add("PATH", 1, 0)
	add("PATH", 2, 100*time.Millisecond)
	add("PATH", 3, 200*time.Millisecond)
	// No gap between calls reaches the timeout. The old untracked key's tail
	// becomes individually tracked when room returns, without extending spill.
	add("KERNEL", 4, 800*time.Millisecond)
	add("PATH", 3, 1110*time.Millisecond)
	events := add("PATH", 3, 1250*time.Millisecond)
	_, _, spill := a.RejectionTracking()
	if spill || len(events) != 1 || !events[0].Exceptional {
		t.Fatal("lost conservative tail tracking")
	}
	fallback := SourcePosition{Device: 1, Inode: 2, Start: 600, End: 600, Valid: true}
	if safe := a.SafeSourcePosition(fallback); safe.End != 200 {
		t.Fatalf("restart would lose original spilled prefix: %#v", safe)
	}
	events = add("KERNEL", 5, 1300*time.Millisecond)
	if len(events) != 1 || !events[0].Complete || events[0].Exceptional {
		t.Fatal("unrelated valid event remains isolated")
	}
	events = add("EOE", 3, 1350*time.Millisecond)
	if len(events) != 1 || !events[0].Exceptional {
		t.Fatal("tainted tail called complete")
	}
	if safe := a.SafeSourcePosition(fallback); safe.End != fallback.End {
		t.Fatal("resolved evidence still pins progress")
	}
}

func TestSpillDrainUnderContinuousCompoundEvents(t *testing.T) {
	a, _ := NewBoundedAssembler(time.Second, AssemblerLimits{1, 256, 1024})
	start := time.Unix(1000, 0)
	payloads := 0
	add := func(kind string, id int, offset time.Duration) []AssembledEvent {
		events, _ := a.AddRecovering(mustParseRecord(t, fmt.Sprintf("type=%s msg=audit(100.1:%d): item=0", kind, id)), start.Add(offset))
		for _, e := range events {
			for _, r := range e.Records {
				if r.Type != "EOE" {
					payloads++
				}
			}
		}
		return events
	}
	add("PATH", 1, 0)
	add("PATH", 2, 100*time.Millisecond)
	add("PATH", 3, 200*time.Millisecond)
	for i := 0; i < 60; i++ {
		offset := 300*time.Millisecond + time.Duration(i)*100*time.Millisecond
		add("PATH", i+10, offset)
		events := add("EOE", i+10, offset+50*time.Millisecond)
		if i >= 25 {
			if len(events) != 1 || !events[0].Complete || events[0].Exceptional {
				t.Fatal("continuous complete groups indefinitely extend spill")
			}
			keys, _, spill := a.RejectionTracking()
			if keys != 0 || spill || a.Pending() != 0 {
				t.Fatal("resolved stream retains stale isolation")
			}
		}
	}
	if payloads != 63 {
		t.Fatalf("payload loss/duplication: got %d want 63", payloads)
	}
}
