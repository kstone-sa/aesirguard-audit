package audit

import (
	"fmt"
	"testing"
	"time"
)

func TestWatermarkDiscontinuityPreservesEventAssembly(t *testing.T) {
	for _, jump := range []int64{61, 1000, 1000000000, -1000} {
		t.Run(fmt.Sprint(jump), func(t *testing.T) {
			a := NewAssembler(2 * time.Second)
			now := time.Unix(1700000000, 0)
			add := func(ts int64, serial int, typ string) []AssembledEvent {
				return a.AddAt(mustParseRecord(t, fmt.Sprintf("type=%s msg=audit(%d.000:%d):", typ, ts, serial)), now)
			}
			if got := add(1700000000, 1, "SYSCALL"); len(got) != 0 {
				t.Fatal(got)
			}
			if got := add(1700000000+jump, 2, "SYSCALL"); len(got) != 0 {
				t.Fatalf("jump expired unrelated evidence: %#v", got)
			}
			// Pending evidence across epochs remains joinable, not silently evicted.
			add(1700000000, 1, "PATH")
			if got := add(1700000000, 1, "EOE"); len(got) != 1 || !got[0].Complete || len(got[0].Records) != 3 {
				t.Fatalf("split original event: %#v", got)
			}
			for serial := 3; serial < 20; serial++ {
				ts := int64(1700000000 + serial)
				add(ts, serial, "SYSCALL")
				add(ts, serial, "PATH")
				got := add(ts, serial, "EOE")
				if len(got) != 1 || !got[0].Complete || len(got[0].Records) != 3 {
					t.Fatalf("normal flow poisoned: %#v", got)
				}
			}
			got := a.FlushExpired(now.Add(2 * time.Second))
			if len(got) != 1 || got[0].Completion != CompletionTimeout {
				t.Fatalf("outlier did not expire by inactivity: %#v", got)
			}
		})
	}
}

func TestWatermarkOutOfOrderAndMalformedTimestamps(t *testing.T) {
	a := NewAssembler(2 * time.Second)
	now := time.Unix(1700000000, 0)
	for _, stamp := range []string{"1700000000.500:1", "1700000000.000:2", "999999999999999999999.0:3", "9999999999.000000000x:4", "+9999999999.0:5"} {
		if got := a.AddAt(Record{Type: "SYSCALL", ID: stamp}, now); len(got) != 0 {
			t.Fatalf("unexpected expiry: %#v", got)
		}
	}
	want := time.Unix(1700000000, 500000000)
	if !a.latestAuditTime.Equal(want) {
		t.Fatalf("watermark=%s want=%s", a.latestAuditTime, want)
	}
	for _, stamp := range []string{"1700000000.500:1", "1700000000.000:2"} {
		got := a.AddAt(Record{Type: "EOE", ID: stamp}, now)
		if len(got) != 1 || !got[0].Complete {
			t.Fatal(got)
		}
	}
	if got := a.FlushExpired(now.Add(2 * time.Second)); len(got) != 3 {
		t.Fatalf("malformed timestamps lost/became immortal: %#v", got)
	}
}
