package audit

import (
	"fmt"
	"testing"
	"time"
)

func FuzzRecoveringAssemblerAccountsForPayload(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 7, 1, 2, 3, 8, 9})
	f.Add([]byte{255, 254, 253, 0, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 512 {
			data = data[:512]
		}
		a, _ := NewBoundedAssembler(time.Second, AssemblerLimits{2, 3, 256})
		now := time.Unix(1000, 0)
		received, delivered := 0, 0
		account := func(events []AssembledEvent) {
			for _, e := range events {
				if e.Exceptional && e.Complete {
					t.Fatal("exceptional record called complete")
				}
				for _, r := range e.Records {
					if r.Type != "EOE" {
						delivered++
					}
				}
			}
		}
		types := []string{"PATH", "PATH", "PROCTITLE", "EOE", "KERNEL"}
		for _, b := range data {
			kind := types[int(b)%len(types)]
			line := fmt.Sprintf("node=n%d type=%s msg=audit(100.1:%d): item=0 name=\"/safe\"", (b/5)%2, kind, (b/10)%4)
			r, err := ParseRecord(line)
			if err != nil {
				t.Fatal(err)
			}
			if r.Type != "EOE" {
				received++
			}
			events, _ := a.AddRecovering(r, now)
			account(events)
			keys, keyBytes, _ := a.RejectionTracking()
			if a.Pending() > 2 || a.PendingBytes() > 256 || keys > 2 || keyBytes > 256 {
				t.Fatal("resource budget exceeded")
			}
		}
		account(a.FlushAll())
		if delivered != received {
			t.Fatalf("payload records received=%d delivered=%d", received, delivered)
		}
	})
}
