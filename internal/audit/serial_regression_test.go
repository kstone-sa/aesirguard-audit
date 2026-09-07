package audit

import (
	"testing"
	"time"
)

func TestInvalidSerialCannotChangeWatermark(t *testing.T) {
	for _, bad := range []string{"bogus", "", "-1", "+1", "1:2", "18446744073709551616"} {
		a := NewAssembler(time.Second)
		now := time.Unix(1, 0)
		a.AddAt(mustParseRecord(t, `type=SYSCALL msg=audit(100.0:1): pid=1`), now)
		before := a.latestAuditTime
		events := a.AddAt(mustParseRecord(t, `type=USER_AUTH msg=audit(110.0:`+bad+`): res=failed`), now)
		if !a.latestAuditTime.Equal(before) || a.Pending() != 1 || len(events) != 1 {
			t.Fatalf("invalid serial affected unrelated event: %q %#v", bad, events)
		}
		e := BuildCanonicalEvent(events[0], CanonicalOptions{})
		if e.Audit.Time != "" || len(e.Event.Issues) == 0 {
			t.Fatal("missing malformed ID evidence")
		}
		events = a.AddAt(mustParseRecord(t, `type=EOE msg=audit(100.0:1):`), now)
		if len(events) != 1 || !events[0].Complete || len(events[0].Records) != 2 {
			t.Fatal("valid event was split")
		}
		a.AddAt(mustParseRecord(t, `type=SYSCALL msg=audit(111.0:2): pid=2`), now)
		if a.latestAuditTime.Unix() != 111 {
			t.Fatal("watermark did not recover")
		}
	}
}
