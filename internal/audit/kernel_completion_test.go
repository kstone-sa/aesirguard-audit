package audit

import (
	"testing"
	"time"
)

func TestKernelSecurityRecordsRequireCompoundEventBoundary(t *testing.T) {
	for _, kind := range []string{"CONFIG_CHANGE", "FEATURE_CHANGE", "MAC_STATUS", "MAC_POLICY_LOAD", "AVC", "SECCOMP", "BPF", "CAPSET", "BPRM_FCAPS"} {
		for _, reverse := range []bool{false, true} {
			t.Run(kind+map[bool]string{true: "/reversed", false: "/forward"}[reverse], func(t *testing.T) {
				a := NewAssembler(time.Second)
				records := []Record{mustParseRecord(t, "type="+kind+" msg=audit(100.0:1): res=1"), mustParseRecord(t, `type=SYSCALL msg=audit(100.0:1): pid=123 exe="/bin/tool" success=yes`)}
				if reverse {
					records[0], records[1] = records[1], records[0]
				}
				for _, r := range records {
					if events := a.Add(r); len(events) != 0 {
						t.Fatalf("premature completion: %#v", events)
					}
				}
				events := a.Add(mustParseRecord(t, `type=EOE msg=audit(100.0:1):`))
				if len(events) != 1 || !events[0].Complete || len(events[0].Records) != 3 {
					t.Fatalf("split compound event: %#v", events)
				}
				e := BuildCanonicalEvent(events[0], CanonicalOptions{})
				if e.Process == nil || e.Process.PID != "123" {
					t.Fatal("lost syscall attribution")
				}
			})
		}
	}
}

func TestUnterminatedKernelRecordIsExplicitlyIncomplete(t *testing.T) {
	a := NewAssembler(time.Second)
	r := mustParseRecord(t, `type=CONFIG_CHANGE msg=audit(100.0:1): op=add_rule res=1`)
	if events := a.Add(r); len(events) != 0 {
		t.Fatal("CONFIG_CHANGE prematurely terminal")
	}
	events := a.FlushAll()
	if len(events) != 1 || events[0].Complete || events[0].Completion != CompletionEOF {
		t.Fatalf("missing incomplete boundary: %#v", events)
	}
}
