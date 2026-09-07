package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSeccompActionAndPointerAreRecordSpecific(t *testing.T) {
	for _, tc := range []struct{ code, filter, action string }{
		{"0x00000000", "kill_thread", "terminate_by_seccomp"},
		{"0x80000000", "kill_process", "terminate_by_seccomp"},
		{"0x00030000", "trap", "trap_syscall"},
		{"0x0005000d", "errno", "block_syscall"},
		{"0x7fc00000", "user_notif", "notify_syscall"},
		{"0x7ff00000", "trace", "trace_syscall"},
		{"0x7ffc0000", "log", "log_syscall"},
		{"0x7fff0000", "allow", "allow_syscall"},
		{"0x12340000", "unknown", "filter_syscall"},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			e := canonicalLines(t, fmt.Sprintf(`type=SECCOMP msg=audit(100.0:1): arch=c000003e syscall=39 ip=0x123 code=%s sig=0`, tc.code))
			if e.Event.Action != tc.action || e.Origin != nil || e.Security == nil || e.Security.Seccomp == nil {
				t.Fatalf("wrong semantics: %#v", e)
			}
			s := e.Security.Seccomp
			if s.Action != tc.filter || s.Code != tc.code || s.InstructionPointer != "0x123" || s.Signal != "0" {
				t.Fatalf("lost filter evidence: %#v", s)
			}
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip CanonicalEvent
			if err := json.Unmarshal(raw, &roundtrip); err != nil {
				t.Fatal(err)
			}
			rendered := WithHumanMessage(roundtrip)
			if strings.Contains(rendered.Message, "from") || strings.Contains(rendered.Message, "attempted to block") {
				t.Fatalf("invented origin or actor intent: %s", rendered.Message)
			}
		})
	}
}

func TestSeccompRemainsPresentWithAVCAndRealAuthenticationOrigin(t *testing.T) {
	seccomp := `type=SECCOMP msg=audit(100.0:1): ip=0x123 code=0x7ffc0000 sig=0`
	avc := `type=AVC msg=audit(100.0:1): avc: denied { read } for scontext=a tcontext=b permissive=1`
	for _, lines := range [][]string{{seccomp, avc}, {avc, seccomp}} {
		e := canonicalLines(t, lines...)
		if e.Security == nil || e.Security.Decision != "denied" || e.Security.Seccomp == nil || e.Security.Seccomp.Action != "log" || e.Origin != nil {
			t.Fatalf("mixed evidence loss: %#v", e)
		}
	}
	e := canonicalLines(t, seccomp, `type=USER_AUTH msg=audit(100.0:1): addr=192.0.2.10 res=success`)
	if e.Origin == nil || e.Origin.Address != "192.0.2.10" {
		t.Fatal("lost actual origin to instruction pointer")
	}
}

func TestConflictingSeccompCodesRemainUnknown(t *testing.T) {
	e := canonicalLines(t, `type=SECCOMP msg=audit(100.0:1): code=0x7ffc0000 code=0x0005000d`)
	if e.Event.Action != "filter_syscall" || e.Security.Seccomp.Action != "unknown" || len(e.Event.Issues) != 4 {
		t.Fatal("concealed conflicting filter codes")
	}
}
