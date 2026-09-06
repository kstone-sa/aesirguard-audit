package audit

import (
	"strings"
	"testing"
)

func TestKernelActionResultPrecedesTransportResult(t *testing.T) {
	for _, kind := range []string{"CONFIG_CHANGE", "FEATURE_CHANGE", "MAC_STATUS", "MAC_POLICY_LOAD"} {
		for _, value := range []string{"0", "1"} {
			r := "type=" + kind + " msg=audit(100.0:1): res=" + value
			syscall := `type=SYSCALL msg=audit(100.0:1): success=yes`
			for _, lines := range [][]string{{r, syscall}, {syscall, r}} {
				e := canonicalLines(t, lines...)
				if e.Event.Success == nil || *e.Event.Success != (value == "1") {
					t.Fatalf("%s res=%s: %#v", kind, value, e.Event)
				}
			}
		}
	}
	e := canonicalLines(t, `type=USER_AUTH msg=audit(100.0:1): res=1`)
	if e.Event.Success != nil || len(e.Event.Issues) != 1 {
		t.Fatal("applied kernel Boolean convention to unrelated producer")
	}
	e = canonicalLines(t, `type=CONFIG_CHANGE msg=audit(100.0:1): res=0 res=1`)
	if e.Event.Success != nil || len(e.Event.Issues) != 2 {
		t.Fatal("concealed conflicting results")
	}
}

func TestPermissiveDenialDoesNotClaimEnforcementOrSyscallSuccess(t *testing.T) {
	for _, success := range []string{"yes", "no"} {
		e := WithHumanMessage(canonicalLines(t, `type=AVC msg=audit(100.0:1): avc: denied { execute } for scontext=a tcontext=b permissive=1`, `type=SYSCALL msg=audit(100.0:1): success=`+success))
		if !strings.Contains(e.Message, "not enforced in permissive mode") || strings.Contains(e.Message, "was denied access") || e.Event.Success == nil || *e.Event.Success != (success == "yes") {
			t.Fatalf("misleading permissive result: %#v", e)
		}
	}
	e := WithHumanMessage(canonicalLines(t, `type=AVC msg=audit(100.0:1): avc: denied { execute } for permissive=0`))
	if !strings.Contains(e.Message, "was denied access") {
		t.Fatal("lost enforced denial")
	}
}
