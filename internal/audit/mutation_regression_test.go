package audit

import (
	"strings"
	"testing"
)

func TestMutationClaimsRequireOperationEvidence(t *testing.T) {
	for _, test := range []struct{ call, key, exit, action string }{
		{"openat", "identity", "3", "observe_configuration_activity"},
		{"adjtimex", "time_change", "0", "observe_system_activity"},
		{"clock_adjtime", "time_change", "0", "observe_system_activity"},
		{"settimeofday", "time_change", "0", "observe_system_activity"},
		{"write", "identity", "0", "observe_configuration_activity"},
		{"write", "identity", "5", "change_identity_configuration"},
		{"chmod", "perm_mod", "0", "change_permissions"},
	} {
		r := mustParseRecord(t, `type=SYSCALL msg=audit(100.1:1): success=yes SYSCALL=`+test.call+` key="`+test.key+`" exit=`+test.exit)
		p := mustParseRecord(t, `type=PATH msg=audit(100.1:1): name="/etc/passwd"`)
		e := WithHumanMessage(BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r, p}, Complete: true}, CanonicalOptions{}))
		if e.Event.Action != test.action {
			t.Fatalf("%s: %#v", test.call, e)
		}
		if strings.HasPrefix(test.action, "observe_") && (strings.Contains(e.Message, "changed") || strings.Contains(e.Message, "modified")) {
			t.Fatalf("overclaim: %s", e.Message)
		}
	}
}
