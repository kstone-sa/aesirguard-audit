package audit

import (
	"reflect"
	"testing"
)

func TestLinuxAuditMultiKeys(t *testing.T) {
	for _, key := range []string{`key=6964656e746974790161756469745f636f6e666967`, "key=6964656e746974790161756469745f636f6e666967\x1dKEY=identity\x01audit_config", "key=\"identity\x01audit_config\""} {
		r := mustParseRecord(t, `type=SYSCALL msg=audit(100.1:1): SYSCALL=openat success=yes `+key)
		e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
		if e.Rule == nil || !reflect.DeepEqual(e.Rule.Keys, []string{"identity", "audit_config"}) || e.Event.Category != "configuration" {
			t.Fatalf("multi-key decoding: %#v", e)
		}
	}
}
