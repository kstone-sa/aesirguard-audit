package audit

import (
	"reflect"
	"strings"
	"testing"
)

func TestEmbeddedUSERAVCKeepsSecurityEvidence(t *testing.T) {
	record := mustParseRecord(t, `type=USER_AVC msg=audit(1721721700.000:101): pid=20 auid=1000 AUID="analyst" msg='avc: denied { read write } for name="shadow" scontext=staff_u:staff_r:staff_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0'`)
	event := WithHumanMessage(BuildCanonicalEvent(AssembledEvent{
		ID: record.ID, Records: []Record{record}, Complete: true, Completion: CompletionSingleRecord,
	}, CanonicalOptions{}))
	if record.EmbeddedParseError != "" || len(event.Event.Issues) != 0 {
		t.Fatalf("parse error=%q issues=%#v", record.EmbeddedParseError, event.Event.Issues)
	}
	if event.Security == nil || event.Security.Decision != "denied" ||
		!reflect.DeepEqual(event.Security.Permissions, []string{"read", "write"}) ||
		event.Security.SubjectContext != "staff_u:staff_r:staff_t:s0" ||
		event.Security.TargetContext != "system_u:object_r:shadow_t:s0" ||
		event.Security.TargetClass != "file" || event.Security.Permissive == nil || *event.Security.Permissive {
		t.Fatalf("security=%#v", event.Security)
	}
	if event.Target == nil || event.Target.Name != "shadow" || !strings.Contains(event.Message, "denied") {
		t.Fatalf("target=%#v message=%q", event.Target, event.Message)
	}
}

func TestSecurityClassificationPrecedesExecutionEvidence(t *testing.T) {
	for _, evidence := range []string{"execve", "execveat", "argv"} {
		t.Run(evidence, func(t *testing.T) {
			avc := mustParseRecord(t, `type=AVC msg=audit(1721721700.000:102): avc: denied { execute } for name="tool" permissive=0`)
			context := mustParseRecord(t, `type=SYSCALL msg=audit(1721721700.000:102): success=no exe="/bin/tool" SYSCALL="`+evidence+`"`)
			if evidence == "argv" {
				context = mustParseRecord(t, `type=PROCTITLE msg=audit(1721721700.000:102): proctitle=2f62696e2f746f6f6c00`)
			}
			event := WithHumanMessage(BuildCanonicalEvent(AssembledEvent{
				ID: avc.ID, Records: []Record{context, avc}, Complete: true, Completion: CompletionEOE,
			}, CanonicalOptions{}))
			if event.Event.Type != "AVC" || event.Event.Category != "access_control" ||
				event.Event.Action != "enforce_access_control" || !strings.Contains(event.Message, "denied") {
				t.Fatalf("event=%#v message=%q", event.Event, event.Message)
			}
			if event.Process == nil {
				t.Fatal("lost correlated process evidence")
			}
		})
	}
}

func TestModuleClassificationKeepsSpecificSyscall(t *testing.T) {
	event := CanonicalEvent{
		Event:   CanonicalEventMeta{Type: "KERN_MODULE"},
		Process: &CanonicalProcess{Syscall: "finit_module"},
	}
	classifyCanonicalEvent(&event)
	if event.Event.Action != "load_kernel_module" {
		t.Fatalf("event=%#v", event.Event)
	}
}
