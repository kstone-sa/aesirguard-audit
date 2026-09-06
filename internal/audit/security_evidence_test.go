package audit

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestMappedRecordPermutationsPreserveSecurityDecision(t *testing.T) {
	lines := []string{
		`type=BPRM_FCAPS msg=audit(100.0:1): fp=0000000000002000`,
		`type=AVC msg=audit(100.0:1): avc: denied { execute } for scontext=source tcontext=target tclass=file permissive=1`,
		`type=SYSCALL msg=audit(100.0:1): pid=12 success=yes subj=unrelated_context`,
	}
	var expected *CanonicalSecurity
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		e := canonicalLines(t, lines[order[0]], lines[order[1]], lines[order[2]])
		if e.Event.Type != "AVC" || e.Security == nil || e.Security.SubjectContext != "source" || e.Security.TargetContext != "target" || e.Security.Permissive == nil || !*e.Security.Permissive {
			t.Fatalf("lost or mixed evidence: %#v", e)
		}
		if expected == nil {
			expected = e.Security
		} else if !reflect.DeepEqual(expected, e.Security) {
			t.Fatal("record order changes security evidence")
		}
	}
}

func TestMultipleDecisionsRetainDistinctContextPairs(t *testing.T) {
	a := `type=AVC msg=audit(100.0:1): avc: denied { read } for scontext=subject_a tcontext=target_a tclass=file permissive=0`
	b := `type=AVC msg=audit(100.0:1): avc: denied { write } for scontext=subject_b tcontext=target_b tclass=dir permissive=1`
	first, second := canonicalLines(t, a, b), canonicalLines(t, b, a)
	if !reflect.DeepEqual(first.Security, second.Security) || len(first.Event.Issues) == 0 || len(second.Event.Issues) == 0 {
		t.Fatal("unstable decision selection or lost secondary decision")
	}
	for _, e := range []CanonicalEvent{first, second} {
		fields := map[string]string{}
		for _, issue := range e.Event.Issues {
			if issue.Code != "additional_security_evidence" {
				continue
			}
			value, err := hex.DecodeString(issue.Value)
			if err != nil {
				t.Fatal(err)
			}
			fields[issue.Field] = string(value)
		}
		if fields["scontext"] == "" || fields["tcontext"] == "" || fields["permissions"] == "" || fields["scontext"] == e.Security.SubjectContext {
			t.Fatalf("secondary decision not recoverable: %#v", fields)
		}
	}
}
