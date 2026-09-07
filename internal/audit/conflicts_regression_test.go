package audit

import (
	"encoding/hex"
	"testing"
)

func TestConflictingSingletonEvidence(t *testing.T) {
	for _, fields := range []string{`auid=1000 auid=2000 AUID="analyst"`, `exe="/bin/true" exe="/evil"`, `pid=1 pid=2`, `decision=allowed decision=denied`, `permissive=0 permissive=1`} {
		r := mustParseRecord(t, `type=AVC msg=audit(100.1:1): `+fields)
		e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
		count := 0
		for _, issue := range e.Event.Issues {
			if issue.Code == "conflicting_singleton" {
				count++
				if _, err := hex.DecodeString(issue.Value); err != nil {
					t.Fatal(err)
				}
			}
		}
		if count < 2 {
			t.Fatalf("no conflict evidence: %#v", e)
		}
		if e.Actor != nil || (e.Process != nil && (e.Process.Executable != "" || e.Process.PID != "")) || (e.Security != nil && (e.Security.Decision != "" || e.Security.Permissive != nil)) {
			t.Fatalf("authoritative ambiguous value: %#v", e)
		}
	}
}
func TestSingletonIdenticalAndListsRemainValid(t *testing.T) {
	r := mustParseRecord(t, `type=SYSCALL msg=audit(100.1:1): auid=1000 auid=1000 key="one" key="two"`)
	e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
	if len(e.Event.Issues) != 0 || e.Actor == nil || e.Rule == nil || len(e.Rule.Keys) != 2 {
		t.Fatalf("false conflict: %#v", e)
	}
}
func TestCrossRecordAndEmbeddedSingletonConflicts(t *testing.T) {
	for _, lines := range [][]string{
		{`type=SYSCALL msg=audit(100.1:1): exe="/bin/true"`, `type=AVC msg=audit(100.1:1): exe="/evil"`},
		{`type=USER_AUTH msg=audit(100.1:1): exe="/bin/true" msg='exe="/evil" res=failed'`},
	} {
		var records []Record
		for _, line := range lines {
			records = append(records, mustParseRecord(t, line))
		}
		e := BuildCanonicalEvent(AssembledEvent{ID: records[0].ID, Records: records, Complete: true}, CanonicalOptions{})
		if e.Process != nil && e.Process.Executable != "" {
			t.Fatalf("conflicting executable: %#v", e.Process)
		}
		if len(e.Event.Issues) < 2 {
			t.Fatal("missing provenance")
		}
	}
}
