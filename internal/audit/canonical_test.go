package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestBuildCanonicalEventGolden(t *testing.T) {
	input, err := os.Open("../../testdata/execve.audit")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	assembler := NewAssembler(0)
	var events []AssembledEvent
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		events = append(events, assembler.Add(mustParseRecord(t, scanner.Text()))...)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	events = append(events, assembler.FlushAll()...)
	if len(events) != 1 {
		t.Fatalf("assembled events = %#v", events)
	}

	got := WithHumanMessage(BuildCanonicalEvent(events[0], CanonicalOptions{}))
	wantJSON, err := os.ReadFile("../../testdata/execve.v0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	var want CanonicalEvent
	if err := json.Unmarshal(wantJSON, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("canonical event mismatch\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

func TestBuildCanonicalEventMarksOnlyIncompleteBoundaries(t *testing.T) {
	record := mustParseRecord(t, `type=SYSCALL msg=audit(1721721700.000:80): syscall=1`)
	assembler := NewAssembler(0)
	assembler.Add(record)
	events := assembler.FlushAll()

	got := BuildCanonicalEvent(events[0], CanonicalOptions{})
	if got.Event.Integrity == nil || got.Event.Integrity.State != "incomplete" || got.Event.Integrity.Reason != CompletionEOF {
		t.Fatalf("integrity = %#v", got.Event.Integrity)
	}
}

func TestBuildCanonicalEventCollapsesEqualEnrichedUsers(t *testing.T) {
	record := mustParseRecord(t, `type=SYSCALL msg=audit(1721721601.456:43): auid=1000 uid=1000 euid=1000 AUID="mario" UID="mario" EUID="mario"`)
	assembled := AssembledEvent{ID: record.ID, Records: []Record{record}, Complete: true, Completion: CompletionEOE}

	got := BuildCanonicalEvent(assembled, CanonicalOptions{})
	if got.Actor == nil || got.Actor.User != "mario" || got.Actor.UserID != "" {
		t.Fatalf("actor = %#v", got.Actor)
	}
	if got.Process != nil {
		t.Fatalf("redundant process identity = %#v", got.Process)
	}
	if got.Event.Integrity != nil {
		t.Fatalf("integrity on complete event = %#v", got.Event.Integrity)
	}
}

func TestBuildCanonicalEventUsesIDsForRawInput(t *testing.T) {
	record := mustParseRecord(t, `type=SYSCALL msg=audit(1721721601.456:43): auid=1000 uid=1000 euid=0 pid=10`)
	assembled := AssembledEvent{ID: record.ID, Records: []Record{record}, Complete: true, Completion: CompletionEOE}

	got := BuildCanonicalEvent(assembled, CanonicalOptions{})
	if got.Actor == nil || got.Actor.UserID != "1000" || got.Actor.User != "" {
		t.Fatalf("actor = %#v", got.Actor)
	}
	if got.Process == nil || got.Process.UserID != "0" || got.Process.User != "" || got.Process.RealUserID != "" {
		t.Fatalf("process = %#v", got.Process)
	}
}

func TestBuildCanonicalEventReportsInvalidAndUnsupportedInput(t *testing.T) {
	record := mustParseRecord(t, `type=TEST msg=audit(not-a-valid-id): value=kept`)
	assembled := AssembledEvent{ID: record.ID, Records: []Record{record}, Completion: CompletionEOF}

	got := BuildCanonicalEvent(assembled, CanonicalOptions{Host: "override"})
	if got.Audit.Time != "" {
		t.Fatalf("audit metadata = %#v", got.Audit)
	}
	wantIssues := []CanonicalIssue{
		{Code: "invalid_audit_id", Field: "audit.id", Value: "not-a-valid-id"},
		{Code: "unsupported_record", RecordType: "TEST"},
	}
	if !reflect.DeepEqual(got.Event.Issues, wantIssues) {
		t.Fatalf("issues = %#v, want %#v", got.Event.Issues, wantIssues)
	}
	if got.Source == nil || got.Source.Host != "override" {
		t.Fatalf("source = %#v", got.Source)
	}
}

func TestBuildCanonicalEventOmitsEmptyCapabilities(t *testing.T) {
	record := mustParseRecord(t, `type=PATH msg=audit(1721721604.000:46): item=0 name="/tmp/file" cap_fp=none cap_fi=0000000000000000 cap_fe=0`)
	assembled := AssembledEvent{ID: record.ID, Records: []Record{record}, Completion: CompletionEOF}

	got := BuildCanonicalEvent(assembled, CanonicalOptions{})
	if len(got.Paths) != 1 || got.Paths[0].Capabilities != nil {
		t.Fatalf("paths = %#v", got.Paths)
	}
}
