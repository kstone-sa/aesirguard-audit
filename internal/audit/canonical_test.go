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
		record := mustParseRecord(t, scanner.Text())
		events = append(events, assembler.Add(record)...)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	events = append(events, assembler.FlushAll()...)
	if len(events) != 1 {
		t.Fatalf("assembled events = %#v", events)
	}

	got := BuildCanonicalEvent(events[0], CanonicalOptions{})
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

func TestBuildCanonicalEventMarksIncompleteEOF(t *testing.T) {
	record := mustParseRecord(t, `type=SYSCALL msg=audit(1721721700.000:80): syscall=1`)
	assembled := NewAssembler(0)
	assembled.Add(record)
	events := assembled.FlushAll()

	got := BuildCanonicalEvent(events[0], CanonicalOptions{})
	if got.Event.Complete {
		t.Fatal("EOF-flushed event reported complete")
	}
	if got.Event.Completion != CompletionEOF {
		t.Fatalf("completion = %q", got.Event.Completion)
	}
}

func TestBuildCanonicalEventPreservesRepeatedUnmappedFields(t *testing.T) {
	record := mustParseRecord(t, `type=USER_AUTH msg=audit(1721721601.456:43): pid=300 uid=0 msg='op=PAM:authentication res=failed' detail=first detail=second`)
	assembled := AssembledEvent{
		ID:         record.ID,
		Records:    []Record{record},
		Complete:   false,
		Completion: CompletionEOF,
	}

	got := BuildCanonicalEvent(assembled, CanonicalOptions{})
	if len(got.Unmapped) != 1 {
		t.Fatalf("unmapped = %#v", got.Unmapped)
	}
	fields := got.Unmapped[0].Fields
	if want := []string{`op=PAM:authentication res=failed`}; !reflect.DeepEqual(fields["msg"], want) {
		t.Fatalf("nested msg = %#v, want %#v", fields["msg"], want)
	}
	if want := []string{"first", "second"}; !reflect.DeepEqual(fields["detail"], want) {
		t.Fatalf("detail = %#v, want %#v", fields["detail"], want)
	}
}

func TestBuildCanonicalEventReportsInvalidAuditID(t *testing.T) {
	record := mustParseRecord(t, `type=TEST msg=audit(not-a-valid-id): value=kept`)
	assembled := AssembledEvent{ID: record.ID, Records: []Record{record}, Completion: CompletionEOF}

	got := BuildCanonicalEvent(assembled, CanonicalOptions{Host: "override", BootID: "boot-1"})
	if got.Audit.Time != "" || got.Audit.Serial != nil {
		t.Fatalf("audit metadata = %#v", got.Audit)
	}
	if len(got.Event.Issues) != 1 || got.Event.Issues[0].Code != "invalid_audit_id" {
		t.Fatalf("issues = %#v", got.Event.Issues)
	}
	if got.Source == nil || got.Source.Host != "override" || got.Source.BootID != "boot-1" {
		t.Fatalf("source = %#v", got.Source)
	}
}

func TestBuildCanonicalEventPreservesMalformedPathItem(t *testing.T) {
	record := mustParseRecord(t, `type=PATH msg=audit(1721721604.000:46): item=invalid name="/tmp/file"`)
	assembled := AssembledEvent{ID: record.ID, Records: []Record{record}, Completion: CompletionEOF}

	got := BuildCanonicalEvent(assembled, CanonicalOptions{})
	if len(got.Paths) != 1 || got.Paths[0].Item != nil {
		t.Fatalf("paths = %#v", got.Paths)
	}
	if len(got.Unmapped) != 1 || !reflect.DeepEqual(got.Unmapped[0].Fields["item"], []string{"invalid"}) {
		t.Fatalf("unmapped = %#v", got.Unmapped)
	}
}
