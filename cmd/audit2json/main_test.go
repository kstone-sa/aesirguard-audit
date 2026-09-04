package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/marios-github/audit2json/internal/audit"
)

func TestRunFlushesIncompleteEventsInInputOrder(t *testing.T) {
	input := strings.Join([]string{
		`type=SYSCALL msg=audit(1721721700.000:80): syscall=1`,
		`type=SYSCALL msg=audit(1721721701.000:81): syscall=2`,
	}, "\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run(nil, strings.NewReader(input), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&stdout)
	var events []audit.CanonicalEvent
	for {
		var event audit.CanonicalEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 2 {
		t.Fatalf("events = %#v; stderr = %q", events, stderr.String())
	}
	if events[0].Audit.ID != "1721721700.000:80" || events[1].Audit.ID != "1721721701.000:81" {
		t.Fatalf("event order = %#v", events)
	}
	if events[0].Event.Complete || events[0].Event.Completion != audit.CompletionEOF {
		t.Fatalf("completion metadata = %#v", events[0].Event)
	}
}

func TestRunSupportsLegacySchema(t *testing.T) {
	input := `type=SYSCALL msg=audit(1721721700.000:80): syscall=1 key="legacy"`
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run([]string{"--schema", "v0.1"}, strings.NewReader(input), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var event audit.Event
	if err := json.NewDecoder(&stdout).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.ID != "1721721700.000:80" || event.Key != "legacy" {
		t.Fatalf("legacy event = %#v", event)
	}
}

func TestRunRejectsUnknownSchema(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"--schema", "future"}, strings.NewReader(""), &stdout, &stderr); err == nil {
		t.Fatal("expected an error")
	}
}
