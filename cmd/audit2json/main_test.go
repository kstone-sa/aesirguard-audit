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
	var events []audit.Event
	for {
		var event audit.Event
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
	if events[0].ID != "1721721700.000:80" || events[1].ID != "1721721701.000:81" {
		t.Fatalf("event order = %#v", events)
	}
}
