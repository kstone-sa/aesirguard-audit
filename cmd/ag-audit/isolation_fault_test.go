package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/audit"
	eventoutput "github.com/kstone-sa/aesirguard-audit/internal/output"
)

func TestExceptionalEvidenceSinkFailureCannotBecomeSuccess(t *testing.T) {
	a, _ := audit.NewBoundedAssembler(time.Second, audit.AssemblerLimits{MaxPendingEvents: 2, MaxRecordsPerEvent: 1, MaxPendingBytes: 1024})
	sink := &faultSink{writeErr: errInjectedSink}
	p := &eventProcessor{assembler: a, sink: sink, diagnostics: newOperationalDiagnostics(io.Discard, 0)}
	if err := p.addLine(`type=PATH msg=audit(100.1:1): item=0`); err != nil {
		t.Fatal(err)
	}
	if err := p.addLine(`type=PATH msg=audit(100.1:1): item=1`); !errors.Is(err, errInjectedSink) {
		t.Fatalf("masked evidence loss: %v", err)
	}
	if p.diagnostics.counters.EmittedEvents != 0 {
		t.Fatal("failed evidence counted as delivered")
	}
}

func TestInvalidPhysicalInputStillDeliversExpiredEvidence(t *testing.T) {
	for _, kind := range []string{"parse_failure", "line_limit"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := audit.NewBoundedAssembler(time.Second, audit.AssemblerLimits{MaxPendingEvents: 1, MaxRecordsPerEvent: 256, MaxPendingBytes: 1024})
			r, err := audit.ParseRecord(`type=PATH msg=audit(100.1:1): item=0 name="/safe"`)
			if err != nil {
				t.Fatal(err)
			}
			a.AddRecovering(r, time.Now().Add(-2*time.Second))
			var output bytes.Buffer
			p := &eventProcessor{assembler: a, sink: eventoutput.NewWriterSink(&output), diagnostics: newOperationalDiagnostics(io.Discard, 0)}
			if kind == "parse_failure" {
				err = p.addLine("malformed input")
			} else {
				err = p.rejectLine("malformed prefix", 100, audit.SourcePosition{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if a.Pending() != 0 || p.diagnostics.counters.EmittedEvents != 2 || !bytes.Contains(output.Bytes(), []byte(`"reason":"timeout"`)) {
				t.Fatalf("invalid input starved expiry: %s", output.String())
			}
			// Failure to deliver the expired evidence remains a sink failure, not
			// successful progress or permission to advance the source checkpoint.
			a.AddRecovering(r, time.Now().Add(-2*time.Second))
			p.sink = &faultSink{writeErr: errInjectedSink}
			if kind == "parse_failure" {
				err = p.addLine("malformed input")
			} else {
				err = p.rejectLine("malformed prefix", 100, audit.SourcePosition{})
			}
			if !errors.Is(err, errInjectedSink) {
				t.Fatalf("expired output failure masked: %v", err)
			}
		})
	}
}

func TestOversizedPhysicalLineIsolatedAndFollowedByValidEvents(t *testing.T) {
	input := `type=PATH msg=audit(100.1:1): item=0 name="/safe"` + "\n" +
		`type=PATH msg=audit(100.1:1): item=1 name="` + strings.Repeat("x", 2000) + "\"\n" +
		"type=EOE msg=audit(100.1:1):\n" +
		"type=KERNEL msg=audit(100.1:2): device=good\n"
	var output, diagnostics bytes.Buffer
	if err := run([]string{"--max-line-bytes=128"}, strings.NewReader(input), &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(diagnostics.Bytes(), []byte("physical_line_limit_exceeded")) ||
		!bytes.Contains(output.Bytes(), []byte(`"reason":"line_limit"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"id":"100.1:2"`)) ||
		bytes.Count(output.Bytes(), []byte(`"type":"KERNEL"`)) != 1 {
		t.Fatalf("isolation failed: %s", output.String())
	}
	// The affected logical event must never be normalized as a complete tail.
	if bytes.Contains(output.Bytes(), []byte(`"type":"PATH"`)) {
		t.Fatal("partial event normalized after line rejection")
	}
}
