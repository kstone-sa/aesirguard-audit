package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kstone-sa/audit2json/internal/audit"
	"github.com/kstone-sa/audit2json/internal/collector"
)

var errInjectedSink = errors.New("injected sink failure")

type faultSink struct {
	writeErr  error
	commitErr error
	writes    int
	commits   int
}

func (sink *faultSink) Write(audit.CanonicalEvent) error {
	sink.writes++
	return sink.writeErr
}

func (sink *faultSink) Commit() error {
	sink.commits++
	return sink.commitErr
}

func (sink *faultSink) Close() error { return nil }

func TestMalformedFallbackDoesNotDisappearOnSinkFailure(t *testing.T) {
	assembler, err := audit.NewBoundedAssembler(time.Second, audit.AssemblerLimits{
		MaxPendingEvents: 1, MaxRecordsPerEvent: 2, MaxPendingBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := &faultSink{writeErr: errInjectedSink}
	diagnostics := newOperationalDiagnostics(io.Discard, 0)
	processor := &eventProcessor{assembler: assembler, sink: sink, diagnostics: diagnostics}
	err = processor.addSourceLine("malformed audit line", audit.SourcePosition{Bytes: 21, Valid: true})
	if !errors.Is(err, errInjectedSink) {
		t.Fatalf("error = %v", err)
	}
	if sink.writes != 1 || diagnostics.counters.ParseFailures != 1 || diagnostics.counters.EmittedEvents != 0 {
		t.Fatalf("writes=%d counters=%#v", sink.writes, diagnostics.counters)
	}
}

func TestCheckpointNeverAdvancesWhenSinkCommitFails(t *testing.T) {
	directory := t.TempDir()
	checkpointPath := filepath.Join(directory, "checkpoint")
	inputPath := filepath.Join(directory, "audit.log")
	position := audit.SourcePosition{Device: 1, Inode: 2, End: 128, Valid: true}
	sink := &faultSink{commitErr: errInjectedSink}
	writer := newCheckpointWriter(commandOptions{
		checkpointPath: checkpointPath, checkpointInterval: time.Nanosecond,
	}, inputPath, audit.SourcePosition{}, false, sink)

	if err := writer.persist(position, true); !errors.Is(err, errInjectedSink) {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(checkpointPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checkpoint exists after failed commit: %v", err)
	}
	if writer.initialized || writer.last.End != 0 {
		t.Fatalf("writer advanced after failure: %#v", writer)
	}

	sink.commitErr = nil
	if err := writer.persist(position, true); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := collector.LoadCheckpoint(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint == nil || checkpoint.Offset != position.End || sink.commits != 2 {
		t.Fatalf("checkpoint=%#v commits=%d", checkpoint, sink.commits)
	}
}
