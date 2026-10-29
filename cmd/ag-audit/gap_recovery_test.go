package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/audit"
	"github.com/kstone-sa/aesirguard-audit/internal/collector"
)

func recoveryFixture(t *testing.T) (commandOptions, string, *collector.Checkpoint, collector.SourcePosition) {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(input, []byte("retained\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := collector.OpenFileFollower(input, collector.FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pos := collector.SourcePosition{Identity: f.Identity(), Anchor: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
	options := commandOptions{checkpointPath: filepath.Join(dir, "checkpoint"), lockPath: filepath.Join(dir, "lock")}
	previous := &collector.Checkpoint{Version: 2, InputPath: input, Device: pos.Identity.Device, Inode: pos.Identity.Inode + 100000, Offset: 10, Anchor: pos.Anchor, UpdatedAt: time.Now().UTC()}
	if err := collector.SaveCheckpoint(options.checkpointPath, *previous); err != nil {
		t.Fatal(err)
	}
	return options, input, previous, pos
}

func TestGapRecoveryCrashBoundariesAndIdempotence(t *testing.T) {
	for _, phase := range []string{"prepare", "sink", "checkpoint", "completion", "success"} {
		t.Run(phase, func(t *testing.T) {
			options, input, previous, pos := recoveryFixture(t)
			var diagnostics bytes.Buffer
			diag := newOperationalDiagnostics(&diagnostics, 0)
			manager, err := openGapRecovery(options, input, diag)
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("injected storage failure")
			if phase == "prepare" {
				manager.saveLedger = func(string, collector.GapLedger) error { return failure }
			}
			err = manager.prepare(previous, pos, &collector.SourceGapError{Identity: collector.FileIdentity{Device: previous.Device, Inode: previous.Inode}})
			if phase == "prepare" {
				if !errors.Is(err, failure) {
					t.Fatal(err)
				}
				cp, _ := collector.LoadCheckpoint(options.checkpointPath)
				if !sameCheckpoint(cp, previous) {
					t.Fatal("advanced without durable loss evidence")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Simulate process death after write-ahead recording; disk is authoritative.
			manager, err = openGapRecovery(options, input, diag)
			if err != nil {
				t.Fatal(err)
			}
			resume, err := manager.pending(previous)
			if err != nil || resume == nil {
				t.Fatalf("prepared recovery lost: %v", err)
			}
			sink := &faultSink{}
			if phase == "sink" {
				sink.commitErr = failure
			}
			if phase == "checkpoint" {
				manager.saveCheckpoint = func(string, collector.Checkpoint) error { return failure }
			}
			if phase == "completion" {
				manager.saveLedger = func(string, collector.GapLedger) error { return failure }
			}
			processor := &eventProcessor{assembler: audit.NewAssembler(time.Second), sink: sink, diagnostics: diag}
			err = manager.commit(processor)
			if phase != "success" && !errors.Is(err, failure) {
				t.Fatalf("missing injected failure: %v", err)
			}
			cp, err := collector.LoadCheckpoint(options.checkpointPath)
			if err != nil {
				t.Fatal(err)
			}
			if (phase == "sink" || phase == "checkpoint") && !sameCheckpoint(cp, previous) {
				t.Fatal("checkpoint advanced on IO failure")
			}
			manager, err = openGapRecovery(options, input, diag)
			if err != nil {
				t.Fatal(err)
			}
			resume, err = manager.pending(cp)
			if err != nil {
				t.Fatal(err)
			}
			sink.commitErr = nil
			if phase != "success" {
				if resume == nil {
					t.Fatal("interrupted transition not resumed")
				}
				if err := manager.commit(processor); err != nil {
					t.Fatal(err)
				}
			}
			cp, err = collector.LoadCheckpoint(options.checkpointPath)
			if err != nil || cp.Inode != pos.Identity.Inode || cp.Offset != 0 {
				t.Fatal("invalid resumed checkpoint", err)
			}
			manager, err = openGapRecovery(options, input, newOperationalDiagnostics(io.Discard, 0))
			if err != nil {
				t.Fatal(err)
			}
			pending, err := manager.pending(cp)
			if err != nil || pending != nil || manager.ledger.Total != 1 {
				t.Fatal("repeats recovery", err)
			}
			if !strings.Contains(diagnostics.String(), "recovery_resumed_with_gap") {
				t.Fatal("missing resumed diagnostic")
			}
		})
	}
}

func TestGapLedgerRejectsUnsafeOrCorruptState(t *testing.T) {
	for _, kind := range []string{"symlink", "corrupt", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			options, input, _, _ := recoveryFixture(t)
			path := options.checkpointPath + ".recovery"
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(options.checkpointPath, path)
			case "corrupt":
				err = os.WriteFile(path, []byte(`{"version":1}`), 0600)
			case "oversized":
				err = os.WriteFile(path, make([]byte, 65537), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := openGapRecovery(options, input, newOperationalDiagnostics(io.Discard, 0)); err == nil {
				t.Fatal("unsafe ledger bypassed")
			}
		})
	}
}

func TestFirstRecoveredEventFailureLeavesReplayableCommittedLineage(t *testing.T) {
	options, input, previous, pos := recoveryFixture(t)
	manager, err := openGapRecovery(options, input, newOperationalDiagnostics(io.Discard, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.prepare(previous, pos, &collector.SourceGapError{Identity: collector.FileIdentity{Device: previous.Device, Inode: previous.Inode}}); err != nil {
		t.Fatal(err)
	}
	sink := &faultSink{}
	p := &eventProcessor{assembler: audit.NewAssembler(time.Second), sink: sink, diagnostics: newOperationalDiagnostics(io.Discard, 0)}
	if err := manager.commit(p); err != nil {
		t.Fatal(err)
	}
	sink.writeErr = errInjectedSink
	if err := p.addLine("retained"); !errors.Is(err, errInjectedSink) {
		t.Fatal("first recovered output failure masked", err)
	}
	cp, err := collector.LoadCheckpoint(options.checkpointPath)
	if err != nil || cp.Offset != 0 || cp.Inode != pos.Identity.Inode {
		t.Fatal("lost replay position", err)
	}
	restarted, err := openGapRecovery(options, input, newOperationalDiagnostics(io.Discard, 0))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := restarted.pending(cp)
	if err != nil || pending != nil || restarted.ledger.Total != 1 {
		t.Fatal("repeats committed gap", err)
	}
	sink.writeErr = nil
	if err := p.addLine("retained"); err != nil {
		t.Fatal("cannot replay recovered input", err)
	}
}

func TestGapHistoryBoundedAcrossRepeatedIncidents(t *testing.T) {
	options, input, previous, pos := recoveryFixture(t)
	manager, err := openGapRecovery(options, input, newOperationalDiagnostics(io.Discard, 0))
	if err != nil {
		t.Fatal(err)
	}
	p := &eventProcessor{assembler: audit.NewAssembler(time.Second), sink: &faultSink{}, diagnostics: newOperationalDiagnostics(io.Discard, 0)}
	for i := 0; i < 20; i++ {
		if err := manager.prepare(previous, pos, &collector.SourceGapError{Identity: collector.FileIdentity{Device: previous.Device, Inode: previous.Inode}}); err != nil {
			t.Fatal(err)
		}
		if err := manager.commit(p); err != nil {
			t.Fatal(err)
		}
	}
	ledger, err := collector.LoadGapLedger(options.checkpointPath + ".recovery")
	if err != nil || ledger.Total != 20 || len(ledger.Incidents) != 8 || ledger.Incidents[0].Number != 13 {
		t.Fatalf("unbounded/lost gap history: %#v %v", ledger, err)
	}
}
