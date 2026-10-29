package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/audit"
	"github.com/kstone-sa/aesirguard-audit/internal/collector"
)

// gapRecovery owns the write-ahead transition. Function fields allow failures
// at durable boundaries to be tested without changing production filesystem IO.
type gapRecovery struct {
	path           string
	input          string
	checkpointPath string
	ledger         *collector.GapLedger
	saveLedger     func(string, collector.GapLedger) error
	saveCheckpoint func(string, collector.Checkpoint) error
}

func openGapRecovery(options commandOptions, input string, diagnostics *operationalDiagnostics) (*gapRecovery, error) {
	path := options.checkpointPath
	if path == "" {
		path = options.lockPath
		if path == "" {
			path = collector.DefaultLockPath(input)
		}
	}
	path += ".recovery"
	// Never overwrite another configured resource through the sidecar path.
	for _, other := range []string{input, options.outputPath, options.lockPath, options.checkpointPath} {
		if other != "" && sameConfiguredPath(path, other) {
			return nil, fmt.Errorf("gap ledger conflicts with configured path")
		}
	}
	ledger, err := collector.LoadGapLedger(path)
	if err != nil {
		return nil, fmt.Errorf("load gap ledger: %w", err)
	}
	if ledger != nil && ledger.InputPath != input {
		return nil, fmt.Errorf("gap ledger input mismatch")
	}
	manager := &gapRecovery{path: filepath.Clean(path), input: input, checkpointPath: options.checkpointPath, ledger: ledger,
		saveLedger: collector.SaveGapLedger, saveCheckpoint: collector.SaveCheckpoint}
	if ledger != nil {
		diagnostics.persistentGaps = ledger.Total
		if err := diagnostics.log("warn", "source_gap_history", map[string]any{"persistent_gaps": ledger.Total, "last_gap": ledger.Incidents[len(ledger.Incidents)-1]}); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func sameCheckpoint(a, b *collector.Checkpoint) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.InputPath == b.InputPath && a.Device == b.Device && a.Inode == b.Inode && a.Offset == b.Offset && a.Anchor == b.Anchor
}

func (r *gapRecovery) pending(checkpoint *collector.Checkpoint) (*collector.Checkpoint, error) {
	if r.ledger == nil {
		return nil, nil
	}
	last := &r.ledger.Incidents[len(r.ledger.Incidents)-1]
	if !last.Prepared {
		return nil, nil
	}
	if !sameCheckpoint(checkpoint, last.Previous) && !sameCheckpoint(checkpoint, &last.Resume) {
		return nil, fmt.Errorf("checkpoint does not match prepared recovery evidence")
	}
	return &last.Resume, nil
}

func (r *gapRecovery) prepare(previous *collector.Checkpoint, position collector.SourcePosition, cause error) error {
	if r.ledger == nil {
		r.ledger = &collector.GapLedger{Version: 1, InputPath: r.input}
	}
	if r.ledger.Total == ^uint64(0) {
		return fmt.Errorf("gap incident count exhausted")
	}
	if len(r.ledger.Incidents) > 0 {
		last := &r.ledger.Incidents[len(r.ledger.Incidents)-1]
		if last.Prepared {
			last.Prepared = false
			last.Superseded = true
		}
	}
	r.ledger.Total++
	var identity collector.FileIdentity
	var offset, size *int64
	var gap *collector.SourceGapError
	var truncated *collector.SourceTruncatedError
	if errors.As(cause, &truncated) {
		identity = truncated.Identity
		offset = &truncated.Offset
		size = &truncated.Size
	} else if errors.As(cause, &gap) {
		identity = gap.Identity
	}

	r.ledger.Incidents = append(r.ledger.Incidents, collector.GapIncident{
		Number: r.ledger.Total, ObservedIdentity: identity, ObservedOffset: offset, ObservedSize: size, DetectedAt: time.Now().UTC(), Reason: collector.SourceGapReason(cause), Previous: previous, Prepared: true,
		Resume: collector.Checkpoint{Version: collector.CheckpointVersion, InputPath: r.input, Device: position.Identity.Device, Inode: position.Identity.Inode,
			Offset: position.Offset, Anchor: position.Anchor, UpdatedAt: time.Now().UTC()},
	})
	if len(r.ledger.Incidents) > 8 {
		r.ledger.Incidents = append([]collector.GapIncident(nil), r.ledger.Incidents[len(r.ledger.Incidents)-8:]...)
	}
	if err := r.saveLedger(r.path, *r.ledger); err != nil {
		return fmt.Errorf("persist source gap evidence: %w", err)
	}
	return nil
}

func (r *gapRecovery) commit(processor *eventProcessor) error {
	incident := &r.ledger.Incidents[len(r.ledger.Incidents)-1]
	processor.diagnostics.counters.Gaps++
	processor.diagnostics.persistentGaps = r.ledger.Total
	if err := processor.diagnostics.log("error", "source_gap", map[string]any{
		"incident": incident, "decision": "replay_oldest_contiguous_retained_chain", "potential_data_loss": true, "possible_duplicates": true,
	}); err != nil {
		return err
	}
	// Do not join pending events or a partial physical line across a missing
	// generation. Accepted partial evidence must cross the sink boundary first.
	if err := processor.flushAll(audit.CompletionSourceGap); err != nil {
		return err
	}
	if err := processor.sink.Commit(); err != nil {
		return fmt.Errorf("commit output before gap recovery: %w", err)
	}
	if r.checkpointPath != "" {
		if err := r.saveCheckpoint(r.checkpointPath, incident.Resume); err != nil {
			return fmt.Errorf("commit recovery checkpoint: %w", err)
		}
	}
	incident.Prepared = false
	if err := r.saveLedger(r.path, *r.ledger); err != nil {
		return fmt.Errorf("complete recovery ledger: %w", err)
	}
	return processor.diagnostics.log("warn", "recovery_resumed_with_gap", map[string]any{
		"incident_number": incident.Number, "resume": incident.Resume, "persistent_gaps": r.ledger.Total, "possible_duplicates": true, "potential_data_loss": true,
	})
}
