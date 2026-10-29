package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kstone-sa/aesirguard-audit/internal/collector"
)

func TestLiveGapRecoversAndRestarts(t *testing.T) {
	for _, mode := range []string{"truncate", "unretained", "missing_intermediate"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			input, out, cpPath := filepath.Join(dir, "audit.log"), filepath.Join(dir, "events"), filepath.Join(dir, "checkpoint")
			first := "type=KERNEL msg=audit(100.1:1): device=first\n"
			second := "type=KERNEL msg=audit(100.1:2): device=second\n"
			os.WriteFile(input, []byte(first), 0600)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var diagnostics bytes.Buffer
			done := make(chan error, 1)
			args := []string{"--follow", "--poll-interval=1ms", "--checkpoint-interval=1ms", "--rotation-drain-interval=1ms",
				"--output-file=" + out, "--checkpoint-file=" + cpPath, "--lock-file=" + filepath.Join(dir, "lock"), input}
			go func() { done <- runContext(ctx, args, strings.NewReader(""), io.Discard, &diagnostics) }()
			waitUpgrade(t, func() bool {
				cp, _ := collector.LoadCheckpoint(cpPath)
				return cp != nil && cp.Offset == int64(len(first))
			}, "initial durable position")
			switch mode {
			case "truncate":
				if err := os.Truncate(input, 0); err != nil {
					t.Fatal(err)
				}
				waitUpgrade(t, func() bool {
					ledger, _ := collector.LoadGapLedger(cpPath + ".recovery")
					return ledger != nil && !ledger.Incidents[len(ledger.Incidents)-1].Prepared
				}, "live truncation recovered before append")
			case "unretained":
				if err := os.Remove(input); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(input, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing_intermediate":
				if err := os.Rename(input, input+".3"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(input+".1", []byte("type=KERNEL msg=audit(100.1:9): device=retained\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(input, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			appendUpgrade(t, input, second)
			waitUpgrade(t, func() bool { data, _ := os.ReadFile(out); return bytes.Contains(data, []byte("100.1:2")) }, "valid event after live gap")
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("live recovery failed: %v logs=%s", err, diagnostics.String())
			}
			ledger, err := collector.LoadGapLedger(cpPath + ".recovery")
			if err != nil || ledger == nil || ledger.Total != 1 {
				t.Fatalf("missing/repeated durable gap: %#v %v", ledger, err)
			}
			if !strings.Contains(diagnostics.String(), "recovery_resumed_with_gap") {
				t.Fatal("no resumption diagnostic")
			}
			// The committed lineage must be usable with no state edits on restart.
			ctx, cancel = context.WithCancel(context.Background())
			diagnostics.Reset()
			go func() { done <- runContext(ctx, args, strings.NewReader(""), io.Discard, &diagnostics) }()
			appendUpgrade(t, input, "type=KERNEL msg=audit(100.1:3): device=new\n")
			waitUpgrade(t, func() bool { data, _ := os.ReadFile(out); return bytes.Contains(data, []byte("100.1:3")) }, "new data on recovered lineage")
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			ledger, _ = collector.LoadGapLedger(cpPath + ".recovery")
			if ledger.Total != 1 || strings.Contains(diagnostics.String(), `"event":"source_gap"`) {
				t.Fatal("gap repeats on restart")
			}
		})
	}
}
