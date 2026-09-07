package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/kstone-sa/audit2json/internal/collector"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIncompleteManagedOutputCannotAdvanceCheckpoint(t *testing.T) {
	dir := t.TempDir()
	input, output, checkpoint := filepath.Join(dir, "audit.log"), filepath.Join(dir, "events.ndjson"), filepath.Join(dir, "checkpoint")
	if err := os.WriteFile(input, []byte("type=USER_LOGIN msg=audit(100.0:1): res=success\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The exact prior state must remain untouched: output validation precedes
	// checkpoint loading, creation, and any source reads.
	prior := writeRecoveryCheckpoint(t, input, checkpoint)
	if err := os.WriteFile(output, []byte("{\"schema_version\":\"1."), 0600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--follow", "--output-file=" + output, "--checkpoint-file=" + checkpoint, "--lock-file=" + filepath.Join(dir, "lock"), input}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "incomplete NDJSON tail") {
		t.Fatalf("startup result: %v", err)
	}
	actual, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, prior) {
		t.Fatal("checkpoint changed despite invalid output")
	}
}

func writeRecoveryCheckpoint(t *testing.T, input, path string) []byte {
	t.Helper()
	info, err := os.Stat(input)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if err := collector.SaveCheckpoint(path, collector.Checkpoint{InputPath: input, Device: uint64(stat.Dev), Inode: stat.Ino, Offset: 0, Anchor: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestManagedPartialWriteRestartPreservesSourceProgress(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "audit.log")
	output := filepath.Join(dir, "events.ndjson")
	checkpoint := filepath.Join(dir, "checkpoint")
	if err := os.WriteFile(input, []byte("type=USER_LOGIN msg=audit(100.0:1): uid=0 auid=1000 pid=10 res=success\n"), 0600); err != nil {
		t.Fatal(err)
	}
	prior := writeRecoveryCheckpoint(t, input, checkpoint)
	args := []string{"--follow", "--output-file=" + output, "--checkpoint-file=" + checkpoint, "--lock-file=" + filepath.Join(dir, "lock"), input}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(limited bool) []byte {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManagedOutputFaultChild$")
		cmd.Env = append(os.Environ(), "AUDIT2JSON_FAULT_ARGS="+string(encoded), fmt.Sprintf("AUDIT2JSON_FAULT_LIMIT=%t", limited))
		diagnostics, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatal("fault subprocess blocked")
		}
		if err == nil {
			t.Fatalf("fault subprocess accepted damaged output: %s", diagnostics)
		}
		return diagnostics
	}
	invoke(true)
	partial, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(partial) != 128 || partial[len(partial)-1] == '\n' {
		t.Fatalf("did not inject positive partial write: %q", partial)
	}
	if diagnostics := invoke(false); !bytes.Contains(diagnostics, []byte("incomplete NDJSON tail")) {
		t.Fatalf("restart error: %s", diagnostics)
	}
	actual, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, prior) {
		t.Fatal("checkpoint advanced after partial write or restart")
	}
	after, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, partial) {
		t.Fatal("restart appended onto or changed partial evidence")
	}
}

func TestManagedOutputFaultChild(t *testing.T) {
	encoded := os.Getenv("AUDIT2JSON_FAULT_ARGS")
	if encoded == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("AUDIT2JSON_FAULT_LIMIT") == "true" {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 128, Max: 128}); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(args, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
