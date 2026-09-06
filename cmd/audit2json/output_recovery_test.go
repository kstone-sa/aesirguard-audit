package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncompleteManagedOutputCannotAdvanceCheckpoint(t *testing.T) {
	dir := t.TempDir()
	input, output, checkpoint := filepath.Join(dir, "audit.log"), filepath.Join(dir, "events.ndjson"), filepath.Join(dir, "checkpoint")
	if err := os.WriteFile(input, []byte("type=USER_LOGIN msg=audit(100.0:1): res=success\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The exact prior state must remain untouched: output validation precedes
	// checkpoint loading, creation, and any source reads.
	prior := []byte("preserved checkpoint evidence")
	if err := os.WriteFile(checkpoint, prior, 0600); err != nil {
		t.Fatal(err)
	}
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
