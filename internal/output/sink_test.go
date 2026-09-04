package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kstone-sa/audit2json/internal/audit"
)

func TestWriterSinkEmitsOneLineWithoutEscapingHTML(t *testing.T) {
	var buffer bytes.Buffer
	sink := NewWriterSink(&buffer)
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "0.3", Message: "a < b"}); err != nil {
		t.Fatal(err)
	}
	if got := buffer.String(); !strings.HasSuffix(got, "\n") || strings.Contains(got, `\u003c`) {
		t.Fatalf("output = %q", got)
	}
}

func TestFileSinkAppendsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	for _, id := range []string{"1.0:1", "1.0:2"} {
		sink, err := OpenFileSink(path, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "0.3", Audit: audit.CanonicalAudit{ID: id}}); err != nil {
			t.Fatal(err)
		}
		if err := sink.Close(); err != nil {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(contents), "\n"); lines != 2 {
		t.Fatalf("output lines = %d: %s", lines, contents)
	}
}

func TestFileSinkCommitSyncsWithoutPerEventSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	sink, err := OpenFileSink(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "0.3"}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileSinkRejectsUnsafeTargets(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.ndjson")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink.ndjson")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileSink(symlink, false); err == nil {
		t.Fatal("expected symlink output rejection")
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileSink(target, false); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("error = %v", err)
	}
}

func TestFileSinkReopensAfterRenameRotation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.ndjson")
	rotated := path + ".1"
	sink, err := OpenFileSink(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "0.3", Message: "before"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "0.3", Message: "after"}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	oldContents, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatal(err)
	}
	newContents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(oldContents), "before") || strings.Contains(string(oldContents), "after") || !strings.Contains(string(newContents), "after") {
		t.Fatalf("rotated outputs: old=%s new=%s", oldContents, newContents)
	}
}

type blockingWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (writer *blockingWriter) Write(data []byte) (int, error) {
	writer.once.Do(func() { close(writer.started) })
	<-writer.release
	return len(data), nil
}

func TestWriterSinkAppliesBackPressureSynchronously(t *testing.T) {
	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	sink := NewWriterSink(writer)
	done := make(chan error, 1)
	go func() {
		done <- sink.Write(audit.CanonicalEvent{SchemaVersion: "0.3"})
	}()

	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("sink did not start writing")
	}
	select {
	case err := <-done:
		t.Fatalf("sink returned before writer accepted data: %v", err)
	default:
	}
	close(writer.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
