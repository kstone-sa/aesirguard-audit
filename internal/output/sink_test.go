package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kstone-sa/audit2json/internal/audit"
)

func TestWriterSinkEmitsOneLineWithoutEscapingHTML(t *testing.T) {
	var buffer bytes.Buffer
	sink := NewWriterSink(&buffer)
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0", Message: "a < b"}); err != nil {
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
		if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0", Audit: audit.CanonicalAudit{ID: id}}); err != nil {
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
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0"}); err != nil {
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

func TestFileSinkRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := OpenFileSink(path, false)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected FIFO output rejection")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO output blocked sink setup")
	}
}

func TestFileSinkRejectsUnsafeDirectoryHierarchy(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, symlinkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileSink(filepath.Join(symlinkDirectory, "events.ndjson"), false); err == nil {
		t.Fatal("expected symlinked output directory rejection")
	}
	if err := os.Chmod(realDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileSink(filepath.Join(realDirectory, "events.ndjson"), false); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
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
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0", Message: "before"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0", Message: "after"}); err != nil {
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

func TestFileSinkRejectsSymlinkToRotatedInode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.ndjson")
	rotated := path + ".1"
	sink, err := OpenFileSink(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0", Message: "before"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rotated, path); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0", Message: "after"}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("error = %v", err)
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
		done <- sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0"})
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
