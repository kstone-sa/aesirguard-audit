package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marios-github/audit2json/internal/audit"
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
