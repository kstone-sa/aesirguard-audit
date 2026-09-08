package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kstone-sa/aesirguard-audit/internal/audit"
)

func TestEveryPartialNDJSONBoundaryFailsClosed(t *testing.T) {
	var encoded bytes.Buffer
	event := audit.CanonicalEvent{SchemaVersion: "1.0", Message: "escaped\nline and UTF-8: ü"}
	if err := NewWriterSink(&encoded).Write(event); err != nil {
		t.Fatal(err)
	}
	line := encoded.Bytes()
	for cut := 1; cut < len(line); cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.ndjson")
			original := append(append([]byte{}, line...), line[:cut]...)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			sink, err := OpenFileSink(path, false)
			if err == nil {
				sink.Close()
				t.Fatal("accepted partial physical line")
			}
			actual, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, original) {
				t.Fatal("changed incomplete evidence")
			}
		})
	}
}

type partialFileWriter struct {
	file  *os.File
	count int
}

func (w partialFileWriter) Write(b []byte) (int, error) {
	n, err := w.file.Write(b[:w.count])
	if err != nil {
		return n, err
	}
	return n, errInjectedWriter
}

func TestPositivePartialWritePreventsCommitAndRestartAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	sink, err := OpenFileSink(path, false)
	if err != nil {
		t.Fatal(err)
	}
	sink.encoder = json.NewEncoder(partialFileWriter{sink.file, 7})
	if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0"}); !errors.Is(err, errInjectedWriter) {
		t.Fatal(err)
	}
	if err := sink.Commit(); !errors.Is(err, errInjectedWriter) {
		t.Fatalf("commit after partial write: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenFileSink(path, false)
	if err == nil {
		restarted.Close()
		t.Fatal("restart accepted partial output")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 7 {
		t.Fatalf("restart altered tail: %q", b)
	}
}

func TestRotatedReplacementMustHaveCompleteBoundary(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint(commit), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.ndjson")
			sink, err := OpenFileSink(path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			if err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0"}); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, path+".1"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("{\"partial\":"), 0600); err != nil {
				t.Fatal(err)
			}
			if commit {
				err = sink.Commit()
			} else {
				err = sink.Write(audit.CanonicalEvent{})
			}
			if err == nil {
				t.Fatal("accepted incomplete replacement")
			}
		})
	}
}

func TestManagedOutputAllowsOnlyOneWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	first, err := OpenFileSink(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenFileSink(path, false)
	if err == nil {
		second.Close()
		t.Fatal("allowed competing managed writers")
	}
}
