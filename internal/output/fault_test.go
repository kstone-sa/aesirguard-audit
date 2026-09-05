package output

import (
	"errors"
	"testing"

	"github.com/kstone-sa/audit2json/internal/audit"
)

var errInjectedWriter = errors.New("injected writer failure")

type failingWriter struct {
	writes int
}

func (writer *failingWriter) Write([]byte) (int, error) {
	writer.writes++
	return 0, errInjectedWriter
}

func TestWriterSinkPropagatesConsumerFailure(t *testing.T) {
	writer := &failingWriter{}
	sink := NewWriterSink(writer)
	err := sink.Write(audit.CanonicalEvent{SchemaVersion: "1.0"})
	if !errors.Is(err, errInjectedWriter) || writer.writes != 1 {
		t.Fatalf("error=%v writes=%d", err, writer.writes)
	}
}
