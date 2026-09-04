package output

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/kstone-sa/audit2json/internal/audit"
)

// Sink synchronously accepts canonical events.
type Sink interface {
	Write(audit.CanonicalEvent) error
	Commit() error
	Close() error
}

// NDJSONSink writes one canonical event per line without an unbounded queue.
type NDJSONSink struct {
	encoder *json.Encoder
	file    *os.File
	path    string
	sync    bool
}

// NewWriterSink creates a synchronous sink over a caller-owned writer.
func NewWriterSink(writer io.Writer) *NDJSONSink {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return &NDJSONSink{encoder: encoder}
}

// OpenFileSink opens an append-only managed output file. When syncEachWrite is
// true, Write returns only after the event line is synced locally.
func OpenFileSink(path string, syncEachWrite bool) (*NDJSONSink, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	sink := NewWriterSink(file)
	sink.file = file
	sink.path = path
	sink.sync = syncEachWrite
	return sink, nil
}

// Write encodes and synchronously writes one complete NDJSON line.
func (sink *NDJSONSink) Write(event audit.CanonicalEvent) error {
	if err := sink.reopenIfRotated(); err != nil {
		return err
	}
	if err := sink.encoder.Encode(event); err != nil {
		return err
	}
	if sink.sync && sink.file != nil {
		return sink.file.Sync()
	}
	return nil
}

// Commit establishes the sink durability boundary used by checkpoints. A
// stdout write has no stronger local operation; managed files are synced.
func (sink *NDJSONSink) Commit() error {
	if err := sink.reopenIfRotated(); err != nil {
		return err
	}
	if sink.file == nil {
		return nil
	}
	return sink.file.Sync()
}

func (sink *NDJSONSink) reopenIfRotated() error {
	if sink.file == nil || sink.path == "" {
		return nil
	}
	openedInfo, err := sink.file.Stat()
	if err != nil {
		return err
	}
	pathInfo, err := os.Stat(sink.path)
	if err == nil && os.SameFile(openedInfo, pathInfo) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	replacement, err := os.OpenFile(sink.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := sink.file.Sync(); err != nil {
		_ = replacement.Close()
		return err
	}
	previous := sink.file
	sink.file = replacement
	sink.encoder = json.NewEncoder(replacement)
	sink.encoder.SetEscapeHTML(false)
	return previous.Close()
}

// Close releases a managed file. Caller-owned writers are not closed.
func (sink *NDJSONSink) Close() error {
	if sink.file == nil {
		return nil
	}
	var syncErr error
	if sink.sync {
		syncErr = sink.file.Sync()
	}
	closeErr := sink.file.Close()
	sink.file = nil
	return errors.Join(syncErr, closeErr)
}
