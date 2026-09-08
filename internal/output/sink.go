package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/kstone-sa/aesirguard-audit/internal/audit"
	"github.com/kstone-sa/aesirguard-audit/internal/securefile"
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
	failed  error
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
	file, err := openManagedFile(path)
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
func (sink *NDJSONSink) Write(event audit.CanonicalEvent) (err error) {
	if sink.failed != nil {
		return sink.failed
	}
	defer func() {
		if err != nil {
			sink.failed = err
		}
	}()
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
	if sink.failed != nil {
		return sink.failed
	}
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
	pathInfo, err := os.Lstat(sink.path)
	if err == nil && pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output %s is a symbolic link", sink.path)
	}
	if err == nil && os.SameFile(openedInfo, pathInfo) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	replacement, err := openManagedFile(sink.path)
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

func openManagedFile(path string) (*os.File, error) {
	file, err := securefile.OpenAppend(path, "output", 0o600)
	if err != nil {
		return nil, err
	}
	reject := func(err error) (*os.File, error) { return nil, errors.Join(err, file.Close()) }
	// Each managed inode has one cooperating writer, including batch invocations.
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return reject(fmt.Errorf("lock managed output %s: %w", path, err))
	}
	info, err := file.Stat()
	if err != nil {
		return reject(err)
	}
	if info.Size() != 0 {
		var last [1]byte
		if _, err := file.ReadAt(last[:], info.Size()-1); err != nil {
			return reject(err)
		}
		if last[0] != '\n' {
			return reject(fmt.Errorf("managed output %s has an incomplete NDJSON tail; preserve and repair or quarantine it before restarting", path))
		}
	}
	return file, nil
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
