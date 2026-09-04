package collector

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

const defaultReadBufferBytes = 64 * 1024

// FollowerOptions controls polling and the maximum retained physical line.
type FollowerOptions struct {
	PollInterval time.Duration
	MaxLineBytes int
	Generation   uint64
}

// FileIdentity is stable for one opened file generation.
type FileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// SourceLine is one newline-terminated physical record and its byte range.
type SourceLine struct {
	Text       string
	Identity   FileIdentity
	Generation uint64
	Start      int64
	End        int64
}

// FileFollower reads complete lines from a growing file. It deliberately stays
// attached to the opened inode; input rotation is a separate state machine.
type FileFollower struct {
	path         string
	file         *os.File
	reader       *bufio.Reader
	pollInterval time.Duration
	maxLineBytes int
	partial      []byte
	identity     FileIdentity
	generation   uint64
	readOffset   int64
	lineStart    int64
	completeEnd  int64
}

// OpenFileFollower opens path at offset zero and prepares to wait at EOF.
func OpenFileFollower(path string, options FollowerOptions) (*FileFollower, error) {
	return OpenFileFollowerAt(path, options, 0, nil)
}

// OpenFileFollowerAt opens path at a complete-line offset. When expected is
// non-nil the open file must be the checkpointed generation.
func OpenFileFollowerAt(path string, options FollowerOptions, offset int64, expected *FileIdentity) (*FileFollower, error) {
	if options.PollInterval <= 0 {
		return nil, fmt.Errorf("poll interval must be positive")
	}
	if options.MaxLineBytes <= 0 {
		return nil, fmt.Errorf("maximum line size must be positive")
	}
	if offset < 0 {
		return nil, fmt.Errorf("start offset must not be negative")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	identity, err := identityFromFileInfo(info)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if expected != nil && identity != *expected {
		_ = file.Close()
		return nil, fmt.Errorf("source generation changed: checkpoint device=%d inode=%d, path device=%d inode=%d", expected.Device, expected.Inode, identity.Device, identity.Inode)
	}
	if info.Size() < offset {
		_ = file.Close()
		return nil, fmt.Errorf("source size %d is before checkpoint offset %d", info.Size(), offset)
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &FileFollower{
		path:         path,
		file:         file,
		reader:       bufio.NewReaderSize(file, defaultReadBufferBytes),
		pollInterval: options.PollInterval,
		maxLineBytes: options.MaxLineBytes,
		partial:      make([]byte, 0, defaultReadBufferBytes),
		identity:     identity,
		generation:   options.Generation,
		readOffset:   offset,
		lineStart:    offset,
		completeEnd:  offset,
	}, nil
}

// Next returns one complete line. ok is false after an idle poll, allowing the
// caller to expire pending logical events without a separate goroutine.
func (follower *FileFollower) Next(ctx context.Context) (line string, ok bool, err error) {
	sourceLine, ok, err := follower.NextSource(ctx)
	return sourceLine.Text, ok, err
}

// NextSource returns one complete line with byte and generation provenance.
func (follower *FileFollower) NextSource(ctx context.Context) (line SourceLine, ok bool, err error) {
	for {
		if err := ctx.Err(); err != nil {
			return SourceLine{}, false, err
		}
		fragment, readErr := follower.reader.ReadSlice('\n')
		if len(fragment) > 0 {
			if len(follower.partial)+len(fragment) > follower.maxLineBytes {
				return SourceLine{}, false, fmt.Errorf("physical line in %s exceeds %d bytes", follower.path, follower.maxLineBytes)
			}
			follower.partial = append(follower.partial, fragment...)
			follower.readOffset += int64(len(fragment))
		}

		switch {
		case readErr == nil:
			complete := bytes.TrimSuffix(follower.partial, []byte{'\n'})
			complete = bytes.TrimSuffix(complete, []byte{'\r'})
			line = SourceLine{
				Text:       string(complete),
				Identity:   follower.identity,
				Generation: follower.generation,
				Start:      follower.lineStart,
				End:        follower.readOffset,
			}
			follower.completeEnd = follower.readOffset
			follower.lineStart = follower.readOffset
			follower.partial = follower.partial[:0]
			return line, true, nil
		case errors.Is(readErr, bufio.ErrBufferFull):
			continue
		case errors.Is(readErr, io.EOF):
			timer := time.NewTimer(follower.pollInterval)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return SourceLine{}, false, ctx.Err()
			case <-timer.C:
				return SourceLine{}, false, nil
			}
		default:
			return SourceLine{}, false, readErr
		}
	}
}

// Identity returns the opened generation identity.
func (follower *FileFollower) Identity() FileIdentity { return follower.identity }

// CompleteOffset is the end of the last newline-terminated record.
func (follower *FileFollower) CompleteOffset() int64 { return follower.completeEnd }

func identityFromFileInfo(info os.FileInfo) (FileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileIdentity{}, fmt.Errorf("cannot read file identity")
	}
	return FileIdentity{Device: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}

// Close releases the source descriptor.
func (follower *FileFollower) Close() error {
	return follower.file.Close()
}
