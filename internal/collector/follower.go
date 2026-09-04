package collector

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const defaultReadBufferBytes = 64 * 1024

// FollowerOptions controls polling and the maximum retained physical line.
type FollowerOptions struct {
	PollInterval time.Duration
	MaxLineBytes int
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
}

// OpenFileFollower opens path at offset zero and prepares to wait at EOF.
func OpenFileFollower(path string, options FollowerOptions) (*FileFollower, error) {
	if options.PollInterval <= 0 {
		return nil, fmt.Errorf("poll interval must be positive")
	}
	if options.MaxLineBytes <= 0 {
		return nil, fmt.Errorf("maximum line size must be positive")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &FileFollower{
		path:         path,
		file:         file,
		reader:       bufio.NewReaderSize(file, defaultReadBufferBytes),
		pollInterval: options.PollInterval,
		maxLineBytes: options.MaxLineBytes,
		partial:      make([]byte, 0, defaultReadBufferBytes),
	}, nil
}

// Next returns one complete line. ok is false after an idle poll, allowing the
// caller to expire pending logical events without a separate goroutine.
func (follower *FileFollower) Next(ctx context.Context) (line string, ok bool, err error) {
	for {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		fragment, readErr := follower.reader.ReadSlice('\n')
		if len(fragment) > 0 {
			if len(follower.partial)+len(fragment) > follower.maxLineBytes {
				return "", false, fmt.Errorf("physical line in %s exceeds %d bytes", follower.path, follower.maxLineBytes)
			}
			follower.partial = append(follower.partial, fragment...)
		}

		switch {
		case readErr == nil:
			complete := bytes.TrimSuffix(follower.partial, []byte{'\n'})
			complete = bytes.TrimSuffix(complete, []byte{'\r'})
			line = string(complete)
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
				return "", false, ctx.Err()
			case <-timer.C:
				return "", false, nil
			}
		default:
			return "", false, readErr
		}
	}
}

// Close releases the source descriptor.
func (follower *FileFollower) Close() error {
	return follower.file.Close()
}
