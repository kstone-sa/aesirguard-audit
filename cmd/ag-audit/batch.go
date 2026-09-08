package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/kstone-sa/aesirguard-audit/internal/audit"
)

func runBatch(ctx context.Context, options commandOptions, stdin io.Reader, processor *eventProcessor) error {
	input := stdin
	if options.inputPath != "" {
		// Never block in open on a FIFO before cancellation can be observed.
		file, err := os.OpenFile(options.inputPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("batch input path must be a regular file; use stdin for streams")
		}
		input = file
	}
	if original, ok := input.(*os.File); ok {
		// Inherited stdin can be in blocking mode outside Go's poller. A
		// nonblocking duplicate makes Close interrupt a pending pipe read.
		fd := original.Fd()
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
		if errno != 0 {
			return errno
		}
		duplicate, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_DUPFD_CLOEXEC, 0)
		if errno != 0 {
			return errno
		}
		if err := syscall.SetNonblock(int(duplicate), true); err != nil {
			syscall.Close(int(duplicate))
			return err
		}
		pollable := os.NewFile(duplicate, original.Name())
		defer func() {
			pollable.Close()
			// Dup shares open-file flags with the caller's descriptor.
			syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFL, flags)
		}()
		input = pollable
	}
	// Only cancellation uses a callback; parsing and output remain synchronous.
	// CLI stdin is a closable file. In-memory test readers need no interruption.
	if closer, ok := input.(io.Closer); ok {
		closed := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { _ = closer.Close(); close(closed) })
		defer func() {
			if !stop() {
				<-closed
			}
		}()
	}
	reader := bufio.NewReaderSize(input, 64*1024)
	var partial []byte
	for {
		if ctx.Err() != nil {
			return processor.flushAll(audit.CompletionShutdown)
		}
		fragment, err := reader.ReadSlice('\n')
		if ctx.Err() != nil {
			return processor.flushAll(audit.CompletionShutdown)
		}
		if len(fragment) > options.maxLineBytes-len(partial) {
			return fmt.Errorf("physical line exceeds %d bytes", options.maxLineBytes)
		}
		partial = append(partial, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if len(partial) > 0 {
			line := bytes.TrimSuffix(partial, []byte{'\n'})
			line = bytes.TrimSuffix(line, []byte{'\r'})
			if err := processor.addLine(string(line)); err != nil {
				return err
			}
			partial = partial[:0]
		}
		if errors.Is(err, io.EOF) {
			return processor.flushAll(audit.CompletionEOF)
		}
	}
}
