package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/marios-github/audit2json/internal/audit"
	"github.com/marios-github/audit2json/internal/collector"
	eventoutput "github.com/marios-github/audit2json/internal/output"
)

const (
	defaultPollInterval       = 200 * time.Millisecond
	defaultEventTimeout       = 2 * time.Second
	defaultMaxLineBytes       = 1024 * 1024
	defaultMaxPendingEvents   = 4096
	defaultMaxRecordsPerEvent = 256
	defaultMaxPendingBytes    = 64 * 1024 * 1024
	defaultCheckpointInterval = time.Second
)

type commandOptions struct {
	inputPath          string
	sourceHost         string
	outputPath         string
	lockPath           string
	checkpointPath     string
	follow             bool
	renderMessage      bool
	syncOutput         bool
	pollInterval       time.Duration
	eventTimeout       time.Duration
	maxLineBytes       int
	maxPendingEvents   int
	maxRecordsPerEvent int
	maxPendingBytes    int
	checkpointInterval time.Duration
}

type eventProcessor struct {
	assembler     *audit.Assembler
	sink          eventoutput.Sink
	stderr        io.Writer
	canonical     audit.CanonicalOptions
	renderMessage bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "audit2json:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runContext(context.Background(), args, stdin, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (returnErr error) {
	options, err := parseOptions(args, stderr)
	if err != nil {
		return err
	}

	if options.follow {
		lockPath := options.lockPath
		if lockPath == "" {
			lockPath = collector.DefaultLockPath(options.inputPath)
		}
		lock, acquired, err := collector.AcquireFileLock(lockPath)
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		if !acquired {
			return nil
		}
		defer func() {
			returnErr = errors.Join(returnErr, lock.Close())
		}()
	}

	sink, err := openSink(options, stdout)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, sink.Close())
	}()

	assembler, err := audit.NewBoundedAssembler(options.eventTimeout, audit.AssemblerLimits{
		MaxPendingEvents:   options.maxPendingEvents,
		MaxRecordsPerEvent: options.maxRecordsPerEvent,
		MaxPendingBytes:    options.maxPendingBytes,
	})
	if err != nil {
		return err
	}
	processor := &eventProcessor{
		assembler:     assembler,
		sink:          sink,
		stderr:        stderr,
		canonical:     audit.CanonicalOptions{Host: options.sourceHost},
		renderMessage: options.renderMessage,
	}

	if options.follow {
		return runFollower(ctx, options, processor)
	}
	return runBatch(options, stdin, processor)
}

func parseOptions(args []string, stderr io.Writer) (commandOptions, error) {
	flags := flag.NewFlagSet("audit2json", flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := commandOptions{}
	flags.StringVar(&options.sourceHost, "source-host", "", "include this source host in canonical events")
	flags.StringVar(&options.outputPath, "output-file", "", "append NDJSON to this managed output file instead of stdout")
	flags.StringVar(&options.lockPath, "lock-file", "", "singleton lock path for follow mode")
	flags.StringVar(&options.checkpointPath, "checkpoint-file", "", "durable recovery checkpoint for follow mode")
	flags.BoolVar(&options.follow, "follow", false, "follow a growing audit log until interrupted")
	flags.BoolVar(&options.renderMessage, "render-message", false, "include a deterministic analyst-readable message")
	flags.BoolVar(&options.syncOutput, "sync-output", false, "sync the managed output file after every event")
	flags.DurationVar(&options.pollInterval, "poll-interval", defaultPollInterval, "EOF polling interval in follow mode")
	flags.DurationVar(&options.eventTimeout, "event-timeout", defaultEventTimeout, "maximum inactivity for an unterminated audit event")
	flags.IntVar(&options.maxLineBytes, "max-line-bytes", defaultMaxLineBytes, "maximum physical audit line size")
	flags.IntVar(&options.maxPendingEvents, "max-pending-events", defaultMaxPendingEvents, "maximum unresolved logical events")
	flags.IntVar(&options.maxRecordsPerEvent, "max-records-per-event", defaultMaxRecordsPerEvent, "maximum records retained per unresolved event")
	flags.IntVar(&options.maxPendingBytes, "max-pending-bytes", defaultMaxPendingBytes, "maximum source bytes retained by unresolved events")
	flags.DurationVar(&options.checkpointInterval, "checkpoint-interval", defaultCheckpointInterval, "maximum interval between durable checkpoint updates")
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if flags.NArg() > 1 {
		return options, fmt.Errorf("usage: audit2json [options] [audit.log]")
	}
	if flags.NArg() == 1 {
		options.inputPath = flags.Arg(0)
	}
	if options.follow && options.inputPath == "" {
		return options, fmt.Errorf("follow mode requires an audit log path")
	}
	if options.lockPath != "" && !options.follow {
		return options, fmt.Errorf("lock-file requires follow mode")
	}
	if options.checkpointPath != "" && !options.follow {
		return options, fmt.Errorf("checkpoint-file requires follow mode")
	}
	if options.syncOutput && options.outputPath == "" {
		return options, fmt.Errorf("sync-output requires output-file")
	}
	if options.pollInterval <= 0 || options.eventTimeout <= 0 || options.checkpointInterval <= 0 {
		return options, fmt.Errorf("poll interval, event timeout, and checkpoint interval must be positive")
	}
	if options.maxLineBytes <= 0 || options.maxPendingEvents <= 0 || options.maxRecordsPerEvent <= 0 || options.maxPendingBytes <= 0 {
		return options, fmt.Errorf("collection limits must be positive")
	}
	if options.inputPath != "" && options.outputPath != "" && sameConfiguredPath(options.inputPath, options.outputPath) {
		return options, fmt.Errorf("input and output files must differ")
	}
	if options.lockPath != "" && sameConfiguredPath(options.inputPath, options.lockPath) {
		return options, fmt.Errorf("input and lock files must differ")
	}
	if options.lockPath != "" && options.outputPath != "" && sameConfiguredPath(options.outputPath, options.lockPath) {
		return options, fmt.Errorf("output and lock files must differ")
	}
	for _, conflict := range []struct {
		leftName  string
		leftPath  string
		rightName string
		rightPath string
	}{
		{"input", options.inputPath, "checkpoint", options.checkpointPath},
		{"output", options.outputPath, "checkpoint", options.checkpointPath},
		{"lock", options.lockPath, "checkpoint", options.checkpointPath},
	} {
		if conflict.leftPath != "" && conflict.rightPath != "" && sameConfiguredPath(conflict.leftPath, conflict.rightPath) {
			return options, fmt.Errorf("%s and %s files must differ", conflict.leftName, conflict.rightName)
		}
	}
	return options, nil
}

func openSink(options commandOptions, stdout io.Writer) (eventoutput.Sink, error) {
	if options.outputPath == "" {
		return eventoutput.NewWriterSink(stdout), nil
	}
	sink, err := eventoutput.OpenFileSink(options.outputPath, options.syncOutput)
	if err != nil {
		return nil, fmt.Errorf("open output file: %w", err)
	}
	return sink, nil
}

func runBatch(options commandOptions, stdin io.Reader, processor *eventProcessor) error {
	input := stdin
	var file *os.File
	if options.inputPath != "" {
		var err error
		file, err = os.Open(options.inputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), options.maxLineBytes)
	for scanner.Scan() {
		if err := processor.addLine(scanner.Text()); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return processor.flushAll(audit.CompletionEOF)
}

func runFollower(ctx context.Context, options commandOptions, processor *eventProcessor) error {
	inputPath, err := collector.CanonicalPath(options.inputPath)
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}
	checkpoint, err := loadConfiguredCheckpoint(options.checkpointPath, inputPath)
	if err != nil {
		return err
	}
	var expected *collector.FileIdentity
	var startOffset int64
	if checkpoint != nil {
		expected = &collector.FileIdentity{Device: checkpoint.Device, Inode: checkpoint.Inode}
		startOffset = checkpoint.Offset
	}
	follower, err := collector.OpenFileFollowerAt(options.inputPath, collector.FollowerOptions{
		PollInterval: options.pollInterval,
		MaxLineBytes: options.maxLineBytes,
	}, startOffset, expected)
	if err != nil {
		return err
	}
	defer follower.Close()
	checkpointWriter := newCheckpointWriter(options, inputPath, follower.Identity(), startOffset, checkpoint != nil, processor.sink)
	if err := checkpointWriter.persist(startOffset, true); err != nil {
		return err
	}

	for {
		line, ok, err := follower.NextSource(ctx)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if err := processor.flushAll(audit.CompletionShutdown); err != nil {
				return err
			}
			return checkpointWriter.persist(follower.CompleteOffset(), true)
		}
		if err != nil {
			return err
		}
		if ok {
			source := audit.SourcePosition{
				Device: line.Identity.Device, Inode: line.Identity.Inode,
				Generation: line.Generation, Start: line.Start, End: line.End, Valid: true,
			}
			if err := processor.addSourceLine(line.Text, source); err != nil {
				return err
			}
			safe := processor.assembler.SafeSourcePosition(audit.SourcePosition{
				Device: line.Identity.Device, Inode: line.Identity.Inode,
				Generation: line.Generation, Start: line.End, End: line.End, Valid: true,
			})
			if err := checkpointWriter.persist(safe.End, false); err != nil {
				return err
			}
			continue
		}
		if err := processor.emit(processor.assembler.FlushExpired(time.Now())); err != nil {
			return err
		}
		safe := processor.assembler.SafeSourcePosition(audit.SourcePosition{
			Device: follower.Identity().Device, Inode: follower.Identity().Inode,
			Start: follower.CompleteOffset(), End: follower.CompleteOffset(), Valid: true,
		})
		if err := checkpointWriter.persist(safe.End, false); err != nil {
			return err
		}
	}
}

func loadConfiguredCheckpoint(path, inputPath string) (*collector.Checkpoint, error) {
	if path == "" {
		return nil, nil
	}
	checkpoint, err := collector.LoadCheckpoint(path)
	if err != nil {
		return nil, fmt.Errorf("load checkpoint: %w", err)
	}
	if checkpoint != nil && checkpoint.InputPath != inputPath {
		return nil, fmt.Errorf("checkpoint input %s does not match configured input %s", checkpoint.InputPath, inputPath)
	}
	return checkpoint, nil
}

type checkpointWriter struct {
	path        string
	inputPath   string
	identity    collector.FileIdentity
	interval    time.Duration
	sink        eventoutput.Sink
	lastOffset  int64
	lastAttempt time.Time
	initialized bool
}

func newCheckpointWriter(options commandOptions, inputPath string, identity collector.FileIdentity, offset int64, initialized bool, sink eventoutput.Sink) *checkpointWriter {
	return &checkpointWriter{
		path: options.checkpointPath, inputPath: inputPath, identity: identity,
		interval: options.checkpointInterval, sink: sink, lastOffset: offset,
		lastAttempt: time.Now(), initialized: initialized,
	}
}

func (writer *checkpointWriter) persist(offset int64, force bool) error {
	if writer.path == "" {
		return nil
	}
	if offset < writer.lastOffset {
		return fmt.Errorf("checkpoint offset regressed from %d to %d", writer.lastOffset, offset)
	}
	if writer.initialized && offset == writer.lastOffset {
		return nil
	}
	if !force && time.Since(writer.lastAttempt) < writer.interval {
		return nil
	}
	writer.lastAttempt = time.Now()
	if err := writer.sink.Commit(); err != nil {
		return fmt.Errorf("commit output before checkpoint: %w", err)
	}
	checkpoint := collector.Checkpoint{
		InputPath: writer.inputPath, Device: writer.identity.Device,
		Inode: writer.identity.Inode, Offset: offset,
	}
	if err := collector.SaveCheckpoint(writer.path, checkpoint); err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	writer.lastOffset = offset
	writer.initialized = true
	return nil
}

func (processor *eventProcessor) addLine(line string) error {
	return processor.addSourceLine(line, audit.SourcePosition{})
}

func (processor *eventProcessor) addSourceLine(line string, source audit.SourcePosition) error {
	record, err := audit.ParseRecord(line)
	if err != nil {
		fmt.Fprintln(processor.stderr, "skip:", err)
		return nil
	}
	if source.Valid {
		record.Source = source
		record.SourceBytes = int(source.End - source.Start)
	}
	events, err := processor.assembler.AddChecked(record)
	if err != nil {
		return err
	}
	return processor.emit(events)
}

func (processor *eventProcessor) flushAll(completion audit.Completion) error {
	return processor.emit(processor.assembler.FlushAllWith(completion))
}

func (processor *eventProcessor) emit(events []audit.AssembledEvent) error {
	for _, event := range events {
		output := audit.BuildCanonicalEvent(event, processor.canonical)
		if processor.renderMessage {
			output = audit.WithHumanMessage(output)
		}
		if err := processor.sink.Write(output); err != nil {
			return err
		}
	}
	return nil
}

func sameConfiguredPath(left, right string) bool {
	leftInfo, leftStatErr := os.Stat(left)
	rightInfo, rightStatErr := os.Stat(right)
	if leftStatErr == nil && rightStatErr == nil && os.SameFile(leftInfo, rightInfo) {
		return true
	}
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return filepath.Clean(left) == filepath.Clean(right)
	}
	return filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}
