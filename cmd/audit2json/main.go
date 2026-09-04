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
	defaultRotationDrain      = 500 * time.Millisecond
	defaultHeartbeatInterval  = 30 * time.Second
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
	rotationDrain      time.Duration
	heartbeatInterval  time.Duration
	configPath         string
	checkConfig        bool
}

type eventProcessor struct {
	assembler     *audit.Assembler
	sink          eventoutput.Sink
	stderr        io.Writer
	canonical     audit.CanonicalOptions
	renderMessage bool
	diagnostics   *operationalDiagnostics
	replayWindow  bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		writeFatalDiagnostic(os.Stderr, err)
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
	diagnostics := newOperationalDiagnostics(stderr, options.heartbeatInterval)
	if options.checkConfig {
		diagnostics.log("info", "configuration_valid", map[string]any{"config": options.configPath})
		return nil
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
			diagnostics.log("info", "singleton_active", map[string]any{"input": options.inputPath, "lock": lockPath})
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
		diagnostics:   diagnostics,
	}
	diagnostics.log("info", "started", map[string]any{"follow": options.follow, "input": options.inputPath, "sink": sinkName(options)})
	defer diagnostics.log("info", "stopped", map[string]any{"counters": &diagnostics.counters})

	if options.follow {
		return runFollower(ctx, options, processor)
	}
	return runBatch(options, stdin, processor)
}

func parseOptions(args []string, stderr io.Writer) (commandOptions, error) {
	configPath, err := bootstrapConfigPath(args)
	if err != nil {
		return commandOptions{}, err
	}
	flags := flag.NewFlagSet("audit2json", flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := commandOptions{
		pollInterval: defaultPollInterval, eventTimeout: defaultEventTimeout,
		maxLineBytes: defaultMaxLineBytes, maxPendingEvents: defaultMaxPendingEvents,
		maxRecordsPerEvent: defaultMaxRecordsPerEvent, maxPendingBytes: defaultMaxPendingBytes,
		checkpointInterval: defaultCheckpointInterval, rotationDrain: defaultRotationDrain,
		heartbeatInterval: defaultHeartbeatInterval, configPath: configPath,
	}
	if configPath != "" {
		config, err := loadFileConfig(configPath)
		if err != nil {
			return options, fmt.Errorf("load configuration: %w", err)
		}
		if err := config.apply(&options); err != nil {
			return options, fmt.Errorf("validate configuration: %w", err)
		}
	}
	flags.StringVar(&options.configPath, "config", configPath, "load versioned JSON configuration")
	flags.BoolVar(&options.checkConfig, "check-config", false, "validate configuration and exit")
	flags.StringVar(&options.sourceHost, "source-host", options.sourceHost, "include this source host in canonical events")
	flags.StringVar(&options.outputPath, "output-file", options.outputPath, "append NDJSON to this managed output file instead of stdout")
	flags.StringVar(&options.lockPath, "lock-file", options.lockPath, "singleton lock path for follow mode")
	flags.StringVar(&options.checkpointPath, "checkpoint-file", options.checkpointPath, "durable recovery checkpoint for follow mode")
	flags.BoolVar(&options.follow, "follow", options.follow, "follow a growing audit log until interrupted")
	flags.BoolVar(&options.renderMessage, "render-message", options.renderMessage, "include a deterministic analyst-readable message")
	flags.BoolVar(&options.syncOutput, "sync-output", options.syncOutput, "sync the managed output file after every event")
	flags.DurationVar(&options.pollInterval, "poll-interval", options.pollInterval, "EOF polling interval in follow mode")
	flags.DurationVar(&options.eventTimeout, "event-timeout", options.eventTimeout, "maximum inactivity for an unterminated audit event")
	flags.IntVar(&options.maxLineBytes, "max-line-bytes", options.maxLineBytes, "maximum physical audit line size")
	flags.IntVar(&options.maxPendingEvents, "max-pending-events", options.maxPendingEvents, "maximum unresolved logical events")
	flags.IntVar(&options.maxRecordsPerEvent, "max-records-per-event", options.maxRecordsPerEvent, "maximum records retained per unresolved event")
	flags.IntVar(&options.maxPendingBytes, "max-pending-bytes", options.maxPendingBytes, "maximum source bytes retained by unresolved events")
	flags.DurationVar(&options.checkpointInterval, "checkpoint-interval", options.checkpointInterval, "maximum interval between durable checkpoint updates")
	flags.DurationVar(&options.rotationDrain, "rotation-drain-interval", options.rotationDrain, "stable EOF time before switching input generations")
	flags.DurationVar(&options.heartbeatInterval, "heartbeat-interval", options.heartbeatInterval, "structured heartbeat interval (zero disables)")
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if flags.NArg() > 1 {
		return options, fmt.Errorf("usage: audit2json [options] [audit.log]")
	}
	if flags.NArg() == 1 {
		options.inputPath = flags.Arg(0)
	}
	if options.checkConfig && options.configPath == "" {
		return options, fmt.Errorf("check-config requires config")
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
	if options.pollInterval <= 0 || options.eventTimeout <= 0 || options.checkpointInterval <= 0 || options.rotationDrain <= 0 || options.heartbeatInterval < 0 {
		return options, fmt.Errorf("poll, event timeout, checkpoint, and rotation drain intervals must be positive")
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

func sinkName(options commandOptions) string {
	if options.outputPath == "" {
		return "stdout"
	}
	return "file"
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
	var startPosition audit.SourcePosition
	if checkpoint != nil {
		startPosition = audit.SourcePosition{
			Device: checkpoint.Device, Inode: checkpoint.Inode,
			Start: checkpoint.Offset, End: checkpoint.Offset, Valid: true,
		}
	}
	follower, err := collector.OpenRotatingFollower(options.inputPath, collector.RotationOptions{
		FollowerOptions: collector.FollowerOptions{PollInterval: options.pollInterval, MaxLineBytes: options.maxLineBytes},
		DrainInterval:   options.rotationDrain,
		ExcludePaths:    []string{options.outputPath, options.checkpointPath, options.lockPath},
	}, checkpoint)
	if err != nil {
		return err
	}
	defer follower.Close()
	if checkpoint == nil {
		position := follower.CompletePosition()
		startPosition = audit.SourcePosition{
			Device: position.Identity.Device, Inode: position.Identity.Inode,
			Generation: position.Generation, Start: position.Offset, End: position.Offset, Valid: true,
		}
	}
	checkpointWriter := newCheckpointWriter(options, inputPath, startPosition, checkpoint != nil, processor.sink)
	if err := checkpointWriter.persist(startPosition, true); err != nil {
		return err
	}
	rotationCount := follower.RotationCount()
	processor.replayWindow = checkpoint != nil
	if checkpoint != nil {
		processor.diagnostics.log("info", "recovery_started", map[string]any{"device": checkpoint.Device, "inode": checkpoint.Inode, "offset": checkpoint.Offset})
	}

	for {
		line, ok, err := follower.Next(ctx)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if err := processor.flushAll(audit.CompletionShutdown); err != nil {
				return err
			}
			return checkpointWriter.persist(sourcePosition(follower.CompletePosition()), true)
		}
		if err != nil {
			var gap *collector.SourceGapError
			var truncated *collector.SourceTruncatedError
			if errors.As(err, &gap) || errors.As(err, &truncated) {
				processor.diagnostics.counters.Gaps++
				processor.diagnostics.log("error", "source_gap", map[string]any{"error": err.Error()})
			}
			return err
		}
		if ok {
			source := audit.SourcePosition{
				Device: line.StartIdentity.Device, Inode: line.StartIdentity.Inode,
				Generation: line.StartGeneration, Start: line.Start, End: line.Start,
				Bytes: line.SourceBytes, Valid: true,
			}
			if err := processor.addSourceLine(line.Text, source); err != nil {
				return err
			}
			safe := processor.assembler.SafeSourcePosition(sourcePosition(follower.CompletePosition()))
			if err := checkpointWriter.persist(safe, false); err != nil {
				return err
			}
			continue
		}
		if follower.RotationCount() != rotationCount {
			rotationCount = follower.RotationCount()
			processor.diagnostics.counters.Rotations = rotationCount
			processor.diagnostics.log("info", "input_rotation", map[string]any{"generation": rotationCount})
		}
		if err := processor.emit(processor.assembler.FlushExpired(time.Now())); err != nil {
			return err
		}
		if processor.replayWindow && follower.CaughtUp() {
			processor.replayWindow = false
			processor.diagnostics.log("info", "recovery_caught_up", map[string]any{"replay_candidates": processor.diagnostics.counters.ReplayCandidates})
		}
		safe := processor.assembler.SafeSourcePosition(sourcePosition(follower.CompletePosition()))
		if err := checkpointWriter.persist(safe, false); err != nil {
			return err
		}
		if processor.diagnostics.heartbeatDue() {
			lagBytes := int64(-1)
			if lag, err := follower.LagBytes(); err == nil {
				lagBytes = lag
			}
			processor.diagnostics.heartbeat(processor, lagBytes)
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
	interval    time.Duration
	sink        eventoutput.Sink
	last        audit.SourcePosition
	lastAttempt time.Time
	initialized bool
}

func newCheckpointWriter(options commandOptions, inputPath string, position audit.SourcePosition, initialized bool, sink eventoutput.Sink) *checkpointWriter {
	return &checkpointWriter{
		path: options.checkpointPath, inputPath: inputPath,
		interval: options.checkpointInterval, sink: sink, last: position,
		lastAttempt: time.Now(), initialized: initialized,
	}
}

func (writer *checkpointWriter) persist(position audit.SourcePosition, force bool) error {
	if writer.path == "" {
		return nil
	}
	if sourcePositionBefore(position, writer.last) {
		return fmt.Errorf("checkpoint position regressed")
	}
	if writer.initialized && sameSourcePosition(position, writer.last) {
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
		InputPath: writer.inputPath, Device: position.Device,
		Inode: position.Inode, Offset: position.End,
	}
	if err := collector.SaveCheckpoint(writer.path, checkpoint); err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	writer.last = position
	writer.initialized = true
	return nil
}

func sourcePosition(position collector.SourcePosition) audit.SourcePosition {
	return audit.SourcePosition{
		Device: position.Identity.Device, Inode: position.Identity.Inode,
		Generation: position.Generation, Start: position.Offset, End: position.Offset, Valid: true,
	}
}

func sourcePositionBefore(left, right audit.SourcePosition) bool {
	if left.Generation != right.Generation {
		return left.Generation < right.Generation
	}
	return left.End < right.End
}

func sameSourcePosition(left, right audit.SourcePosition) bool {
	return left.Device == right.Device && left.Inode == right.Inode && left.End == right.End
}

func (processor *eventProcessor) addLine(line string) error {
	return processor.addSourceLine(line, audit.SourcePosition{})
}

func (processor *eventProcessor) addSourceLine(line string, source audit.SourcePosition) error {
	processor.diagnostics.counters.InputLines++
	lineBytes := len(line) + 1
	if source.Valid && source.Bytes > 0 {
		lineBytes = source.Bytes
	}
	processor.diagnostics.counters.InputBytes += uint64(lineBytes)
	record, err := audit.ParseRecord(line)
	if err != nil {
		processor.diagnostics.counters.ParseFailures++
		processor.diagnostics.log("warn", "parse_failure", map[string]any{"error": err.Error()})
		return nil
	}
	if source.Valid {
		record.Source = source
		if source.Bytes > 0 {
			record.SourceBytes = source.Bytes
		} else {
			record.SourceBytes = int(source.End - source.Start)
		}
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
		processor.diagnostics.counters.EmittedEvents++
		if processor.replayWindow {
			processor.diagnostics.counters.ReplayCandidates++
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
