package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kstone-sa/audit2json/internal/audit"
	"github.com/kstone-sa/audit2json/internal/collector"
)

func TestRunFlushesIncompleteEventsInInputOrder(t *testing.T) {
	input := strings.Join([]string{
		`type=SYSCALL msg=audit(1721721700.000:80): syscall=1`,
		`type=SYSCALL msg=audit(1721721701.000:81): syscall=2`,
	}, "\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run(nil, strings.NewReader(input), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&stdout)
	var events []audit.CanonicalEvent
	for {
		var event audit.CanonicalEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 2 {
		t.Fatalf("events = %#v; stderr = %q", events, stderr.String())
	}
	if events[0].Audit.ID != "1721721700.000:80" || events[1].Audit.ID != "1721721701.000:81" {
		t.Fatalf("event order = %#v", events)
	}
	if events[0].Event.Integrity == nil || events[0].Event.Integrity.Reason != audit.CompletionEOF {
		t.Fatalf("completion metadata = %#v", events[0].Event)
	}
}

func TestRunOptionallyRendersMessage(t *testing.T) {
	input := strings.Join([]string{
		`type=SYSCALL msg=audit(1721721700.000:80): auid=1000 euid=0 pid=10 exe="/usr/bin/sudo" AUID="mario" EUID="root"`,
		`type=EXECVE msg=audit(1721721700.000:80): argc=2 a0="sudo" a1="id"`,
		`type=EOE msg=audit(1721721700.000:80):`,
	}, "\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run([]string{"--render-message"}, strings.NewReader(input), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var event audit.CanonicalEvent
	if err := json.NewDecoder(&stdout).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Message != "mario attempted to execute /usr/bin/sudo as root with arguments: id" || event.Renderer != audit.HumanRendererVersion {
		t.Fatalf("rendered event = %#v", event)
	}
}

func TestRunPreservesMalformedLineAsFallbackEvent(t *testing.T) {
	const input = `type=SYSCALL msg=audit(1721721702.000:82): broken`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run(nil, strings.NewReader(input), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var event audit.CanonicalEvent
	if err := json.NewDecoder(&stdout).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Audit.ID != "1721721702.000:82" || event.Audit.Raw != input || event.Event.Action != "parse_failure" {
		t.Fatalf("fallback event = %#v", event)
	}
}

func TestRunFollowerStreamsAppendedEventAndStops(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "audit.log")
	outputPath := filepath.Join(directory, "audit.ndjson")
	lockPath := filepath.Join(directory, "audit.lock")
	if err := os.WriteFile(inputPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var stderr bytes.Buffer
	go func() {
		done <- runContext(ctx, []string{
			"--follow",
			"--poll-interval=5ms",
			"--output-file=" + outputPath,
			"--lock-file=" + lockPath,
			inputPath,
		}, strings.NewReader(""), io.Discard, &stderr)
	}()
	waitForFile(t, lockPath)

	file, err := os.OpenFile(inputPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString(strings.Join([]string{
		`type=SYSCALL msg=audit(1721721800.000:90): success=yes auid=1000 AUID="mario"`,
		`type=EOE msg=audit(1721721800.000:90):`,
	}, "\n") + "\n")
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	waitForOutput(t, outputPath)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follow error = %v; stderr = %q", err, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follow mode did not stop after cancellation")
	}

	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var event audit.CanonicalEvent
	if err := json.Unmarshal(bytes.TrimSpace(contents), &event); err != nil {
		t.Fatal(err)
	}
	if event.Audit.ID != "1721721800.000:90" || event.Event.Success == nil || !*event.Event.Success {
		t.Fatalf("streamed event = %#v", event)
	}
}

func TestRunFollowerFlushesPendingEventOnShutdown(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "audit.log")
	outputPath := filepath.Join(directory, "audit.ndjson")
	lockPath := filepath.Join(directory, "audit.lock")
	line := `type=SYSCALL msg=audit(1721721801.000:91): syscall=1` + "\n"
	if err := os.WriteFile(inputPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runContext(ctx, []string{
			"--follow",
			"--poll-interval=5ms",
			"--event-timeout=1h",
			"--output-file=" + outputPath,
			"--lock-file=" + lockPath,
			inputPath,
		}, strings.NewReader(""), io.Discard, io.Discard)
	}()
	waitForFile(t, lockPath)
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, outputPath)
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var event audit.CanonicalEvent
	if err := json.Unmarshal(bytes.TrimSpace(contents), &event); err != nil {
		t.Fatal(err)
	}
	if event.Event.Integrity == nil || event.Event.Integrity.Reason != audit.CompletionShutdown {
		t.Fatalf("shutdown event = %#v", event)
	}
}

func TestRunFollowerExitsSuccessfullyWhenLockIsOwned(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "audit.log")
	lockPath := filepath.Join(directory, "audit.lock")
	if err := os.WriteFile(inputPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	args := []string{"--follow", "--poll-interval=5ms", "--lock-file=" + lockPath, inputPath}
	go func() {
		done <- runContext(ctx, args, strings.NewReader(""), io.Discard, io.Discard)
	}()
	waitForFile(t, lockPath)

	var stdout bytes.Buffer
	if err := runContext(context.Background(), args, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("contending process output = %q", stdout.String())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunFollowerResumesFromCheckpoint(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "audit.log")
	checkpointPath := filepath.Join(directory, "audit.checkpoint")
	if err := os.WriteFile(inputPath, []byte(strings.Join([]string{
		`type=KERNEL msg=audit(1721721900.000:100): device=one`,
		`type=KERNEL msg=audit(1721721901.000:101): device=two`,
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	firstOutput := filepath.Join(directory, "first.ndjson")
	runFollowerUntilOutput(t, inputPath, firstOutput, checkpointPath, 2)
	checkpoint, err := collector.LoadCheckpoint(checkpointPath)
	if err != nil || checkpoint == nil {
		t.Fatalf("checkpoint = %#v, %v", checkpoint, err)
	}
	info, err := os.Stat(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Offset != info.Size() {
		t.Fatalf("checkpoint offset = %d, want %d", checkpoint.Offset, info.Size())
	}

	file, err := os.OpenFile(inputPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(`type=KERNEL msg=audit(1721721902.000:102): device=three` + "\n")
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	secondOutput := filepath.Join(directory, "second.ndjson")
	runFollowerUntilOutput(t, inputPath, secondOutput, checkpointPath, 1)
	contents, err := os.ReadFile(secondOutput)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), `"100"`) || strings.Contains(string(contents), `"101"`) || !strings.Contains(string(contents), `1721721902.000:102`) {
		t.Fatalf("resumed output = %s", contents)
	}
}

func TestRunFollowerCheckpointStopsBeforeUnresolvedEvent(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "audit.log")
	outputPath := filepath.Join(directory, "audit.ndjson")
	checkpointPath := filepath.Join(directory, "audit.checkpoint")
	lockPath := filepath.Join(directory, "audit.lock")
	input := strings.Join([]string{
		`type=SYSCALL msg=audit(1721721910.000:110): syscall=1`,
		`type=KERNEL msg=audit(1721721911.000:111): device=complete`,
	}, "\n") + "\n"
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runContext(ctx, []string{
			"--follow", "--poll-interval=5ms", "--event-timeout=1h", "--checkpoint-interval=1ms",
			"--output-file=" + outputPath, "--checkpoint-file=" + checkpointPath,
			"--lock-file=" + lockPath, inputPath,
		}, strings.NewReader(""), io.Discard, io.Discard)
	}()
	waitForOutput(t, outputPath)
	deadline := time.Now().Add(2 * time.Second)
	for {
		checkpoint, err := collector.LoadCheckpoint(checkpointPath)
		if err == nil && checkpoint != nil && checkpoint.Offset == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("safe checkpoint not observed: %#v, %v", checkpoint, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunFollowerContinuesAcrossRenameRotation(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "audit.log")
	outputPath := filepath.Join(directory, "events.ndjson")
	checkpointPath := filepath.Join(directory, "checkpoint")
	lockPath := filepath.Join(directory, "lock")
	if err := os.WriteFile(inputPath, []byte(`type=KERNEL msg=audit(1721721920.000:120): device=old`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runContext(ctx, []string{
			"--follow", "--poll-interval=5ms", "--rotation-drain-interval=10ms", "--checkpoint-interval=5ms",
			"--output-file=" + outputPath, "--checkpoint-file=" + checkpointPath,
			"--lock-file=" + lockPath, inputPath,
		}, strings.NewReader(""), io.Discard, io.Discard)
	}()
	waitForOutputLines(t, outputPath, 1)
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, []byte(`type=KERNEL msg=audit(1721721921.000:121): device=new`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForOutputLines(t, outputPath, 2)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "1721721920.000:120") || !strings.Contains(string(contents), "1721721921.000:121") {
		t.Fatalf("rotated output = %s", contents)
	}
	checkpoint, err := collector.LoadCheckpoint(checkpointPath)
	if err != nil || checkpoint == nil {
		t.Fatalf("checkpoint = %#v, %v", checkpoint, err)
	}
	info, err := os.Stat(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Offset != info.Size() {
		t.Fatalf("checkpoint offset = %d, want %d", checkpoint.Offset, info.Size())
	}
}

func TestRunRejectsConflictingStatePaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--output-file=" + path, path}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected input/output conflict")
	}
	if err := run([]string{"--follow", "--lock-file=" + path, path}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected input/lock conflict")
	}
}

func TestParseOptionsLoadsConfigAndAppliesCLIOverrides(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "audit2json.json")
	config := `{
  "version": 1,
  "input": {"path": "/var/log/audit/audit.log", "follow": true, "source_host": "configured"},
  "sink": {"file": "/var/log/audit2json/events.ndjson", "sync": true},
  "checkpoint": {"file": "/var/lib/audit2json/checkpoint", "interval": "3s"},
  "collection": {"poll_interval": "250ms", "event_timeout": "4s", "rotation_drain_interval": "750ms"},
  "mapping": {"render_message": true},
  "operations": {"heartbeat_interval": "15s"}
}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	options, err := parseOptions([]string{"--config", configPath, "--source-host=override", "--poll-interval=10ms"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if options.inputPath != "/var/log/audit/audit.log" || !options.follow || options.sourceHost != "override" {
		t.Fatalf("input options = %#v", options)
	}
	if options.outputPath != "/var/log/audit2json/events.ndjson" || !options.syncOutput || !options.renderMessage {
		t.Fatalf("sink and mapping options = %#v", options)
	}
	if options.pollInterval != 10*time.Millisecond || options.eventTimeout != 4*time.Second || options.checkpointInterval != 3*time.Second || options.heartbeatInterval != 15*time.Second {
		t.Fatalf("duration options = %#v", options)
	}
}

func TestParseOptionsAcceptsSingleDashConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "audit2json.json")
	if err := os.WriteFile(configPath, []byte(`{"version":1,"input":{"source_host":"configured"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	options, err := parseOptions([]string{"-config", configPath}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if options.sourceHost != "configured" {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseOptionsRejectsDuplicateConfig(t *testing.T) {
	if _, err := parseOptions([]string{"--config=first.json", "-config", "second.json"}, io.Discard); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunHelpUsesStdoutWithoutDiagnostics(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"--help"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "usage: audit2json") || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestRunVersionUsesStdoutWithoutDiagnostics(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "audit2json dev commit=unknown built=unknown") || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestParseOptionsRejectsUnknownConfigField(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "audit2json.json")
	if err := os.WriteFile(configPath, []byte(`{"version":1,"surprise":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseOptions([]string{"--config=" + configPath, "--check-config"}, io.Discard); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseOptionsRejectsUnsafeConfigFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := parseOptions([]string{"--config=" + symlink}, io.Discard); err == nil {
		t.Fatal("expected symlink configuration rejection")
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := parseOptions([]string{"--config=" + target}, io.Discard); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseOptionsRejectsFIFOConfigWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := parseOptions([]string{"--config=" + path}, io.Discard)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO configuration blocked validation")
	}
}

func TestRunCheckConfigEmitsStructuredDiagnostic(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "audit2json.json")
	if err := os.WriteFile(configPath, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := run([]string{"--config=" + configPath, "--check-config"}, strings.NewReader(""), io.Discard, &stderr); err != nil {
		t.Fatal(err)
	}
	var diagnostic map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &diagnostic); err != nil {
		t.Fatalf("diagnostic = %q: %v", stderr.String(), err)
	}
	if diagnostic["event"] != "configuration_valid" || diagnostic["level"] != "info" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func TestOperationalHeartbeatContainsCountersAndGauges(t *testing.T) {
	var output bytes.Buffer
	diagnostics := newOperationalDiagnostics(&output, time.Nanosecond)
	diagnostics.nextHeartbeat = time.Time{}
	diagnostics.counters.InputLines = 2
	assembler, err := audit.NewBoundedAssembler(time.Second, audit.AssemblerLimits{
		MaxPendingEvents: 2, MaxRecordsPerEvent: 2, MaxPendingBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	processor := &eventProcessor{assembler: assembler}
	if !diagnostics.heartbeatDue() {
		t.Fatal("heartbeat should be due")
	}
	if err := diagnostics.heartbeat(processor, 42); err != nil {
		t.Fatal(err)
	}
	var heartbeat struct {
		Event         string            `json:"event"`
		InputLagBytes int64             `json:"input_lag_bytes"`
		Counters      operationCounters `json:"counters"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &heartbeat); err != nil {
		t.Fatal(err)
	}
	if heartbeat.Event != "heartbeat" || heartbeat.InputLagBytes != 42 || heartbeat.Counters.InputLines != 2 {
		t.Fatalf("heartbeat = %#v", heartbeat)
	}
}

func TestRunFollowerEmitsHeartbeatWhileBacklogIsActive(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "audit.log")
	if err := os.WriteFile(inputPath, []byte(`type=KERNEL msg=audit(1721722000.000:200): device=test`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	diagnostics := &heartbeatCancelWriter{cancel: cancel}
	err := runContext(ctx, []string{
		"--follow", "--poll-interval=5ms", "--heartbeat-interval=1ns",
		"--lock-file=" + filepath.Join(directory, "lock"), inputPath,
	}, strings.NewReader(""), io.Discard, diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if !diagnostics.seen {
		t.Fatal("heartbeat was not emitted while input remained readable")
	}
}

type heartbeatCancelWriter struct {
	cancel context.CancelFunc
	seen   bool
}

func (writer *heartbeatCancelWriter) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte(`"event":"heartbeat"`)) {
		writer.seen = true
		writer.cancel()
	}
	return len(data), nil
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if contents, err := os.ReadFile(path); err == nil && bytes.Contains(contents, []byte("pid=")) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("file was not created: %s", path)
}

func waitForOutput(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if contents, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(contents)) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("output was not written: %s", path)
}

func waitForOutputLines(t *testing.T, path string, count int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if contents, err := os.ReadFile(path); err == nil && strings.Count(string(contents), "\n") >= count {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("output did not reach %d lines", count)
}

func runFollowerUntilOutput(t *testing.T, inputPath, outputPath, checkpointPath string, lines int) {
	t.Helper()
	lockPath := outputPath + ".lock"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runContext(ctx, []string{
			"--follow", "--poll-interval=5ms", "--checkpoint-interval=5ms",
			"--output-file=" + outputPath, "--checkpoint-file=" + checkpointPath,
			"--lock-file=" + lockPath, inputPath,
		}, strings.NewReader(""), io.Discard, io.Discard)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if contents, err := os.ReadFile(outputPath); err == nil && strings.Count(string(contents), "\n") >= lines {
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("output did not reach %d lines", lines)
}
