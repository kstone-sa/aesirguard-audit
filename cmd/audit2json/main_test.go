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
	"testing"
	"time"

	"github.com/marios-github/audit2json/internal/audit"
	"github.com/marios-github/audit2json/internal/collector"
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
