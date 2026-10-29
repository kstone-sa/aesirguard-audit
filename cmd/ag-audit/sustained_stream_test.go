package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/audit"
	"github.com/kstone-sa/aesirguard-audit/internal/collector"
	eventoutput "github.com/kstone-sa/aesirguard-audit/internal/output"
)

// Pace accepted output to ensure the prefilled source spans several observation
// timeouts. This wraps the actual production sink, including its Commit behavior.
type busyTestSink struct {
	eventoutput.Sink
	delay time.Duration
}

func (s *busyTestSink) Write(e audit.CanonicalEvent) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return s.Sink.Write(e)
}

func TestBusyFollowerChild(t *testing.T) {
	if os.Getenv("AG_AUDIT_BUSY_CHILD") != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("AG_AUDIT_BUSY_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	options, err := parseOptions(args, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	lock, acquired, err := collector.AcquireFileLock(options.lockPath)
	if err != nil || !acquired {
		t.Fatalf("lock: %v", err)
	}
	defer lock.Close()
	sink, err := openSink(options, os.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	delay, err := time.ParseDuration(os.Getenv("AG_AUDIT_BUSY_DELAY"))
	if err != nil {
		t.Fatal(err)
	}
	assembler, err := audit.NewBoundedAssembler(options.eventTimeout, audit.AssemblerLimits{
		MaxPendingEvents: options.maxPendingEvents, MaxRecordsPerEvent: options.maxRecordsPerEvent, MaxPendingBytes: options.maxPendingBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	p := &eventProcessor{assembler: assembler, sink: &busyTestSink{Sink: sink, delay: delay}, diagnostics: newOperationalDiagnostics(os.Stderr, 0)}
	if err := runFollower(context.Background(), options, p); err != nil {
		writeFatalDiagnostic(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func startBusyFollower(t *testing.T, args []string, stdoutPath, logPath string, delay time.Duration) *upgradeChild {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestBusyFollowerChild$")
	command.Env = append(os.Environ(), "AG_AUDIT_BUSY_CHILD=1", "AG_AUDIT_BUSY_ARGS="+string(encoded), "AG_AUDIT_BUSY_DELAY="+delay.String())
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = log
	command.Stdout = io.Discard
	copied := make(chan struct{})
	var reader, writer, out *os.File
	if stdoutPath != "" {
		reader, writer, err = os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err = os.OpenFile(stdoutPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		command.Stdout = writer
	} else {
		close(copied)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if writer != nil {
		writer.Close()
		go func() { defer close(copied); defer reader.Close(); defer out.Close(); _, _ = io.Copy(out, reader) }()
	}
	child := &upgradeChild{command: command, done: make(chan error, 1), logPath: logPath}
	go func() { err := command.Wait(); <-copied; log.Close(); child.done <- err }()
	t.Cleanup(func() { _ = command.Process.Kill() })
	return child
}

func busyOutputEvents(t *testing.T, path string) []audit.CanonicalEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var events []audit.CanonicalEvent
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var e audit.CanonicalEvent
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	return events
}

func TestBusyFollowerCheckpointAndForcedRestart(t *testing.T) {
	for _, mode := range []string{"stdout_pipe", "managed_file"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			input, cpPath, out := filepath.Join(dir, "audit.log"), filepath.Join(dir, "checkpoint"), filepath.Join(dir, "events.ndjson")
			var source strings.Builder
			source.WriteString("type=KERNEL msg=audit(100.1:0): device=before\n")
			for i := 1; i <= 3; i++ {
				fmt.Fprintf(&source, "type=PATH msg=audit(100.1:%d): item=0 name=\"/safe\"\n", i)
			}
			// Every source line is available before startup, with a large backlog
			// remaining when we kill the process. No idle FlushExpired is possible:
			// poll interval is one hour and the test has an eight-second deadline.
			pathologicalEnd := int64(source.Len())
			for i := 1000; i < 3000; i++ {
				fmt.Fprintf(&source, "type=KERNEL msg=audit(100.1:%d): device=valid\n", i)
			}
			if err := os.WriteFile(input, []byte(source.String()), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--follow", "--poll-interval=1h", "--event-timeout=250ms", "--checkpoint-interval=1ns",
				"--max-pending-events=1", "--max-pending-bytes=1024", "--checkpoint-file=" + cpPath, "--lock-file=" + filepath.Join(dir, "lock"), input}
			stdoutPath := out
			if mode == "managed_file" {
				args = append([]string{"--output-file=" + out}, args...)
				stdoutPath = ""
			}
			logPath := filepath.Join(dir, "busy.log")
			child := startBusyFollower(t, args, stdoutPath, logPath, 2*time.Millisecond)
			waitUpgrade(t, func() bool {
				data, _ := os.ReadFile(out)
				cp, _ := collector.LoadCheckpoint(cpPath)
				return bytes.Contains(data, []byte(`"id":"100.1:1400"`)) && cp != nil && cp.Offset > pathologicalEnd
			}, "normal classification and checkpoint progress while backlog remains")
			cp, err := collector.LoadCheckpoint(cpPath)
			if err != nil || cp == nil || cp.Offset <= pathologicalEnd || cp.Offset >= int64(source.Len()) {
				t.Fatalf("no busy checkpoint progress: %#v %v", cp, err)
			}
			child.command.Process.Kill()
			child.wait(t, true)
			events := busyOutputEvents(t, out)
			seenBefore, expiredA, lateNormal := false, 0, 0
			rawKeys := make(map[string]bool)
			firstKernel := false
			for _, e := range events {
				if e.Audit.ID == "100.1:0" && e.Event.Type == "KERNEL" {
					seenBefore = true
				}
				if e.Audit.ID == "100.1:1" {
					expiredA++
					if e.Event.Integrity == nil || e.Event.Integrity.Reason != audit.CompletionTimeout {
						t.Fatal("stale evidence not emitted incomplete")
					}
				}
				if (e.Audit.ID == "100.1:2" || e.Audit.ID == "100.1:3") && e.Event.Type == "ASSEMBLY_EXCEPTION" && e.Audit.Raw != "" {
					rawKeys[e.Audit.ID] = true
				}
				if e.Audit.ID == "100.1:1000" {
					firstKernel = e.Event.Type == "ASSEMBLY_EXCEPTION"
				}
				serial, _ := strconv.Atoi(strings.TrimPrefix(e.Audit.ID, "100.1:"))
				if serial >= 1350 && e.Event.Type == "KERNEL" && e.Event.Integrity == nil {
					lateNormal++
				}
			}
			if !seenBefore || len(rawKeys) != 2 || expiredA != 1 || !firstKernel || lateNormal == 0 || len(events) >= 2004 {
				t.Fatalf("busy fixture lost evidence or failed to recover: before=%v expired=%d initial-isolation=%v normal=%d records=%d", seenBefore, expiredA, firstKernel, lateNormal, len(events))
			}
			diagnostics, _ := os.ReadFile(logPath)
			if !bytes.Contains(diagnostics, []byte(`"conservative_isolation":true`)) {
				t.Fatal("fixture did not exhaust rejected-key bookkeeping")
			}
			// Restart the SAME follower arguments/state after SIGKILL, with new data.
			// Drop only the test latency injection so replay of the retained backlog
			// completes quickly; no application configuration or checkpoint is edited.
			appendUpgrade(t, input, "type=KERNEL msg=audit(100.1:5000): device=after_restart\n")
			child = startBusyFollower(t, args, stdoutPath, filepath.Join(dir, "restart.log"), 0)
			waitUpgrade(t, func() bool {
				data, _ := os.ReadFile(out)
				cp, _ := collector.LoadCheckpoint(cpPath)
				stat, _ := os.Stat(input)
				return cp != nil && stat != nil && cp.Offset == stat.Size() && bytes.Contains(data, []byte(`"id":"100.1:5000"`))
			}, "forced restart resumes checkpoint and emits newly appended event")
			child.command.Process.Kill()
			child.wait(t, true)
			last := busyOutputEvents(t, out)
			found := false
			seen := make(map[string]bool)
			for _, e := range last {
				seen[e.Audit.ID] = true
				if e.Audit.ID == "100.1:5000" && e.Event.Type == "KERNEL" && e.Event.Integrity == nil {
					found = true
				}
			}
			for i := 1000; i < 3000; i++ {
				if !seen[fmt.Sprintf("100.1:%d", i)] {
					t.Fatalf("physical source record %d disappeared", i)
				}
			}
			if !found {
				t.Fatal("new valid event still isolated after restart")
			}
			checkpoint, err := collector.LoadCheckpoint(cpPath)
			if err != nil {
				t.Fatal(err)
			}
			follower, err := collector.OpenRotatingFollower(input, collector.RotationOptions{FollowerOptions: collector.FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024}, DrainInterval: time.Millisecond}, checkpoint)
			if err != nil {
				t.Fatal("persisted checkpoint/anchor invalid", err)
			}
			follower.Close()
		})
	}
}
