package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/collector"
)

func TestBatchAndFollowPhysicalLineBounds(t *testing.T) {
	for _, limit := range []int{32, 65536, 65537} {
		for _, ending := range []string{"\n", "\r\n", ""} {
			for _, delta := range []int{-1, 0, 1} {
				t.Run(fmt.Sprintf("%d/%q/%d", limit, ending, delta), func(t *testing.T) {
					input := strings.Repeat("x", limit+delta-len(ending)) + ending
					err := run([]string{"--max-line-bytes", fmt.Sprint(limit)}, strings.NewReader(input), io.Discard, io.Discard)
					if (err != nil) != (delta > 0) {
						t.Fatalf("batch size=%d limit=%d err=%v", len(input), limit, err)
					}
					if ending == "" {
						return
					} // Follow deliberately awaits the physical terminator.
					path := t.TempDir() + "/audit.log"
					if err := os.WriteFile(path, []byte(input), 0600); err != nil {
						t.Fatal(err)
					}
					f, err := collector.OpenFileFollower(path, collector.FollowerOptions{MaxLineBytes: limit, PollInterval: time.Millisecond})
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					_, ok, err := f.Next(context.Background())
					if (err != nil) != (delta > 0) || delta <= 0 && !ok {
						t.Fatalf("follow size=%d limit=%d ok=%v err=%v", len(input), limit, ok, err)
					}
				})
			}
		}
	}
}

func TestBatchCancellationInterruptsIdleInput(t *testing.T) {
	for _, partial := range []string{"", "unfinished physical line"} {
		t.Run(partial, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- runContext(ctx, nil, r, io.Discard, io.Discard) }()
			if _, err := io.WriteString(w, partial); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("batch cancellation blocked")
			}
		})
	}
}

type cancellingInput struct {
	cancel context.CancelFunc
	reads  int
}

func (r *cancellingInput) Read(p []byte) (int, error) {
	r.reads++
	if r.reads == 3 {
		r.cancel()
	}
	return copy(p, "type=SYSCALL msg=audit(1700000000.000:1): syscall=2\n"), nil
}
func TestBatchCancellationBoundsBusyProcessing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &cancellingInput{cancel: cancel}
	var output bytes.Buffer
	if err := runContext(ctx, nil, r, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if r.reads != 3 || !strings.Contains(output.String(), `"reason":"shutdown"`) {
		t.Fatalf("reads=%d output=%s", r.reads, &output)
	}
}

func TestBatchSignalsInterruptIdleStdin(t *testing.T) {
	for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestBatchSignalChild$")
			cmd.Env = append(os.Environ(), "AESIRGUARD_AUDIT_SIGNAL_CHILD=1")
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			ready := make(chan bool, 1)
			go func() {
				s := bufio.NewScanner(stderr)
				for s.Scan() {
					if strings.Contains(s.Text(), `"started"`) {
						ready <- true
						io.Copy(io.Discard, stderr)
						return
					}
				}
				ready <- false
			}()
			select {
			case ok := <-ready:
				if !ok {
					t.Fatal("child did not start")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("child startup timeout")
			}
			if err := cmd.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("signal failed to interrupt stdin")
			}
		})
	}
}
func TestBatchSignalChild(t *testing.T) {
	if os.Getenv("AESIRGUARD_AUDIT_SIGNAL_CHILD") != "1" {
		return
	}
	os.Args = []string{"ag-audit"}
	main()
	os.Exit(0)
}

func TestCancelledStartupDoesNotTouchState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := t.TempDir() + "/state"
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runContext(ctx, []string{"--follow", "--checkpoint-file", path, "/missing/audit.log"}, strings.NewReader(""), io.Discard, io.Discard); err != context.Canceled {
		t.Fatal(err)
	}
}
