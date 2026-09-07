package main

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFollowSIGTERMInterruptsRegularAndFIFOStartup(t *testing.T) {
	for _, kind := range []string{"regular", "fifo"} {
		signal := syscall.SIGTERM
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "audit.log")
			if kind == "fifo" {
				if err := syscall.Mkfifo(source, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(source, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestFollowSignalChild$")
			cmd.Env = append(os.Environ(), "AUDIT2JSON_FOLLOW_SIGNAL_CHILD=1", "AUDIT2JSON_FOLLOW_SOURCE="+source)
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
			if err := cmd.Process.Signal(signal); err != nil && kind != "fifo" {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil && kind != "fifo" {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("signal failed to interrupt follow startup/polling")
			}
		})
	}
}
func TestFollowSignalChild(t *testing.T) {
	if os.Getenv("AUDIT2JSON_FOLLOW_SIGNAL_CHILD") != "1" {
		return
	}
	source := os.Getenv("AUDIT2JSON_FOLLOW_SOURCE")
	os.Args = []string{"audit2json", "--follow", "--poll-interval=1h", "--lock-file", source + ".lock", source}
	main()
	os.Exit(0)
}
