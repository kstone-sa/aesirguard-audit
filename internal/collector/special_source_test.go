package collector

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFollowRejectsSpecialSourcesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	socket := filepath.Join(dir, "socket")
	link := filepath.Join(dir, "link")
	regular := filepath.Join(dir, "regular")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Logf("socket creation unavailable: %v", err)
		socket = ""
	} else {
		defer listener.Close()
	}
	if err := os.WriteFile(regular, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, socket, link, "/dev/null", dir} {
		if path == "" {
			continue
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				f, err := OpenFileFollower(path, FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024})
				if f != nil {
					f.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("accepted special source")
				}
			case <-time.After(time.Second):
				t.Fatal("source open blocked")
			}
		})
	}
	f, err := OpenFileFollower(regular, FollowerOptions{PollInterval: time.Hour, MaxLineBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = f.Next(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}
