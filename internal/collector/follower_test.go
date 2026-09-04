package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileFollowerWaitsForCompleteAppendedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("first\npar"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFileFollower(path, FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()

	line, ok, err := follower.Next(context.Background())
	if err != nil || !ok || line != "first" {
		t.Fatalf("first read = %q, %v, %v", line, ok, err)
	}
	if line, ok, err := follower.Next(context.Background()); err != nil || ok || line != "" {
		t.Fatalf("partial read = %q, %v, %v", line, ok, err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("tial\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	line, ok, err = follower.Next(context.Background())
	if err != nil || !ok || line != "partial" {
		t.Fatalf("appended read = %q, %v, %v", line, ok, err)
	}
}

func TestFileFollowerHonorsCancellationAtEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFileFollower(path, FollowerOptions{PollInterval: time.Hour, MaxLineBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = follower.Next(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestFileFollowerRejectsOversizedPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFileFollower(path, FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()

	if _, _, err := follower.Next(context.Background()); err == nil {
		t.Fatal("expected maximum line size error")
	}
}

func TestFileLockIsNonBlockingAndReleasedByClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.lock")
	first, acquired, err := AcquireFileLock(path)
	if err != nil || !acquired {
		t.Fatalf("first lock = %v, %v", acquired, err)
	}
	second, acquired, err := AcquireFileLock(path)
	if err != nil || acquired || second != nil {
		t.Fatalf("second lock = %#v, %v, %v", second, acquired, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, acquired, err := AcquireFileLock(path)
	if err != nil || !acquired {
		t.Fatalf("third lock = %v, %v", acquired, err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultLockPathIsStablePerInput(t *testing.T) {
	first := DefaultLockPath("/var/log/audit/audit.log")
	if first != DefaultLockPath("/var/log/audit/audit.log") {
		t.Fatal("default lock path is not stable")
	}
	if first == DefaultLockPath("/var/log/audit/other.log") {
		t.Fatal("different inputs share a default lock path")
	}
}
