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

func TestFileFollowerHonorsCancellationWithBacklog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFileFollower(path, FollowerOptions{PollInterval: time.Hour, MaxLineBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()

	ctx, cancel := context.WithCancel(context.Background())
	line, ok, err := follower.Next(ctx)
	if err != nil || !ok || line != "first" {
		t.Fatalf("first read = %q, %v, %v", line, ok, err)
	}
	cancel()
	_, _, err = follower.Next(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error with backlog = %v", err)
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

func TestFileFollowerReturnsOffsetsAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := OpenFileFollower(path, FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	line, ok, err := initial.NextSource(context.Background())
	if err != nil || !ok || line.Text != "first" || line.Start != 0 || line.End != 6 {
		t.Fatalf("source line = %#v, %v, %v", line, ok, err)
	}
	identity := initial.Identity()
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}

	resumed, err := OpenFileFollowerAt(path, FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024}, line.End, &identity)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	line, ok, err = resumed.NextSource(context.Background())
	if err != nil || !ok || line.Text != "second" || line.Start != 6 || line.End != 13 {
		t.Fatalf("resumed line = %#v, %v, %v", line, ok, err)
	}
}

func TestFileFollowerRejectsWrongGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrong := FileIdentity{Device: 1, Inode: 1}
	if follower, err := OpenFileFollowerAt(path, FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024}, 0, &wrong); err == nil {
		follower.Close()
		t.Fatal("expected generation mismatch")
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

func TestFileLockRejectsUntrustedParentDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "untrusted")
	if err := os.Mkdir(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcquireFileLock(filepath.Join(directory, "audit.lock")); err == nil {
		t.Fatal("expected insecure lock directory rejection")
	}
}
