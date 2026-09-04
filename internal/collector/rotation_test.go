package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotatingFollowerDrainsRenameCreateRotation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower := mustOpenRotatingFollower(t, path, nil)
	defer follower.Close()
	first := mustNextRotatingLine(t, follower)
	if first.Text != "first" || first.Generation != 0 {
		t.Fatalf("first line = %#v", first)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := mustNextRotatingLine(t, follower)
	if second.Text != "second" || second.Generation != 1 || second.Identity == first.Identity {
		t.Fatalf("second line = %#v", second)
	}
	if follower.RotationCount() != 1 {
		t.Fatalf("rotation count = %d", follower.RotationCount())
	}
}

func TestRotatingFollowerReadsLateWriteToOldDescriptor(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	rotated := path + ".1"
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower := mustOpenRotatingFollower(t, path, nil)
	defer follower.Close()
	mustNextRotatingLine(t, follower)
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := follower.Next(context.Background()); err != nil || ok {
		t.Fatalf("rotation detection = %v, %v", ok, err)
	}
	old, err := os.OpenFile(rotated, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := old.WriteString("late\n")
	closeErr := old.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	late := mustNextRotatingLine(t, follower)
	if late.Text != "late" || late.Generation != 0 {
		t.Fatalf("late old-generation line = %#v", late)
	}
	newLine := mustNextRotatingLine(t, follower)
	if newLine.Text != "new" || newLine.Generation != 1 {
		t.Fatalf("new-generation line = %#v", newLine)
	}
}

func TestRotatingFollowerWaitsThroughMissingPathWindow(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower := mustOpenRotatingFollower(t, path, nil)
	defer follower.Close()
	mustNextRotatingLine(t, follower)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := follower.Next(context.Background()); err != nil || ok {
		t.Fatalf("missing-path window = %v, %v", ok, err)
	}
	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	line := mustNextRotatingLine(t, follower)
	if line.Text != "new" {
		t.Fatalf("replacement line = %#v", line)
	}
}

func TestRotatingFollowerQueuesRapidRotations(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower := mustOpenRotatingFollower(t, path, nil)
	defer follower.Close()
	mustNextRotatingLine(t, follower)
	if err := os.Rename(path, path+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".1", []byte("middle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(path+".2", now.Add(-2*time.Second), now.Add(-2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path+".1", now.Add(-time.Second), now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for index, want := range []string{"middle", "current"} {
		line := mustNextRotatingLine(t, follower)
		if line.Text != want || line.Generation != uint64(index+1) {
			t.Fatalf("rapid rotation line %d = %#v", index, line)
		}
	}
}

func TestRotatingFollowerPreservesPartialLineAcrossRotation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	if err := os.WriteFile(path, []byte("type=KER"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower := mustOpenRotatingFollower(t, path, nil)
	defer follower.Close()
	if _, ok, err := follower.Next(context.Background()); err != nil || ok {
		t.Fatalf("partial read = %v, %v", ok, err)
	}
	origin := follower.CompletePosition()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("NEL msg=audit(1.0:1): device=test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	line := mustNextRotatingLine(t, follower)
	if line.Text != "type=KERNEL msg=audit(1.0:1): device=test" || line.StartIdentity != origin.Identity || line.Identity == origin.Identity {
		t.Fatalf("cross-generation line = %#v; origin = %#v", line, origin)
	}
}

func TestRotatingFollowerRecoversThroughRetainedGenerations(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	oldest := path + ".2"
	middle := path + ".1"
	if err := os.WriteFile(oldest, []byte("skip\noldest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(middle, []byte("middle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(oldest, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(middle, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(oldest)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := identityFromFileInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := &Checkpoint{Device: identity.Device, Inode: identity.Inode, Offset: int64(len("skip\n"))}
	follower := mustOpenRotatingFollower(t, path, checkpoint)
	defer follower.Close()
	for index, want := range []string{"oldest", "middle", "current"} {
		line := mustNextRotatingLine(t, follower)
		if line.Text != want || line.Generation != uint64(index) {
			t.Fatalf("line %d = %#v, want %q", index, line, want)
		}
	}
}

func TestRotatingFollowerReportsMissingCheckpointGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	checkpoint := &Checkpoint{Device: 1, Inode: 2}
	_, err := OpenRotatingFollower(path, testRotationOptions(), checkpoint)
	var gap *SourceGapError
	if !errors.As(err, &gap) {
		t.Fatalf("gap error = %v", err)
	}
}

func TestRotatingFollowerReportsSameInodeTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower := mustOpenRotatingFollower(t, path, nil)
	defer follower.Close()
	mustNextRotatingLine(t, follower)
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	_, _, err := follower.Next(context.Background())
	var truncated *SourceTruncatedError
	if !errors.As(err, &truncated) {
		t.Fatalf("truncation error = %v", err)
	}
}

func mustOpenRotatingFollower(t *testing.T, path string, checkpoint *Checkpoint) *RotatingFollower {
	t.Helper()
	follower, err := OpenRotatingFollower(path, testRotationOptions(), checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	return follower
}

func testRotationOptions() RotationOptions {
	return RotationOptions{
		FollowerOptions: FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024},
		DrainInterval:   2 * time.Millisecond,
	}
}

func mustNextRotatingLine(t *testing.T, follower *RotatingFollower) SourceLine {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		line, ok, err := follower.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			return line
		}
	}
	t.Fatal("timed out waiting for rotating source line")
	return SourceLine{}
}
