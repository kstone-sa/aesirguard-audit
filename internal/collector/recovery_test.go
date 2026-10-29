package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoveryChoosesOldestContiguousSuffix(t *testing.T) {
	for _, suffixes := range [][]string{{".4", ".3", ".1", ""}, {".3", ".2", ".1", ""}, {".4", ""}} {
		dir := t.TempDir()
		input := filepath.Join(dir, "audit.log")
		for _, suffix := range suffixes {
			if err := os.WriteFile(input+suffix, []byte("record"+suffix+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		options := RotationOptions{FollowerOptions: FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024}, DrainInterval: time.Nanosecond}
		f, err := OpenRecoveryFollower(input, options)
		if err != nil {
			t.Fatal(err)
		}
		expected := "record.1"
		if len(suffixes) == 4 && suffixes[1] == ".2" {
			expected = "record.3"
		}
		if len(suffixes) == 2 {
			expected = "record"
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		line, ok, err := f.Next(ctx)
		cancel()
		f.Close()
		if err != nil || !ok || line.Text != expected {
			t.Fatalf("suffix=%v line=%#v err=%v", suffixes, line, err)
		}
	}
}

func TestRecoveryNeverBypassesAnchorOrAmbiguity(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "audit.log")
	for _, s := range []string{".3", ".1", ""} {
		if err := os.WriteFile(input+s, []byte("replacement\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := OpenFileFollower(input+".3", FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	identity := f.Identity()
	f.Close()
	cp := &Checkpoint{Version: 2, InputPath: input, Device: identity.Device, Inode: identity.Inode, Offset: 12, Anchor: emptyAnchor, UpdatedAt: time.Now()}
	options := RotationOptions{FollowerOptions: FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024}, DrainInterval: time.Millisecond}
	_, err = OpenRotatingFollower(input, options, cp)
	var mismatch *ContentAnchorMismatchError
	if !errors.As(err, &mismatch) || RecoverableSourceGap(err) {
		t.Fatalf("anchor bypass through chain gap: %v", err)
	}
	if err := os.Link(input+".1", input+".01"); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRecoveryFollower(input, options); err == nil {
		f.Close()
		t.Fatal("aliased generations bypassed")
	}
	os.Remove(input + ".01")
	os.Remove(input + ".1")
	if err := os.Symlink(input, input+".1"); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRecoveryFollower(input, options); err == nil {
		f.Close()
		t.Fatal("unsafe rotation bypassed")
	}
}
