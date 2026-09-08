package collector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckpointRoundTripAndReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "audit.checkpoint")
	for _, offset := range []int64{120, 240} {
		checkpoint := Checkpoint{
			InputPath: "/var/log/audit/audit.log", Device: 10, Inode: 20, Offset: offset, Anchor: emptyAnchor,
		}
		if err := SaveCheckpoint(path, checkpoint); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadCheckpoint(path)
		if err != nil {
			t.Fatal(err)
		}
		if loaded == nil || loaded.Version != CheckpointVersion || loaded.Offset != offset || loaded.UpdatedAt.IsZero() {
			t.Fatalf("loaded checkpoint = %#v", loaded)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode = %o", info.Mode().Perm())
	}
}

func TestCheckpointRejectsCorruptionAndUnsupportedVersion(t *testing.T) {
	directory := t.TempDir()
	for name, contents := range map[string]string{
		"corrupt":     "not json\n",
		"unsupported": `{"version":99,"input_path":"/audit.log","device":1,"inode":2,"offset":0,"updated_at":"2026-01-01T00:00:00Z"}` + "\n",
	} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCheckpoint(path); err == nil {
			t.Fatalf("expected %s checkpoint rejection", name)
		}
	}
}

func TestCheckpointRejectsWritableState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	contents := `{"version":1,"input_path":"/audit.log","device":1,"inode":2,"offset":0,"updated_at":"2026-01-01T00:00:00Z"}` + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCheckpoint(path); err == nil {
		t.Fatal("expected writable checkpoint rejection")
	}
}

func TestCheckpointValidateRequiresTimestampAfterSaveOnly(t *testing.T) {
	checkpoint := Checkpoint{Version: CheckpointVersion, InputPath: "/audit.log", Device: 1, Inode: 2, UpdatedAt: time.Time{}}
	if err := checkpoint.Validate(); err == nil {
		t.Fatal("expected missing timestamp rejection")
	}
}

func TestCheckpointIgnoresInterruptedTemporaryReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "checkpoint")
	if err := SaveCheckpoint(path, Checkpoint{InputPath: "/audit.log", Device: 1, Inode: 2, Offset: 42, Anchor: emptyAnchor}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".aesirguard-audit-checkpoint-interrupted"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCheckpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Offset != 42 {
		t.Fatalf("loaded checkpoint = %#v", loaded)
	}
}

const emptyAnchor = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestCheckpointGenerationAnchor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	original := []byte("event one\nevent two\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := ContentAnchor(f, 10)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	follower, err := OpenFileFollowerAt(path, FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024}, 10, nil, anchor)
	if err != nil {
		t.Fatal(err)
	}
	follower.Close()
	// Overwrite in place to deterministically keep the same device and inode,
	// reproducing the identity collision without relying on allocator reuse.
	if err := os.WriteFile(path, []byte("other one\nevent two\n"), 0600); err != nil {
		t.Fatal(err)
	}
	follower, err = OpenFileFollowerAt(path, FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024}, 10, nil, anchor)
	var gap *SourceGapError
	if !errors.As(err, &gap) {
		if follower != nil {
			follower.Close()
		}
		t.Fatalf("expected explicit source gap: %v", err)
	}
}

func TestCheckpointVersionOneIsNotMigrated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	data := `{"version":1,"input_path":"/audit.log","device":1,"inode":2,"offset":10,"updated_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCheckpoint(path); err == nil {
		t.Fatal("unsafe legacy checkpoint accepted")
	}
	after, _ := os.ReadFile(path)
	if string(after) != data {
		t.Fatal("legacy state modified")
	}
}

func TestCheckpointAnchorAppendAndBoundedWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	data := make([]byte, 20000)
	for i := range data {
		data[i] = 'x'
	}
	data[len(data)-1] = '\n'
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	anchor, err := ContentAnchor(f, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("appended\n"), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	appended, err := ContentAnchor(f, int64(len(data)))
	if err != nil || appended != anchor {
		t.Fatal("append invalidated anchor")
	}
	// The documented sampled discriminator is bounded, not full-file hashing.
	if _, err := f.WriteAt([]byte("middle"), 10000); err != nil {
		t.Fatal(err)
	}
	middle, _ := ContentAnchor(f, int64(len(data)))
	if middle != anchor {
		t.Fatal("anchor exceeded documented windows")
	}
	if _, err := f.WriteAt([]byte("tail"), 19000); err != nil {
		t.Fatal(err)
	}
	changed, _ := ContentAnchor(f, int64(len(data)))
	if changed == anchor || len(changed) != 64 {
		t.Fatal("tail mutation was not detected")
	}
}
