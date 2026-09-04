package collector

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckpointRoundTripAndReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "audit.checkpoint")
	for _, offset := range []int64{120, 240} {
		checkpoint := Checkpoint{
			InputPath: "/var/log/audit/audit.log", Device: 10, Inode: 20, Offset: offset,
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
	if err := SaveCheckpoint(path, Checkpoint{InputPath: "/audit.log", Device: 1, Inode: 2, Offset: 42}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".audit2json-checkpoint-interrupted"), []byte("partial"), 0o600); err != nil {
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
