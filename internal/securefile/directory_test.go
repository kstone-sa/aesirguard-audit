package securefile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPinnedDirectoryDoesNotFollowReplacementPath(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	moved := filepath.Join(root, "moved")
	target := filepath.Join(root, "target")
	for _, p := range []string{original, target} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := OpenDirectory(original, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, original); err != nil {
		t.Fatal(err)
	}
	f, err := OpenRegularAt(dir, "state", "test", syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY, 0600, false)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := os.Stat(filepath.Join(moved, "state")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "state")); !os.IsNotExist(err) {
		t.Fatal("write escaped pinned directory", err)
	}
}
