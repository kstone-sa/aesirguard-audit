package collector

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestStateObjectsFailPromptlyWithoutModification(t *testing.T) {
	for _, kind := range []string{"fifo", "directory", "symlink", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			var err error
			switch kind {
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				err = os.Symlink("missing-target", path)
			case "oversized":
				err = os.WriteFile(path, make([]byte, 65537), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := LoadCheckpoint(path); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("unsafe checkpoint accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("checkpoint open blocked")
			}
			if kind != "oversized" {
				if err := SaveCheckpoint(path, Checkpoint{InputPath: "/audit", Device: 1, Inode: 2}); err == nil {
					t.Fatal("unsafe target replaced")
				}
				if lock, _, err := AcquireFileLock(path); err == nil {
					lock.Close()
					t.Fatal("unsafe lock accepted")
				}
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "fifo" && info.Mode()&os.ModeNamedPipe == 0 {
				t.Fatal("FIFO changed")
			}
			if kind == "symlink" && info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("symlink changed")
			}
		})
	}
}

func TestStateRejectsUnsafeAncestorsBeforeCreatingChildren(t *testing.T) {
	for _, kind := range []string{"symlink", "writable", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "parent")
			switch kind {
			case "symlink":
				target := filepath.Join(root, "target")
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, parent); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(parent, 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(parent, "new", "state")
			if _, err := LoadCheckpoint(path); err == nil {
				t.Fatal("unsafe ancestor accepted on read")
			}
			if err := SaveCheckpoint(path, Checkpoint{InputPath: "/audit", Device: 1, Inode: 2}); err == nil {
				t.Fatal("unsafe ancestor accepted on save")
			}
			if lock, _, err := AcquireFileLock(path); err == nil {
				lock.Close()
				t.Fatal("unsafe ancestor accepted on lock")
			}
			if _, err := os.Stat(filepath.Join(parent, "new")); err == nil {
				t.Fatal("created child through unsafe ancestor")
			}
		})
	}
}
