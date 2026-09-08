//go:build linux

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/securefile"
)

// FileLock owns a kernel-managed advisory lock. The lock file remains on disk
// after Close so another process cannot race with unlink and recreation.
type FileLock struct {
	file *os.File
}

// DefaultLockPath derives a stable per-input lock path.
func DefaultLockPath(inputPath string) string {
	abs, err := filepath.Abs(inputPath)
	if err != nil {
		abs = filepath.Clean(inputPath)
	}
	sum := sha256.Sum256([]byte(filepath.Clean(abs)))
	directory := filepath.Join(os.TempDir(), fmt.Sprintf("aesirguard-audit-%d", os.Getuid()))
	return filepath.Join(directory, hex.EncodeToString(sum[:16])+".lock")
}

// AcquireFileLock attempts a non-blocking exclusive lock. acquired is false
// without an error when another healthy process already owns it.
func AcquireFileLock(path string) (lock *FileLock, acquired bool, err error) {
	directory, err := openStateDirectory(filepath.Dir(path), "lock", true)
	if err != nil {
		return nil, false, err
	}
	defer directory.Close()
	file, err := securefile.OpenRegularAt(directory, filepath.Base(path), "lock", syscall.O_CREAT|syscall.O_RDWR, 0o600, false)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		closeErr := file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, false, closeErr
		}
		return nil, false, errors.Join(err, closeErr)
	}

	if err := file.Truncate(0); err == nil {
		_, err = file.Seek(0, 0)
	}
	if err == nil {
		_, err = fmt.Fprintf(file, "pid=%d\nstarted=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	}
	if err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return nil, false, errors.Join(err, file.Close())
	}
	return &FileLock{file: file}, true, nil
}

// State leaves must be private even when a root-owned sticky ancestor (such
// as /tmp) is allowed during secure traversal.
func openStateDirectory(path, kind string, create bool) (*os.File, error) {
	directory, err := securefile.OpenDirectory(path, kind, create)
	if err != nil {
		return nil, err
	}
	info, err := directory.Stat()
	if err == nil && info.Mode().Perm()&0o022 != 0 {
		err = fmt.Errorf("%s directory %s is group- or world-writable", kind, path)
	}
	if err != nil {
		return nil, errors.Join(err, directory.Close())
	}
	return directory, nil
}

// Close releases the advisory lock and descriptor.
func (lock *FileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}
