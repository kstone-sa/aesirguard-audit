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
	directory := filepath.Join(os.TempDir(), fmt.Sprintf("audit2json-%d", os.Getuid()))
	return filepath.Join(directory, hex.EncodeToString(sum[:16])+".lock")
}

// AcquireFileLock attempts a non-blocking exclusive lock. acquired is false
// without an error when another healthy process already owns it.
func AcquireFileLock(path string) (lock *FileLock, acquired bool, err error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, false, err
	}
	if err := validateLockDirectory(directory); err != nil {
		return nil, false, err
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), path)
	if err := validateLockFile(file); err != nil {
		return nil, false, errors.Join(err, file.Close())
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

func validateLockDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("lock directory %s is not a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify lock directory %s ownership", path)
	}
	if stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 {
		return fmt.Errorf("lock directory %s is owned by uid %d", path, stat.Uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("lock directory %s is group- or world-writable", path)
	}
	return nil
}

func validateLockFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("lock file %s is not regular", file.Name())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify lock file %s ownership", file.Name())
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("lock file %s is owned by uid %d", file.Name(), stat.Uid)
	}
	return nil
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
