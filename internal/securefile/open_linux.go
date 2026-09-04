//go:build linux

// Package securefile opens trusted regular files without resolving a mutable
// path again after validation.
package securefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// OpenReadOnly opens a trusted regular file for reading. When allowRootOwner
// is true, either root or the effective user may own the file.
func OpenReadOnly(path, kind string, allowRootOwner bool) (*os.File, error) {
	return openRegular(path, kind, syscall.O_RDONLY, 0, allowRootOwner)
}

// OpenAppend opens or creates a trusted regular file owned by the effective
// user for append-only writes.
func OpenAppend(path, kind string, mode uint32) (*os.File, error) {
	return openRegular(path, kind, syscall.O_CREAT|syscall.O_APPEND|syscall.O_WRONLY, mode, false)
}

func openRegular(path, kind string, flags int, mode uint32, allowRootOwner bool) (*os.File, error) {
	if path == "" {
		return nil, fmt.Errorf("%s path is empty", kind)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	components := strings.Split(strings.TrimPrefix(absolute, string(os.PathSeparator)), string(os.PathSeparator))
	if len(components) == 0 || components[0] == "" {
		return nil, fmt.Errorf("%s %s has no file name", kind, path)
	}

	directoryFD, err := syscall.Open(string(os.PathSeparator), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(directoryFD), string(os.PathSeparator))
	defer func() { _ = directory.Close() }()
	if err := validateDirectory(directory, kind); err != nil {
		return nil, err
	}
	for _, component := range components[:len(components)-1] {
		nextFD, err := syscall.Openat(int(directory.Fd()), component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		next := os.NewFile(uintptr(nextFD), filepath.Join(directory.Name(), component))
		if err := validateDirectory(next, kind); err != nil {
			return nil, errors.Join(err, next.Close())
		}
		if err := directory.Close(); err != nil {
			return nil, errors.Join(err, next.Close())
		}
		directory = next
	}

	fileFD, err := syscall.Openat(int(directory.Fd()), components[len(components)-1], flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fileFD), absolute)
	if err := validateRegularFile(file, kind, allowRootOwner); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func validateDirectory(directory *os.File, kind string) error {
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok {
		return fmt.Errorf("%s directory %s is not a directory", kind, directory.Name())
	}
	if stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 {
		return fmt.Errorf("%s directory %s has an untrusted owner", kind, directory.Name())
	}
	writable := info.Mode().Perm()&0o022 != 0
	rootSticky := stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
	if writable && !rootSticky {
		return fmt.Errorf("%s directory %s is group- or world-writable", kind, directory.Name())
	}
	return nil
}

func validateRegularFile(file *os.File, kind string, allowRootOwner bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok {
		return fmt.Errorf("%s %s is not a regular file", kind, file.Name())
	}
	trustedOwner := stat.Uid == uint32(os.Geteuid()) || allowRootOwner && stat.Uid == 0
	if !trustedOwner {
		return fmt.Errorf("%s %s has an untrusted owner", kind, file.Name())
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s %s is group- or world-writable", kind, file.Name())
	}
	return nil
}
