package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const CheckpointVersion = 1

// Checkpoint is the durable replay position for one input generation.
type Checkpoint struct {
	Version   int       `json:"version"`
	InputPath string    `json:"input_path"`
	Device    uint64    `json:"device"`
	Inode     uint64    `json:"inode"`
	Offset    int64     `json:"offset"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CanonicalPath returns the stable absolute spelling used in checkpoints.
func CanonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// LoadCheckpoint reads and validates a checkpoint. A missing file returns nil.
func LoadCheckpoint(path string) (*Checkpoint, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("checkpoint %s is not a regular file", path)
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var checkpoint Checkpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		return nil, fmt.Errorf("decode checkpoint: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("checkpoint contains trailing data")
		}
		return nil, fmt.Errorf("decode checkpoint trailer: %w", err)
	}
	if err := checkpoint.Validate(); err != nil {
		return nil, err
	}
	return &checkpoint, nil
}

// Validate rejects corrupt and unsupported state.
func (checkpoint Checkpoint) Validate() error {
	if checkpoint.Version != CheckpointVersion {
		return fmt.Errorf("unsupported checkpoint version %d", checkpoint.Version)
	}
	if checkpoint.InputPath == "" || checkpoint.Device == 0 || checkpoint.Inode == 0 || checkpoint.Offset < 0 || checkpoint.UpdatedAt.IsZero() {
		return fmt.Errorf("invalid checkpoint state")
	}
	return nil
}

// SaveCheckpoint atomically replaces path after syncing file data and the
// containing directory.
func SaveCheckpoint(path string, checkpoint Checkpoint) (returnErr error) {
	checkpoint.Version = CheckpointVersion
	checkpoint.UpdatedAt = time.Now().UTC()
	if err := checkpoint.Validate(); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := validateLockDirectory(directory); err != nil {
		return fmt.Errorf("checkpoint directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".audit2json-checkpoint-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporary != nil {
			returnErr = errors.Join(returnErr, temporary.Close())
		}
		if temporaryPath != "" {
			returnErr = errors.Join(returnErr, os.Remove(temporaryPath))
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(checkpoint); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		temporary = nil
		return err
	}
	temporary = nil
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	temporaryPath = ""
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	return errors.Join(syncErr, closeErr)
}
