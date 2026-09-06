package collector

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kstone-sa/audit2json/internal/securefile"
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
	directory, err := openStateDirectory(filepath.Dir(path), "checkpoint", false)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	file, err := securefile.OpenRegularAt(directory, filepath.Base(path), "checkpoint", syscall.O_RDONLY, 0, false)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	// Checkpoint v1 is a small state document, never an unbounded input stream.
	const maxCheckpointBytes = 64 * 1024
	if info.Size() > maxCheckpointBytes {
		return nil, fmt.Errorf("checkpoint exceeds %d bytes", maxCheckpointBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxCheckpointBytes+1))
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
	directory, err := openStateDirectory(filepath.Dir(path), "checkpoint", true)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close()) }()
	name := filepath.Base(path)
	// Reject unsafe existing targets before replacement. All subsequent mutations
	// use the pinned directory, even if its pathname is renamed concurrently.
	existing, err := securefile.OpenRegularAt(directory, name, "checkpoint", syscall.O_RDONLY, 0, false)
	if err == nil {
		if err := existing.Close(); err != nil {
			return err
		}
	} else if !errors.Is(err, syscall.ENOENT) {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporaryName := ".audit2json-checkpoint-" + hex.EncodeToString(random[:])
	temporary, err := securefile.OpenRegularAt(directory, temporaryName, "checkpoint temporary", syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY, 0o600, false)
	if err != nil {
		return err
	}
	defer func() {
		if temporary != nil {
			returnErr = errors.Join(returnErr, temporary.Close())
		}
		if temporaryName != "" {
			returnErr = errors.Join(returnErr, syscall.Unlinkat(int(directory.Fd()), temporaryName))
		}
	}()
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(checkpoint); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	err = temporary.Close()
	temporary = nil
	if err != nil {
		return err
	}
	if err := syscall.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), name); err != nil {
		return err
	}
	temporaryName = ""
	return directory.Sync()
}
