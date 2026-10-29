package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/securefile"
)

// ContentAnchorMismatchError is deliberately NOT automatically recoverable.
// Size loss proves truncation; changed sampled content without size loss may
// instead be hostile replacement or in-place rewriting of retained evidence.
type ContentAnchorMismatchError struct{ Gap SourceGapError }

func (e *ContentAnchorMismatchError) Error() string {
	return "checkpoint content anchor mismatch: " + e.Gap.Error()
}
func (e *ContentAnchorMismatchError) Unwrap() error { return &e.Gap }

func RecoverableSourceGap(err error) bool {
	var mismatch *ContentAnchorMismatchError
	if errors.As(err, &mismatch) {
		return false
	}
	var gap *SourceGapError
	var truncation *SourceTruncatedError
	return errors.As(err, &gap) || errors.As(err, &truncation)
}

func SourceGapReason(err error) string {
	var truncation *SourceTruncatedError
	if errors.As(err, &truncation) {
		return "source_truncated"
	}
	var gap *SourceGapError
	if errors.As(err, &gap) && gap.Reason != "" {
		return gap.Reason
	}
	return "source_generation_missing"
}

// OpenRecoveryFollower chooses the oldest contiguous retained suffix ending in
// the active file. It never seeks into replacement bytes using an old offset.
// Discovery ambiguity and unsafe/unusable active files remain errors.
func OpenRecoveryFollower(inputPath string, options RotationOptions) (*RotatingFollower, error) {
	inputPath, err := CanonicalPath(inputPath)
	if err != nil {
		return nil, err
	}
	active, err := OpenFileFollower(inputPath, options.FollowerOptions)
	if err != nil {
		return nil, err
	}
	if err := active.Close(); err != nil {
		return nil, err
	}
	candidates, err := discoverCandidates(inputPath, options.ExcludePaths)
	if err != nil {
		return nil, err
	}
	start := len(candidates) - 1
	for start > 0 {
		older, newer := candidates[start-1], candidates[start]
		expected := uint64(0)
		if !newer.current {
			expected = newer.number
		}
		if older.number == 0 || older.number-1 != expected {
			break
		}
		start--
	}
	first := candidates[start]
	fopts := options.FollowerOptions
	fopts.Generation = 0
	file, err := OpenFileFollowerAt(first.path, fopts, 0, &first.identity)
	if err != nil {
		return nil, err
	}
	return &RotatingFollower{inputPath: inputPath, options: options, current: file, currentAtPath: first.current,
		queued: candidates[start+1:], complete: SourcePosition{Identity: first.identity, Anchor: file.originAnchor}}, nil
}

// GapIncident preserves the pre-transition checkpoint even after a new lineage
// is committed. Prepared is a write-ahead decision, not successful recovery.
type GapIncident struct {
	Number           uint64       `json:"number"`
	DetectedAt       time.Time    `json:"detected_at"`
	Reason           string       `json:"reason"`
	ObservedIdentity FileIdentity `json:"observed_identity"`
	ObservedOffset   *int64       `json:"observed_offset,omitempty"`
	ObservedSize     *int64       `json:"observed_size,omitempty"`
	Previous         *Checkpoint  `json:"previous,omitempty"`
	Resume           Checkpoint   `json:"resume"`
	Prepared         bool         `json:"prepared"`
	Superseded       bool         `json:"superseded,omitempty"`
}

// GapLedger is bounded to eight recent incidents plus a lifetime count. It is
// separate from checkpoint v2 so existing checkpoint readers keep their format.
type GapLedger struct {
	Version   int           `json:"version"`
	InputPath string        `json:"input_path"`
	Total     uint64        `json:"total"`
	Incidents []GapIncident `json:"incidents"`
}

func (l GapLedger) Validate() error {
	if l.Version != 1 || l.InputPath == "" || l.Total == 0 || len(l.Incidents) == 0 || len(l.Incidents) > 8 {
		return fmt.Errorf("invalid gap ledger")
	}
	for i, g := range l.Incidents {
		if g.ObservedIdentity.Device == 0 || g.ObservedIdentity.Inode == 0 || (g.Prepared && g.Superseded) || g.Number == 0 || g.Number > l.Total || (i > 0 && g.Number != l.Incidents[i-1].Number+1) || g.DetectedAt.IsZero() ||
			(g.Reason != "source_truncated" && g.Reason != "source_generation_missing" && g.Reason != "missing_intermediate_generation") ||
			g.Resume.InputPath != l.InputPath || g.Resume.Offset != 0 || (i < len(l.Incidents)-1 && g.Prepared) {
			return fmt.Errorf("invalid gap incident")
		}
		if err := g.Resume.Validate(); err != nil {
			return err
		}
		if g.Previous != nil {
			if err := g.Previous.Validate(); err != nil {
				return err
			}
			if g.Previous.InputPath != l.InputPath {
				return fmt.Errorf("gap checkpoint input mismatch")
			}
		}
	}
	if l.Incidents[len(l.Incidents)-1].Number != l.Total {
		return fmt.Errorf("gap ledger count mismatch")
	}
	return nil
}

func LoadGapLedger(path string) (*GapLedger, error) {
	directory, err := openStateDirectory(filepath.Dir(path), "gap ledger", false)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	file, err := securefile.OpenRegularAt(directory, filepath.Base(path), "gap ledger", syscall.O_RDONLY, 0, false)
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
	if info.Size() > 64*1024 {
		return nil, fmt.Errorf("gap ledger exceeds 64 KiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024+1))
	decoder.DisallowUnknownFields()
	var ledger GapLedger
	if err := decoder.Decode(&ledger); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("gap ledger trailing data: %v", err)
	}
	if err := ledger.Validate(); err != nil {
		return nil, err
	}
	return &ledger, nil
}

func SaveGapLedger(path string, ledger GapLedger) error {
	if err := ledger.Validate(); err != nil {
		return err
	}
	// Bound serialized state even with unusually long configured paths.
	data, err := json.Marshal(ledger)
	if err != nil {
		return err
	}
	if len(data)+1 > 64*1024 {
		return fmt.Errorf("gap ledger exceeds 64 KiB")
	}
	return saveState(path, ledger)
}
