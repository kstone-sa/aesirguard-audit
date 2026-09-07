package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SourcePosition is a durable complete-line boundary in one generation.
type SourcePosition struct {
	Identity   FileIdentity
	Generation uint64
	Anchor     string
	Offset     int64
}

var errInputPathPending = errors.New("replacement input path is temporarily absent")

// RotationOptions controls retained-file discovery and old-inode drain time.
type RotationOptions struct {
	FollowerOptions
	DrainInterval time.Duration
	ExcludePaths  []string
}

// SourceGapError means the checkpoint generation is no longer retained.
type SourceGapError struct {
	Identity FileIdentity
}

func (err *SourceGapError) Error() string {
	return fmt.Sprintf("checkpoint source generation is not retained: device=%d inode=%d", err.Identity.Device, err.Identity.Inode)
}

// SourceTruncatedError reports copytruncate or another same-inode shrink.
type SourceTruncatedError struct {
	Identity FileIdentity
	Offset   int64
	Size     int64
}

func (err *SourceTruncatedError) Error() string {
	return fmt.Sprintf("source generation truncated: device=%d inode=%d offset=%d size=%d", err.Identity.Device, err.Identity.Inode, err.Offset, err.Size)
}

type sourceCandidate struct {
	path     string
	identity FileIdentity
	current  bool
	number   uint64
	numbered bool
}

// RotatingFollower drains retained and live rename/create generations in
// source order while preserving partial physical lines.
type RotatingFollower struct {
	inputPath       string
	options         RotationOptions
	current         *FileFollower
	currentAtPath   bool
	queued          []sourceCandidate
	complete        SourcePosition
	rotationCount   uint64
	pendingIdentity FileIdentity
	drainStarted    time.Time
	drainSize       int64
}

// OpenRotatingFollower opens the checkpoint generation, searching retained
// siblings when the configured path already references a newer inode.
func OpenRotatingFollower(inputPath string, options RotationOptions, checkpoint *Checkpoint) (*RotatingFollower, error) {
	if options.DrainInterval <= 0 {
		return nil, fmt.Errorf("rotation drain interval must be positive")
	}
	canonicalInput, err := CanonicalPath(inputPath)
	if err != nil {
		return nil, err
	}
	if checkpoint == nil {
		follower, err := OpenFileFollowerAt(canonicalInput, options.FollowerOptions, 0, nil)
		if err != nil {
			return nil, err
		}
		return &RotatingFollower{
			inputPath: canonicalInput, options: options, current: follower, currentAtPath: true,
			complete: SourcePosition{Identity: follower.Identity(), Offset: 0, Anchor: follower.originAnchor},
		}, nil
	}

	expected := FileIdentity{Device: checkpoint.Device, Inode: checkpoint.Inode}
	candidates, err := discoverCandidates(canonicalInput, options.ExcludePaths)
	if err != nil {
		return nil, err
	}
	index := -1
	for i, candidate := range candidates {
		if candidate.identity == expected {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, &SourceGapError{Identity: expected}
	}
	if err := validateGenerationChain(candidates[index:]); err != nil {
		return nil, err
	}
	first := candidates[index]
	followerOptions := options.FollowerOptions
	followerOptions.Generation = 0
	follower, err := OpenFileFollowerAt(first.path, followerOptions, checkpoint.Offset, &expected, checkpoint.Anchor)
	if err != nil {
		return nil, err
	}
	return &RotatingFollower{
		inputPath: canonicalInput, options: options, current: follower, currentAtPath: first.current,
		queued:   candidates[index+1:],
		complete: SourcePosition{Identity: expected, Offset: checkpoint.Offset, Anchor: checkpoint.Anchor},
	}, nil
}

// Next returns a source line, an idle tick, or an explicit source gap.
func (follower *RotatingFollower) Next(ctx context.Context) (SourceLine, bool, error) {
	line, ok, err := follower.current.NextSource(ctx)
	if err != nil || ok {
		if ok {
			follower.complete = SourcePosition{Identity: line.Identity, Generation: line.Generation, Offset: line.End, Anchor: line.EndAnchor}
		}
		return line, ok, err
	}
	if len(follower.queued) != 0 && !follower.currentAtPath {
		if err := follower.refreshQueue(); err != nil {
			if rotationPending(err) {
				return SourceLine{}, false, nil
			}
			return SourceLine{}, false, err
		}
		if follower.currentAtPath {
			return SourceLine{}, false, nil
		}
		stable, err := follower.stableForSwitch(follower.queued[0].identity)
		if err != nil || !stable {
			return SourceLine{}, false, err
		}
		if err := follower.switchTo(follower.queued[0]); err != nil {
			if rotationPending(err) {
				return SourceLine{}, false, nil
			}
			return SourceLine{}, false, err
		}
		follower.queued = follower.queued[1:]
		follower.resetDrain()
		return SourceLine{}, false, nil
	}
	if !follower.currentAtPath {
		if err := follower.refreshQueue(); err != nil {
			if rotationPending(err) {
				return SourceLine{}, false, nil
			}
			return SourceLine{}, false, err
		}
		return SourceLine{}, false, nil
	}
	pathInfo, err := os.Stat(follower.inputPath)
	if errors.Is(err, os.ErrNotExist) {
		return SourceLine{}, false, nil
	}
	if err != nil {
		return SourceLine{}, false, err
	}
	pathIdentity, err := identityFromFileInfo(pathInfo)
	if err != nil {
		return SourceLine{}, false, err
	}
	if pathIdentity == follower.current.Identity() {
		follower.queued = nil
		follower.resetDrain()
		if pathInfo.Size() < follower.current.CurrentOffset() {
			return SourceLine{}, false, &SourceTruncatedError{Identity: pathIdentity, Offset: follower.current.CurrentOffset(), Size: pathInfo.Size()}
		}
		return SourceLine{}, false, nil
	}
	if err := follower.refreshQueue(); err != nil {
		if rotationPending(err) {
			return SourceLine{}, false, nil
		}
		return SourceLine{}, false, err
	}
	stable, err := follower.stableForSwitch(follower.queued[0].identity)
	if err != nil || !stable {
		return SourceLine{}, false, err
	}
	candidate := follower.queued[0]
	if err := follower.switchTo(candidate); err != nil {
		if rotationPending(err) {
			return SourceLine{}, false, nil
		}
		return SourceLine{}, false, err
	}
	follower.queued = follower.queued[1:]
	follower.resetDrain()
	return SourceLine{}, false, nil
}

func (follower *RotatingFollower) refreshQueue() error {
	previous := follower.queued
	candidates, err := discoverCandidates(follower.inputPath, follower.options.ExcludePaths)
	if err != nil {
		return err
	}
	currentIndex := -1
	for i, candidate := range candidates {
		if candidate.identity == follower.current.Identity() {
			currentIndex = i
			if candidate.current {
				follower.currentAtPath = true
				follower.queued = nil
				return nil
			}
			break
		}
	}
	if currentIndex < 0 || currentIndex+1 >= len(candidates) {
		return &SourceGapError{Identity: follower.current.Identity()}
	}
	refreshed := candidates[currentIndex+1:]
	for _, known := range previous {
		found := false
		for _, candidate := range refreshed {
			if candidate.identity == known.identity {
				found = true
				break
			}
		}
		if !found {
			return &SourceGapError{Identity: known.identity}
		}
	}
	if err := validateGenerationChain(candidates[currentIndex:]); err != nil {
		return err
	}
	follower.queued = refreshed
	return nil
}

func rotationPending(err error) bool {
	return errors.Is(err, errInputPathPending)
}

func (follower *RotatingFollower) stableForSwitch(next FileIdentity) (bool, error) {
	size, err := follower.current.descriptorSize()
	if err != nil {
		return false, err
	}
	if size < follower.current.CurrentOffset() {
		return false, &SourceTruncatedError{Identity: follower.current.Identity(), Offset: follower.current.CurrentOffset(), Size: size}
	}
	now := time.Now()
	if next != follower.pendingIdentity || size != follower.drainSize {
		follower.pendingIdentity = next
		follower.drainSize = size
		follower.drainStarted = now
		return false, nil
	}
	if now.Sub(follower.drainStarted) < follower.options.DrainInterval {
		return false, nil
	}
	return true, nil
}

func (follower *RotatingFollower) resetDrain() {
	follower.pendingIdentity = FileIdentity{}
	follower.drainStarted = time.Time{}
	follower.drainSize = 0
}

func (follower *RotatingFollower) switchTo(candidate sourceCandidate) error {
	options := follower.options.FollowerOptions
	options.Generation = follower.current.generation + 1
	next, err := OpenFileFollowerAt(candidate.path, options, 0, &candidate.identity)
	if err != nil {
		resolved, resolveErr := follower.findCandidate(candidate.identity)
		if resolveErr != nil {
			return errors.Join(err, resolveErr)
		}
		candidate = resolved
		next, err = OpenFileFollowerAt(candidate.path, options, 0, &candidate.identity)
		if err != nil {
			return err
		}
	}
	hadPartial := follower.current.HasPartial()
	if err := follower.current.transferPartialTo(next); err != nil {
		_ = next.Close()
		return err
	}
	if err := follower.current.Close(); err != nil {
		_ = next.Close()
		return err
	}
	follower.current = next
	follower.currentAtPath = candidate.current
	follower.rotationCount++
	if !hadPartial {
		follower.complete = SourcePosition{Identity: candidate.identity, Generation: options.Generation, Offset: 0, Anchor: next.originAnchor}
	}
	return nil
}

func (follower *RotatingFollower) findCandidate(identity FileIdentity) (sourceCandidate, error) {
	candidates, err := discoverCandidates(follower.inputPath, follower.options.ExcludePaths)
	if err != nil {
		return sourceCandidate{}, err
	}
	for _, candidate := range candidates {
		if candidate.identity == identity {
			return candidate, nil
		}
	}
	return sourceCandidate{}, &SourceGapError{Identity: identity}
}

// CompletePosition returns the end of the last complete physical line.
func (follower *RotatingFollower) CompletePosition() SourcePosition { return follower.complete }

// RotationCount is incremented after every generation transition.
func (follower *RotatingFollower) RotationCount() uint64 { return follower.rotationCount }

// CaughtUp reports whether the active descriptor is the configured path and
// has reached its current size.
func (follower *RotatingFollower) CaughtUp() bool {
	if !follower.currentAtPath || len(follower.queued) != 0 {
		return false
	}
	size, err := follower.current.descriptorSize()
	return err == nil && size == follower.current.CurrentOffset()
}

// LagBytes estimates unread source bytes across the active and retained
// generations visible at the instant of the call.
func (follower *RotatingFollower) LagBytes() (int64, error) {
	size, err := follower.current.descriptorSize()
	if err != nil {
		return 0, err
	}
	lag := size - follower.current.CurrentOffset()
	if lag < 0 {
		return 0, &SourceTruncatedError{Identity: follower.current.Identity(), Offset: follower.current.CurrentOffset(), Size: size}
	}
	candidates, err := discoverCandidates(follower.inputPath, follower.options.ExcludePaths)
	if err != nil {
		return 0, err
	}
	found := false
	for _, candidate := range candidates {
		if candidate.identity == follower.current.Identity() {
			found = true
			continue
		}
		if !found {
			continue
		}
		info, err := os.Stat(candidate.path)
		if err != nil {
			return 0, err
		}
		lag += info.Size()
	}
	if !found {
		return 0, &SourceGapError{Identity: follower.current.Identity()}
	}
	return lag, nil
}

// Close releases the active source descriptor.
func (follower *RotatingFollower) Close() error { return follower.current.Close() }

func discoverCandidates(inputPath string, excludes []string) ([]sourceCandidate, error) {
	directory := filepath.Dir(inputPath)
	base := filepath.Base(inputPath)
	excluded := make([]string, 0, len(excludes))
	for _, path := range excludes {
		if path == "" {
			continue
		}
		canonical, err := CanonicalPath(path)
		if err == nil {
			excluded = append(excluded, canonical)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	candidates := make([]sourceCandidate, 0)
	identities := make(map[FileIdentity]int)
	for _, entry := range entries {
		name := entry.Name()
		number, numbered := rotationNumber(base, name)
		if name != base && !numbered {
			continue
		}
		if isCompressedRotation(name) {
			continue
		}
		path := filepath.Join(directory, name)
		if isExcludedPath(path, excluded) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		identity, err := identityFromFileInfo(info)
		if err != nil {
			return nil, err
		}
		candidate := sourceCandidate{path: path, identity: identity, current: path == inputPath, number: number, numbered: numbered}
		if index, exists := identities[identity]; exists {
			return nil, fmt.Errorf("ambiguous generation aliases: %s and %s", candidates[index].path, path)
		}
		identities[identity] = len(candidates)
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return nil, os.ErrNotExist
	}
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].current || candidates[j].current {
				continue
			}
			if !candidates[i].numbered || !candidates[j].numbered || candidates[i].number == candidates[j].number {
				return nil, fmt.Errorf("ambiguous retained generation order between %s and %s", candidates[i].path, candidates[j].path)
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].current != candidates[j].current {
			return !candidates[i].current
		}
		return candidates[i].number > candidates[j].number
	})
	currentFound := false
	for _, candidate := range candidates {
		currentFound = currentFound || candidate.current
	}
	if !currentFound {
		return nil, errInputPathPending
	}
	return candidates, nil
}

// validateGenerationChain requires the conventional .N, ... .2, .1, active
// sequence. Missing intermediate generations are gaps, regardless of mtimes.
func validateGenerationChain(candidates []sourceCandidate) error {
	for i := 0; i+1 < len(candidates); i++ {
		older, newer := candidates[i], candidates[i+1]
		expected := uint64(0)
		if !newer.current {
			expected = newer.number
		}
		if older.current || older.number == 0 || older.number-1 != expected {
			return fmt.Errorf("source generation gap between %s and %s: %w", older.path, newer.path, &SourceGapError{Identity: older.identity})
		}
	}
	return nil
}

func isExcludedPath(path string, excluded []string) bool {
	for _, statePath := range excluded {
		if path == statePath || strings.HasPrefix(path, statePath+".") || strings.HasPrefix(path, statePath+"-") {
			return true
		}
	}
	return false
}

func rotationNumber(base, name string) (uint64, bool) {
	suffix := strings.TrimPrefix(name, base+".")
	if suffix == name || suffix == "" {
		return 0, false
	}
	for _, character := range suffix {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	number, err := strconv.ParseUint(suffix, 10, 64)
	return number, err == nil
}

func isCompressedRotation(name string) bool {
	for _, suffix := range []string{".gz", ".xz", ".bz2", ".zst"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
