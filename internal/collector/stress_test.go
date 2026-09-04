package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotatingFollowerRecoversAcrossManyRetainedGenerations(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	const rotations = 32
	baseTime := time.Now().Add(-time.Hour)
	for suffix := rotations; suffix >= 1; suffix-- {
		candidate := fmt.Sprintf("%s.%d", path, suffix)
		contents := fmt.Sprintf("generation-%02d\n", rotations-suffix)
		if err := os.WriteFile(candidate, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		modified := baseTime.Add(time.Duration(rotations-suffix) * time.Second)
		if err := os.Chtimes(candidate, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf("generation-%02d\n", rotations)), 0o600); err != nil {
		t.Fatal(err)
	}
	oldest := fmt.Sprintf("%s.%d", path, rotations)
	info, err := os.Stat(oldest)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := identityFromFileInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	follower := mustOpenRotatingFollower(t, path, &Checkpoint{Device: identity.Device, Inode: identity.Inode})
	defer follower.Close()
	for generation := 0; generation <= rotations; generation++ {
		line := mustNextRotatingLine(t, follower)
		want := fmt.Sprintf("generation-%02d", generation)
		if line.Text != want || line.Generation != uint64(generation) {
			t.Fatalf("generation %d = %#v, want %q", generation, line, want)
		}
	}
}
