package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerationOrderIndependentOfModificationTimes(t *testing.T) {
	for _, live := range []bool{false, true} {
		for _, times := range [][3]int{{1, 2, 3}, {3, 2, 1}, {2, 3, 1}, {3, 1, 2}, {1, 3, 2}, {2, 1, 3}, {1, 1, 1}} {
			t.Run(fmt.Sprintf("live=%v/times=%v", live, times), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "audit.log")
				var follower *RotatingFollower
				if live {
					if err := os.WriteFile(path, []byte("before\n"), 0600); err != nil {
						t.Fatal(err)
					}
					follower = mustOpenRotatingFollower(t, path, nil)
					mustNextRotatingLine(t, follower)
					if err := os.Rename(path, path+".3"); err != nil {
						t.Fatal(err)
					}
				}
				for i, suffix := range []string{".3", ".2", ".1"} {
					f := path + suffix
					if err := func() error {
						if live && i == 0 {
							return nil
						}
						return os.WriteFile(f, []byte(fmt.Sprintf("generation%d\n", i)), 0600)
					}(); err != nil {
						t.Fatal(err)
					}
					stamp := time.Unix(int64(times[i]), 0)
					if err := os.Chtimes(f, stamp, stamp); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(path, []byte("active\n"), 0600); err != nil {
					t.Fatal(err)
				}
				first := 0
				if live {
					first = 1
				} else {
					info, err := os.Stat(path + ".3")
					if err != nil {
						t.Fatal(err)
					}
					id, err := identityFromFileInfo(info)
					if err != nil {
						t.Fatal(err)
					}
					follower = mustOpenRotatingFollower(t, path, &Checkpoint{Device: id.Device, Inode: id.Inode})
				}
				defer follower.Close()
				for i := first; i < 4; i++ {
					want := fmt.Sprintf("generation%d", i)
					if i == 3 {
						want = "active"
					}
					got := mustNextRotatingLine(t, follower)
					if got.Text != want {
						t.Fatalf("got %q want %q", got.Text, want)
					}
				}
			})
		}
	}
}

func TestRecoveryRejectsMissingAndAmbiguousGenerations(t *testing.T) {
	for _, suffixes := range [][]string{{".3", ".1"}, {".2", ".01", ".1"}, {".0"}} {
		t.Run(fmt.Sprint(suffixes), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			for _, suffix := range append(suffixes, "") {
				if err := os.WriteFile(path+suffix, []byte("event\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			info, err := os.Stat(path + suffixes[0])
			if err != nil {
				t.Fatal(err)
			}
			id, err := identityFromFileInfo(info)
			if err != nil {
				t.Fatal(err)
			}
			follower, err := OpenRotatingFollower(path, RotationOptions{FollowerOptions: FollowerOptions{PollInterval: time.Millisecond, MaxLineBytes: 1024}, DrainInterval: time.Millisecond}, &Checkpoint{Device: id.Device, Inode: id.Inode})
			if err == nil {
				follower.Close()
				t.Fatal("accepted ambiguous or missing generation")
			}
		})
	}
}
