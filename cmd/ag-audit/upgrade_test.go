package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/collector"
)

type upgradeChild struct {
	command *exec.Cmd
	done    chan error
	logPath string
}

func startUpgradeChild(t *testing.T, binary string, args []string, logPath string, stdoutPaths ...string) *upgradeChild {
	t.Helper()
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, args...)
	command.Stderr = log
	command.Stdout = log // Managed mode must not emit canonical data on stdout.
	var captured *os.File
	if len(stdoutPaths) > 0 && stdoutPaths[0] != "" {
		captured, err = os.OpenFile(stdoutPaths[0], os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Close()
			t.Fatal(err)
		}
		command.Stdout = captured
	}
	if err := command.Start(); err != nil {
		log.Close()
		if captured != nil {
			captured.Close()
		}
		t.Fatal(err)
	}
	child := &upgradeChild{command: command, done: make(chan error, 1), logPath: logPath}
	go func() {
		err := command.Wait()
		log.Close()
		if captured != nil {
			captured.Close()
		}
		child.done <- err
	}()
	t.Cleanup(func() { _ = command.Process.Kill() })
	return child
}

func waitUpgrade(t *testing.T, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("upgrade gate timed out: " + description)
}

func (c *upgradeChild) wait(t *testing.T, wantFailure bool) {
	t.Helper()
	select {
	case err := <-c.done:
		if (err != nil) != wantFailure {
			data, _ := os.ReadFile(c.logPath)
			t.Fatalf("process exit=%v log=%s", err, data)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("collector did not stop")
	}
}

func appendUpgrade(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(text)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// This test intentionally creates state with the real pre-fix binary. It is a
// required gate in scripts/verify-upgrade.sh, not a synthesized checkpoint test.
func TestBinaryUpgradeFromFailedDeployment(t *testing.T) {
	previous, fixed := os.Getenv("AG_AUDIT_PRE_FIX_BINARY"), os.Getenv("AG_AUDIT_FIXED_BINARY")
	if previous == "" || fixed == "" {
		t.Skip("run scripts/verify-upgrade.sh for the mandatory real-binary upgrade gate")
	}
	for _, mode := range []string{"managed_file", "stdout"} {
		for _, scenario := range []string{"oversized", "missing_generation", "combined"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				dir := t.TempDir()
				input, cpPath, out := filepath.Join(dir, "audit.log"), filepath.Join(dir, "checkpoint"), filepath.Join(dir, "events.ndjson")
				valid := func(serial int) string {
					return fmt.Sprintf("type=KERNEL msg=audit(1792000000.123:%d): device=test\n", serial)
				}
				if err := os.WriteFile(input, []byte(valid(1)), 0600); err != nil {
					t.Fatal(err)
				}
				args := []string{"--follow", "--poll-interval=1ms", "--checkpoint-interval=1ms", "--rotation-drain-interval=1ms", "--event-timeout=1s",
					"--checkpoint-file=" + cpPath, "--lock-file=" + filepath.Join(dir, "lock"), input}
				stdoutPath := out
				if mode == "managed_file" {
					args = append([]string{"--output-file=" + out}, args...)
					stdoutPath = ""
				}
				old := startUpgradeChild(t, previous, args, filepath.Join(dir, "old.log"), stdoutPath)
				waitUpgrade(t, func() bool {
					cp, _ := collector.LoadCheckpoint(cpPath)
					return cp != nil && cp.Offset == int64(len(valid(1)))
				}, "pre-fix nonzero checkpoint")
				var pathological strings.Builder
				for i := 0; i < 300; i++ {
					fmt.Fprintf(&pathological, "type=PATH msg=audit(1792000000.123:2): item=%d name=\"/safe\"\n", i)
				}
				pathological.WriteString("type=EOE msg=audit(1792000000.123:2):\n")
				pathological.WriteString(valid(3))
				if scenario != "missing_generation" {
					appendUpgrade(t, input, pathological.String())
					old.wait(t, true)
					log, _ := os.ReadFile(old.logPath)
					if !bytes.Contains(log, []byte("assembler records per event limit reached (256)")) {
						t.Fatalf("did not reproduce pre-fix failure: %s", log)
					}
				} else {
					old.command.Process.Signal(syscall.SIGTERM)
					old.wait(t, false)
				}
				failedCheckpoint, _ := os.ReadFile(cpPath)
				if scenario != "oversized" {
					// Keep the purged inode open until the replacement exists, avoiding
					// accidental inode reuse in the fixture. No retained generation remains.
					held, err := os.Open(input)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(input); err != nil {
						t.Fatal(err)
					}
					replacement := valid(3)
					if scenario == "combined" {
						replacement = pathological.String()
					}
					if err := os.WriteFile(input, []byte(replacement), 0600); err != nil {
						t.Fatal(err)
					}
					held.Close()
					old = startUpgradeChild(t, previous, args, filepath.Join(dir, "old-gap.log"), stdoutPath)
					old.wait(t, true)
					log, _ := os.ReadFile(old.logPath)
					if !bytes.Contains(log, []byte("source_gap")) {
						t.Fatalf("pre-fix gap not reproduced: %s", log)
					}
				}
				unchanged, _ := os.ReadFile(cpPath)
				if !bytes.Equal(failedCheckpoint, unchanged) {
					t.Fatal("pre-fix failure unexpectedly rewrote checkpoint")
				}
				// Replace only the executable. Exact same args, paths, state and output.
				for restart := 0; restart < 3; restart++ {
					child := startUpgradeChild(t, fixed, args, filepath.Join(dir, fmt.Sprintf("fixed-%d.log", restart)), stdoutPath)
					if restart > 0 {
						appendUpgrade(t, input, valid(3+restart))
					}
					waitUpgrade(t, func() bool {
						cp, err := collector.LoadCheckpoint(cpPath)
						stat, statErr := os.Stat(input)
						return err == nil && statErr == nil && cp != nil && cp.Offset == stat.Size() && cp.Inode == stat.Sys().(*syscall.Stat_t).Ino && cp.Device == uint64(stat.Sys().(*syscall.Stat_t).Dev)
					}, "upgraded collector caught up and checkpointed")
					data, err := os.ReadFile(out)
					if err != nil {
						t.Fatal(err)
					}
					seen := false
					for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
						var event struct {
							Audit struct {
								ID string `json:"id"`
							}
							Event struct {
								Type string `json:"type"`
							}
						}
						if err := json.Unmarshal(line, &event); err != nil {
							t.Fatal(err)
						}
						if event.Audit.ID == fmt.Sprintf("1792000000.123:%d", 3+restart) && event.Event.Type == "KERNEL" {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("lost subsequent valid event after upgrade/restart %d", restart)
					}
					// Forced process death checks durable state rather than shutdown flushing.
					child.command.Process.Kill()
					child.wait(t, true)
					log, _ := os.ReadFile(child.logPath)
					if bytes.Contains(log, []byte(`"event":"fatal"`)) {
						t.Fatalf("upgraded collector failed: %s", log)
					}
					if scenario != "oversized" {
						ledger, err := collector.LoadGapLedger(cpPath + ".recovery")
						if err != nil || ledger == nil || ledger.Total != 1 || ledger.Incidents[0].Prepared {
							t.Fatalf("invalid/repeated recovery: %#v %v", ledger, err)
						}
						if restart == 0 && (!bytes.Contains(log, []byte(`"event":"source_gap"`)) || !bytes.Contains(log, []byte("recovery_resumed_with_gap"))) {
							t.Fatal("loss not explicitly reported")
						}
						if restart > 0 && bytes.Contains(log, []byte(`"event":"source_gap"`)) {
							t.Fatal("repeats same incident on restart")
						}
					}
				}
			})
		}
	}
}
