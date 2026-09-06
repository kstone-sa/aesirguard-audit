package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestProcessContextNeverChangesSyscallAction(t *testing.T) {
	for _, tc := range []struct{ syscall, number, key, result, action string }{
		{"unlink", "87", "delete", "yes", "delete"},
		{"chmod", "90", "perm_mod", "yes", "change_permissions"},
		{"openat", "257", "access", "no", "access"},
		{"mount", "165", "mounts", "yes", "mount_filesystem"},
		{"init_module", "175", "modules", "yes", "load_kernel_module"},
	} {
		t.Run(tc.syscall, func(t *testing.T) {
			line := fmt.Sprintf(`type=SYSCALL msg=audit(100.0:1): arch=c000003e syscall=%s success=%s exe="/bin/worker" key="%s"`, tc.number, tc.result, tc.key) + "\x1dSYSCALL=" + tc.syscall
			base := []string{line, `type=PATH msg=audit(100.0:1): item=0 name="/tmp/object" nametype=NORMAL`}
			for _, title := range []string{"", `type=PROCTITLE msg=audit(100.0:1): proctitle="worker"`, `type=PROCTITLE msg=audit(100.0:1): proctitle=776F726B65720061726700`} {
				lines := append([]string{}, base...)
				if title != "" {
					lines = append(lines, title)
				}
				e := canonicalLines(t, lines...)
				if e.Event.Action != tc.action {
					t.Fatalf("context changed action: %#v", e)
				}
				b, err := json.Marshal(e)
				if err != nil {
					t.Fatal(err)
				}
				var roundtrip CanonicalEvent
				if err := json.Unmarshal(b, &roundtrip); err != nil {
					t.Fatal(err)
				}
				rendered := WithHumanMessage(roundtrip)
				if strings.Contains(rendered.Message, "execut") {
					t.Fatalf("invented execution: %s", rendered.Message)
				}
			}
		})
	}
}

func TestExecveEvidenceSurvivesMissingArguments(t *testing.T) {
	e := canonicalLines(t, `type=SYSCALL msg=audit(100.0:1): exe="/bin/tool"`, `type=EXECVE msg=audit(100.0:1): argc=2 a0="tool"`, `type=PROCTITLE msg=audit(100.0:1): proctitle="different"`)
	if e.Event.Action != "execute" || e.Process.ArgvSource != "execve" || len(e.Process.Argv) != 0 || len(e.Event.Issues) == 0 {
		t.Fatalf("lost evidence or concealed incomplete EXECVE: %#v", e)
	}
}
