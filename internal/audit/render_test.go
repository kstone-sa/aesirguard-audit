package audit

import "testing"

func TestWithHumanMessageRendersProcessExecution(t *testing.T) {
	success := true
	event := CanonicalEvent{
		Event: CanonicalEventMeta{Success: &success},
		Actor: &CanonicalActor{User: "operator"},
		Process: &CanonicalProcess{
			User:       "root",
			Executable: "/usr/bin/sudo",
			Argv:       []string{"sudo", "cat", "file with spaces"},
		},
	}

	got := WithHumanMessage(event)
	want := `operator executed /usr/bin/sudo as root with arguments: cat "file with spaces"`
	if got.Message != want || got.Renderer != HumanRendererVersion {
		t.Fatalf("rendered event = %#v", got)
	}
}

func TestWithHumanMessageLeavesUnsupportedEventUntouched(t *testing.T) {
	event := CanonicalEvent{Event: CanonicalEventMeta{Type: "USER_AUTH"}}
	got := WithHumanMessage(event)
	if got.Message != "" || got.Renderer != "" {
		t.Fatalf("rendered event = %#v", got)
	}
}

func TestWithHumanMessageDoesNotDescribeNonExecutionSyscallAsExecution(t *testing.T) {
	event := CanonicalEvent{
		Actor: &CanonicalActor{User: "operator"},
		Process: &CanonicalProcess{
			Executable: "/usr/bin/cat",
			Syscall:    "openat",
		},
	}

	got := WithHumanMessage(event)
	if got.Message != "" || got.Renderer != "" {
		t.Fatalf("rendered non-execution event = %#v", got)
	}
}

func TestWithHumanMessageRendersNamedExecveWithoutArguments(t *testing.T) {
	success := true
	event := CanonicalEvent{
		Event: CanonicalEventMeta{Success: &success},
		Process: &CanonicalProcess{
			Executable: "/usr/bin/true",
			Syscall:    "execve",
		},
	}

	got := WithHumanMessage(event)
	if got.Message != "A process executed /usr/bin/true" || got.Renderer != HumanRendererVersion {
		t.Fatalf("rendered execution event = %#v", got)
	}
}

func TestWithHumanMessageRendersCISAuditFamilies(t *testing.T) {
	success := true
	failure := false
	tests := []struct {
		name    string
		event   CanonicalEvent
		message string
	}{
		{
			name:    "sudo scope",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "change_privilege_scope"}, Actor: &CanonicalActor{User: "operator"}, Paths: []CanonicalPath{{Name: "/etc/sudoers"}}},
			message: "operator changed sudo privilege scope at /etc/sudoers",
		},
		{
			name:    "sudo log",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "write_sudo_log"}, Actor: &CanonicalActor{User: "operator"}, Paths: []CanonicalPath{{Name: "/var/log/sudo.log"}}},
			message: "operator modified the sudo log at /var/log/sudo.log",
		},
		{
			name:    "time",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "change_time"}, Actor: &CanonicalActor{User: "root"}, Process: &CanonicalProcess{Syscall: "clock_settime"}},
			message: "root changed system time using clock_settime",
		},
		{
			name:    "network",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "change_network_configuration"}, Actor: &CanonicalActor{User: "root"}, Paths: []CanonicalPath{{Name: "/etc/hostname"}}},
			message: "root changed network configuration at /etc/hostname",
		},
		{
			name:    "failed access",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "access", Success: &failure}, Actor: &CanonicalActor{User: "operator"}, Paths: []CanonicalPath{{Name: "/etc/shadow"}}, Process: &CanonicalProcess{Syscall: "openat"}},
			message: "operator failed to access a file at /etc/shadow using openat",
		},
		{
			name:    "identity",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "change_identity_configuration"}, Actor: &CanonicalActor{User: "root"}, Paths: []CanonicalPath{{Name: "/etc/passwd"}}},
			message: "root changed user or group configuration at /etc/passwd",
		},
		{
			name:    "permissions",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "change_permissions"}, Actor: &CanonicalActor{User: "operator"}, Paths: []CanonicalPath{{Name: "/srv/data"}}, Process: &CanonicalProcess{Syscall: "chmod"}},
			message: "operator changed file permissions or ownership on /srv/data using chmod",
		},
		{
			name:    "mount",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "mount_filesystem"}, Actor: &CanonicalActor{User: "root"}, Paths: []CanonicalPath{{Name: "/mnt/usb"}}, Process: &CanonicalProcess{Syscall: "mount"}},
			message: "root mounted a filesystem at /mnt/usb using mount",
		},
		{
			name:    "session",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "update_session_record"}, Paths: []CanonicalPath{{Name: "/var/log/wtmp"}}},
			message: "A process updated session records at /var/log/wtmp",
		},
		{
			name:    "login",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "update_login_record"}, Paths: []CanonicalPath{{Name: "/run/faillock/operator"}}},
			message: "A process updated login records at /run/faillock/operator",
		},
		{
			name:    "delete",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "delete"}, Actor: &CanonicalActor{User: "operator"}, Paths: []CanonicalPath{{Name: "/tmp/evidence"}}},
			message: "operator deleted a file at /tmp/evidence",
		},
		{
			name:    "rename",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "rename"}, Actor: &CanonicalActor{User: "operator"}, Paths: []CanonicalPath{{Name: "/tmp/old", NameType: "DELETE"}, {Name: "/tmp/new", NameType: "CREATE"}}},
			message: "operator renamed a file from /tmp/old to /tmp/new",
		},
		{
			name:    "MAC policy",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "change_mac_policy"}, Actor: &CanonicalActor{User: "root"}, Paths: []CanonicalPath{{Name: "/etc/apparmor.d/profile"}}},
			message: "root changed mandatory access control policy at /etc/apparmor.d/profile",
		},
		{
			name:    "module load",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "load_kernel_module"}, Actor: &CanonicalActor{User: "root"}, Paths: []CanonicalPath{{Name: "/lib/modules/example.ko"}}, Process: &CanonicalProcess{Syscall: "finit_module"}},
			message: "root loaded a kernel module from /lib/modules/example.ko using finit_module",
		},
		{
			name:    "module unload",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "unload_kernel_module"}, Actor: &CanonicalActor{User: "root"}, Process: &CanonicalProcess{Syscall: "delete_module"}},
			message: "root unloaded a kernel module using delete_module",
		},
		{
			name:    "module query",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "query_kernel_module"}, Actor: &CanonicalActor{User: "root"}, Process: &CanonicalProcess{Syscall: "query_module"}},
			message: "root queried kernel modules using query_module",
		},
		{
			name:    "audit configuration",
			event:   CanonicalEvent{Event: CanonicalEventMeta{Action: "change_audit_configuration"}, Actor: &CanonicalActor{User: "root"}, Paths: []CanonicalPath{{Name: "/etc/audit/rules.d/cis.rules"}}},
			message: "root changed audit configuration at /etc/audit/rules.d/cis.rules",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.event.Event.Success == nil {
				test.event.Event.Success = &success
			}
			got := WithHumanMessage(test.event)
			if got.Message != test.message || got.Renderer != HumanRendererVersion {
				t.Fatalf("rendered event = %#v, want %q", got, test.message)
			}
		})
	}
}

func TestWithHumanMessageDoesNotInventUnknownOutcome(t *testing.T) {
	event := CanonicalEvent{
		Event:   CanonicalEventMeta{Action: "change_time"},
		Actor:   &CanonicalActor{User: "operator"},
		Process: &CanonicalProcess{Syscall: "clock_settime"},
	}

	got := WithHumanMessage(event)
	if got.Message != "operator attempted to change system time using clock_settime" {
		t.Fatalf("message = %q", got.Message)
	}
}

func TestWithHumanMessageDescribesFailedExecveAccurately(t *testing.T) {
	failure := false
	event := CanonicalEvent{
		Event: CanonicalEventMeta{Action: "execute", Success: &failure},
		Actor: &CanonicalActor{User: "operator"},
		Process: &CanonicalProcess{
			Syscall:    "execve",
			Executable: "/missing/tool",
		},
	}

	got := WithHumanMessage(event)
	if got.Message != "operator failed to execute /missing/tool" {
		t.Fatalf("message = %q", got.Message)
	}
}
