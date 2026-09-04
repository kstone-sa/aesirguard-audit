package audit

import "testing"

func TestClassifyCanonicalEventCoversCISAuditFamilies(t *testing.T) {
	failure := false
	tests := []struct {
		name     string
		event    CanonicalEvent
		category string
		action   string
	}{
		{
			name: "privileged or user emulation execution",
			event: CanonicalEvent{Process: &CanonicalProcess{Syscall: "execve", Executable: "/usr/bin/sudo"}},
			category: "process", action: "execute",
		},
		{
			name: "time change",
			event: CanonicalEvent{Process: &CanonicalProcess{Syscall: "clock_settime"}},
			category: "system", action: "change_time",
		},
		{
			name: "network configuration on Debian",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"system_network"}}, Paths: []CanonicalPath{{Name: "/etc/network/interfaces"}}},
			category: "configuration", action: "change_network_configuration",
		},
		{
			name: "network configuration on RHEL or Oracle Linux",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"system_network"}}, Paths: []CanonicalPath{{Name: "/etc/NetworkManager/system-connections/prod.nmconnection"}}},
			category: "configuration", action: "change_network_configuration",
		},
		{
			name: "unsuccessful access",
			event: CanonicalEvent{Event: CanonicalEventMeta{Success: &failure}, Process: &CanonicalProcess{Syscall: "openat"}},
			category: "file", action: "access",
		},
		{
			name: "identity configuration",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"identity"}}, Paths: []CanonicalPath{{Name: "/etc/security/opasswd"}}},
			category: "configuration", action: "change_identity_configuration",
		},
		{
			name: "Debian 13 permission syscall",
			event: CanonicalEvent{Process: &CanonicalProcess{Syscall: "fchmodat2"}},
			category: "file", action: "change_permissions",
		},
		{
			name: "filesystem mount",
			event: CanonicalEvent{Process: &CanonicalProcess{Syscall: "mount"}},
			category: "system", action: "mount_filesystem",
		},
		{
			name: "session record",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"session"}}, Paths: []CanonicalPath{{Name: "/var/log/wtmp"}}},
			category: "session", action: "update_session_record",
		},
		{
			name: "login record",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"logins"}}, Paths: []CanonicalPath{{Name: "/run/faillock/mario"}}},
			category: "authentication", action: "update_login_record",
		},
		{
			name: "Debian 13 rename syscall",
			event: CanonicalEvent{Process: &CanonicalProcess{Syscall: "renameat2"}},
			category: "file", action: "rename",
		},
		{
			name: "file deletion",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"delete"}}, Process: &CanonicalProcess{Syscall: "unlinkat"}},
			category: "file", action: "delete",
		},
		{
			name: "AppArmor policy",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"MAC-policy"}}, Paths: []CanonicalPath{{Name: "/etc/apparmor.d/usr.bin.example"}}},
			category: "configuration", action: "change_mac_policy",
		},
		{
			name: "SELinux policy",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"MAC-policy"}}, Paths: []CanonicalPath{{Name: "/etc/selinux/targeted/contexts/files/file_contexts"}}},
			category: "configuration", action: "change_mac_policy",
		},
		{
			name: "sudo scope",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"scope"}}, Paths: []CanonicalPath{{Name: "/etc/sudoers.d/operators"}}},
			category: "configuration", action: "change_privilege_scope",
		},
		{
			name: "configured sudo log",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"sudo-log-file"}}},
			category: "file", action: "write_sudo_log",
		},
		{
			name: "kernel module load",
			event: CanonicalEvent{Process: &CanonicalProcess{Syscall: "finit_module"}},
			category: "system", action: "load_kernel_module",
		},
		{
			name: "kernel module unload",
			event: CanonicalEvent{Process: &CanonicalProcess{Syscall: "delete_module"}},
			category: "system", action: "unload_kernel_module",
		},
		{
			name: "legacy kernel module query",
			event: CanonicalEvent{Process: &CanonicalProcess{Syscall: "query_module"}},
			category: "system", action: "query_kernel_module",
		},
		{
			name: "audit configuration",
			event: CanonicalEvent{Rule: &CanonicalRule{Keys: []string{"audit_config"}}, Paths: []CanonicalPath{{Name: "/etc/audit/rules.d/cis.rules"}}},
			category: "configuration", action: "change_audit_configuration",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classifyCanonicalEvent(&test.event)
			if test.event.Event.Category != test.category || test.event.Event.Action != test.action {
				t.Fatalf("classification = %s/%s, want %s/%s", test.event.Event.Category, test.event.Event.Action, test.category, test.action)
			}
		})
	}
}

func TestClassifyCanonicalEventDoesNotTreatUnkeyedReadAsConfigurationChange(t *testing.T) {
	success := true
	event := CanonicalEvent{
		Event:   CanonicalEventMeta{Success: &success},
		Process: &CanonicalProcess{Syscall: "openat"},
		Paths:   []CanonicalPath{{Name: "/etc/passwd"}},
	}

	classifyCanonicalEvent(&event)
	if event.Event.Category != "" || event.Event.Action != "" {
		t.Fatalf("classification = %#v", event.Event)
	}
}

func TestClassifyCanonicalEventDoesNotClassifySuccessfulAccessAsCISFailure(t *testing.T) {
	success := true
	event := CanonicalEvent{
		Event:   CanonicalEventMeta{Success: &success},
		Rule:    &CanonicalRule{Keys: []string{"access"}},
		Process: &CanonicalProcess{Syscall: "openat"},
	}

	classifyCanonicalEvent(&event)
	if event.Event.Category != "" || event.Event.Action != "" {
		t.Fatalf("classification = %#v", event.Event)
	}
}

func TestEveryCISClassificationHasRendererCoverage(t *testing.T) {
	failure := false
	for _, rule := range cisAuditClassification.Rules {
		t.Run(rule.Action, func(t *testing.T) {
			event := CanonicalEvent{
				Event: CanonicalEventMeta{
					Category: rule.Category,
					Action:   rule.Action,
				},
				Actor: &CanonicalActor{User: "analyst"},
			}
			if rule.RequireFailure {
				event.Event.Success = &failure
			}
			if len(rule.Syscalls) > 0 {
				event.Process = &CanonicalProcess{Syscall: rule.Syscalls[0]}
			}
			if len(rule.Paths) > 0 {
				event.Paths = []CanonicalPath{{Name: rule.Paths[0]}}
			}

			rendered := WithHumanMessage(event)
			if rendered.Message == "" || rendered.Renderer != HumanRendererVersion {
				t.Fatalf("missing renderer for %s/%s", rule.Category, rule.Action)
			}
		})
	}
}
