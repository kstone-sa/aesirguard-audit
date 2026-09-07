package audit

import (
	"bufio"
	"os"
	"testing"
)

func TestCISDistroCorpus(t *testing.T) {
	tests := []struct {
		fixture string
		action  string
		message string
	}{
		{"debian12.audit", "observe_session_activity", "operator generated session activity at /var/log/wtmp using openat"},
		{"debian13.audit", "change_permissions", "operator changed file permissions or ownership on /srv/data using fchmodat2"},
		{"ubuntu2204.audit", "observe_configuration_activity", "operator generated configuration activity at /etc/apparmor.d/usr.bin.example using openat"},
		{"ubuntu2404.audit", "change_network_configuration", "operator changed network configuration using sethostname"},
		{"rhel8.audit", "observe_system_activity", "operator generated system activity using settimeofday"},
		{"rhel9.audit", "observe_configuration_activity", "operator generated configuration activity at /etc/selinux/targeted/contexts/files/file_contexts.local using openat"},
		{"oracle8.audit", "observe_configuration_activity", "operator generated configuration activity at /etc/sudoers.d/operators using openat"},
		{"oracle9.audit", "load_kernel_module", "operator loaded a kernel module from /lib/modules/example.ko using finit_module"},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			event := readSingleCISFixture(t, "../../testdata/cis/"+test.fixture)
			canonical := WithHumanMessage(BuildCanonicalEvent(event, CanonicalOptions{}))
			if canonical.Event.Action != test.action {
				t.Fatalf("action = %q, want %q", canonical.Event.Action, test.action)
			}
			if canonical.Message != test.message {
				t.Fatalf("message = %q, want %q", canonical.Message, test.message)
			}
		})
	}
}

func readSingleCISFixture(t *testing.T, path string) AssembledEvent {
	t.Helper()
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	assembler := NewAssembler(0)
	var events []AssembledEvent
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		events = append(events, assembler.Add(mustParseRecord(t, scanner.Text()))...)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	events = append(events, assembler.FlushAll()...)
	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	return events[0]
}
