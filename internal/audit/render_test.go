package audit

import "testing"

func TestWithHumanMessageRendersProcessExecution(t *testing.T) {
	event := CanonicalEvent{
		Actor: &CanonicalActor{User: "mario"},
		Process: &CanonicalProcess{
			User:       "root",
			Executable: "/usr/bin/sudo",
			Argv:       []string{"sudo", "cat", "file with spaces"},
		},
	}

	got := WithHumanMessage(event)
	want := `mario executed /usr/bin/sudo as root with arguments: cat "file with spaces"`
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
		Actor: &CanonicalActor{User: "mario"},
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
	event := CanonicalEvent{
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
