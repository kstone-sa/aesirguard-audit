package audit

import (
	"path"
	"strconv"
	"strings"
)

// HumanRendererVersion identifies the deterministic message template set.
const HumanRendererVersion = "1"

// WithHumanMessage returns an event with an analyst-readable message when a
// supported template can be rendered entirely from canonical fields.
func WithHumanMessage(event CanonicalEvent) CanonicalEvent {
	message, ok := renderProcessMessage(event)
	if !ok {
		return event
	}
	event.Message = message
	event.Renderer = HumanRendererVersion
	return event
}

func renderProcessMessage(event CanonicalEvent) (string, bool) {
	if event.Process == nil {
		return "", false
	}
	process := event.Process
	if process.Syscall != "execve" && process.Syscall != "execveat" && len(process.Argv) == 0 {
		return "", false
	}
	executable := process.Executable
	if executable == "" && len(process.Argv) > 0 {
		executable = process.Argv[0]
	}
	if executable == "" {
		executable = process.Name
	}
	if executable == "" {
		return "", false
	}

	actor := "A process"
	if event.Actor != nil {
		actor = renderedIdentity(event.Actor.User, event.Actor.UserID)
	}
	var builder strings.Builder
	builder.WriteString(actor)
	builder.WriteString(" executed ")
	builder.WriteString(executable)
	if process.User != "" || process.UserID != "" {
		builder.WriteString(" as ")
		builder.WriteString(renderedIdentity(process.User, process.UserID))
	}

	arguments := process.Argv
	if len(arguments) > 0 && sameExecutable(arguments[0], executable) {
		arguments = arguments[1:]
	}
	if len(arguments) > 0 {
		builder.WriteString(" with arguments: ")
		for index, argument := range arguments {
			if index > 0 {
				builder.WriteByte(' ')
			}
			builder.WriteString(renderedArgument(argument))
		}
	}
	return builder.String(), true
}

func renderedIdentity(name, id string) string {
	if name != "" {
		return name
	}
	if id != "" {
		return "user ID " + id
	}
	return "an unknown user"
}

func sameExecutable(argument, executable string) bool {
	return argument == executable || path.Base(executable) == argument
}

func renderedArgument(argument string) string {
	if argument == "" || strings.ContainsAny(argument, " \t\r\n\"\\") {
		return strconv.Quote(argument)
	}
	return argument
}
