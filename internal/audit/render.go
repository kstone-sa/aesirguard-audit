package audit

import (
	"path"
	"strconv"
	"strings"
)

// HumanRendererVersion identifies the deterministic message template set.
const HumanRendererVersion = "2"

// WithHumanMessage returns an event with an analyst-readable message when a
// supported template can be rendered entirely from canonical fields.
func WithHumanMessage(event CanonicalEvent) CanonicalEvent {
	message, ok := renderCanonicalMessage(event)
	if !ok {
		return event
	}
	event.Message = message
	event.Renderer = HumanRendererVersion
	return event
}

func renderCanonicalMessage(event CanonicalEvent) (string, bool) {
	switch event.Event.Action {
	case "execute":
		return renderProcessMessage(event)
	case "change_privilege_scope":
		return renderMappedAction(event, "changed sudo privilege scope", "failed to change sudo privilege scope", "attempted to change sudo privilege scope", "at", false)
	case "write_sudo_log":
		return renderMappedAction(event, "modified the sudo log", "failed to modify the sudo log", "attempted to modify the sudo log", "at", true)
	case "change_time":
		return renderMappedAction(event, "changed system time", "failed to change system time", "attempted to change system time", "at", true)
	case "change_network_configuration":
		return renderMappedAction(event, "changed network configuration", "failed to change network configuration", "attempted to change network configuration", "at", true)
	case "access":
		return renderMappedAction(event, "accessed a file", "failed to access a file", "attempted to access a file", "at", true)
	case "change_identity_configuration":
		return renderMappedAction(event, "changed user or group configuration", "failed to change user or group configuration", "attempted to change user or group configuration", "at", true)
	case "change_permissions":
		return renderMappedAction(event, "changed file permissions or ownership", "failed to change file permissions or ownership", "attempted to change file permissions or ownership", "on", true)
	case "mount_filesystem":
		return renderMappedAction(event, "mounted a filesystem", "failed to mount a filesystem", "attempted to mount a filesystem", "at", true)
	case "update_session_record":
		return renderMappedAction(event, "updated session records", "failed to update session records", "attempted to update session records", "at", false)
	case "update_login_record":
		return renderMappedAction(event, "updated login records", "failed to update login records", "attempted to update login records", "at", false)
	case "delete":
		return renderMappedAction(event, "deleted a file", "failed to delete a file", "attempted to delete a file", "at", false)
	case "rename":
		return renderRenameMessage(event)
	case "change_mac_policy":
		return renderMappedAction(event, "changed mandatory access control policy", "failed to change mandatory access control policy", "attempted to change mandatory access control policy", "at", false)
	case "load_kernel_module":
		return renderMappedAction(event, "loaded a kernel module", "failed to load a kernel module", "attempted to load a kernel module", "from", true)
	case "unload_kernel_module":
		return renderMappedAction(event, "unloaded a kernel module", "failed to unload a kernel module", "attempted to unload a kernel module", "from", true)
	case "query_kernel_module":
		return renderMappedAction(event, "queried kernel modules", "failed to query kernel modules", "attempted to query kernel modules", "at", true)
	case "change_audit_configuration":
		return renderMappedAction(event, "changed audit configuration", "failed to change audit configuration", "attempted to change audit configuration", "at", false)
	default:
		return renderProcessMessage(event)
	}
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

	actor := renderedActor(event)
	var builder strings.Builder
	builder.WriteString(actor)
	if event.Event.Success == nil {
		builder.WriteString(" attempted to execute ")
	} else if !*event.Event.Success {
		builder.WriteString(" failed to execute ")
	} else {
		builder.WriteString(" executed ")
	}
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

func renderMappedAction(event CanonicalEvent, successText, failureText, unknownText, pathPreposition string, includeSyscall bool) (string, bool) {
	text := unknownText
	if event.Event.Success != nil && *event.Event.Success {
		text = successText
	} else if event.Event.Success != nil {
		text = failureText
	}
	var builder strings.Builder
	builder.WriteString(renderedActor(event))
	builder.WriteByte(' ')
	builder.WriteString(text)
	if targets := renderedTargets(event.Paths); targets != "" {
		builder.WriteByte(' ')
		builder.WriteString(pathPreposition)
		builder.WriteByte(' ')
		builder.WriteString(targets)
	}
	if includeSyscall && event.Process != nil && event.Process.Syscall != "" {
		builder.WriteString(" using ")
		builder.WriteString(event.Process.Syscall)
	}
	return builder.String(), true
}

func renderRenameMessage(event CanonicalEvent) (string, bool) {
	text := "attempted to rename a file"
	if event.Event.Success != nil && *event.Event.Success {
		text = "renamed a file"
	} else if event.Event.Success != nil {
		text = "failed to rename a file"
	}
	var source, destination string
	for _, path := range event.Paths {
		switch strings.ToUpper(path.NameType) {
		case "DELETE":
			if source == "" {
				source = path.Name
			}
		case "CREATE":
			if destination == "" {
				destination = path.Name
			}
		}
	}
	var builder strings.Builder
	builder.WriteString(renderedActor(event))
	builder.WriteByte(' ')
	builder.WriteString(text)
	if source != "" && destination != "" {
		builder.WriteString(" from ")
		builder.WriteString(renderedArgument(source))
		builder.WriteString(" to ")
		builder.WriteString(renderedArgument(destination))
	} else if targets := renderedTargets(event.Paths); targets != "" {
		builder.WriteString(" at ")
		builder.WriteString(targets)
	}
	return builder.String(), true
}

func renderedActor(event CanonicalEvent) string {
	if event.Actor != nil {
		return renderedIdentity(event.Actor.User, event.Actor.UserID)
	}
	return "A process"
}

func renderedTargets(paths []CanonicalPath) string {
	targets := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		if path.Name == "" || strings.EqualFold(path.NameType, "PARENT") {
			continue
		}
		if _, exists := seen[path.Name]; exists {
			continue
		}
		seen[path.Name] = struct{}{}
		targets = append(targets, renderedArgument(path.Name))
	}
	return strings.Join(targets, ", ")
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
