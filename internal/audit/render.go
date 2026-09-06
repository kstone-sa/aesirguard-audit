package audit

import (
	"path"
	"strconv"
	"strings"
)

// HumanRendererVersion identifies the deterministic message template set.
const HumanRendererVersion = "4"

type actionWording struct {
	success string
	failure string
	unknown string
}

var securityActionWording = map[string]actionWording{
	"authenticate":             {"authenticated", "failed to authenticate", "attempted to authenticate"},
	"check_account":            {"validated", "failed to validate", "attempted to validate"},
	"login":                    {"logged in", "failed to log in", "attempted to log in"},
	"logout":                   {"logged out", "failed to log out", "attempted to log out"},
	"start_session":            {"started a session", "failed to start a session", "attempted to start a session"},
	"end_session":              {"ended a session", "failed to end a session", "attempted to end a session"},
	"acquire_credentials":      {"acquired credentials", "failed to acquire credentials", "attempted to acquire credentials"},
	"dispose_credentials":      {"disposed of credentials", "failed to dispose of credentials", "attempted to dispose of credentials"},
	"refresh_credentials":      {"refreshed credentials", "failed to refresh credentials", "attempted to refresh credentials"},
	"change_credentials":       {"changed credentials", "failed to change credentials", "attempted to change credentials"},
	"change_group_credentials": {"changed group credentials", "failed to change group credentials", "attempted to change group credentials"},
	"modify_user":              {"modified a user", "failed to modify a user", "attempted to modify a user"},
	"modify_group":             {"modified a group", "failed to modify a group", "attempted to modify a group"},
	"create_user":              {"created a user", "failed to create a user", "attempted to create a user"},
	"delete_user":              {"deleted a user", "failed to delete a user", "attempted to delete a user"},
	"create_group":             {"created a group", "failed to create a group", "attempted to create a group"},
	"delete_group":             {"deleted a group", "failed to delete a group", "attempted to delete a group"},
	"lock_account":             {"locked an account", "failed to lock an account", "attempted to lock an account"},
	"unlock_account":           {"unlocked an account", "failed to unlock an account", "attempted to unlock an account"},
	"authentication_error":     {"reported an authentication error", "reported an authentication error", "reported an authentication error"},
	"boot":                     {"booted the system", "failed to boot the system", "attempted to boot the system"},
	"shutdown":                 {"shut down the system", "failed to shut down the system", "attempted to shut down the system"},
	"change_runlevel":          {"changed the system runlevel", "failed to change the system runlevel", "attempted to change the system runlevel"},
	"start_service":            {"started a service", "failed to start a service", "attempted to start a service"},
	"stop_service":             {"stopped a service", "failed to stop a service", "attempted to stop a service"},
	"update_software":          {"updated software", "failed to update software", "attempted to update software"},
	"start_audit_daemon":       {"started the audit daemon", "failed to start the audit daemon", "attempted to start the audit daemon"},
	"stop_audit_daemon":        {"stopped the audit daemon", "failed to stop the audit daemon", "attempted to stop the audit daemon"},
	"abort_audit_daemon":       {"aborted the audit daemon", "the audit daemon aborted", "the audit daemon was aborted"},
	"audit_daemon_error":       {"reported an audit daemon error", "reported an audit daemon error", "reported an audit daemon error"},
	"configure_audit_daemon":   {"configured the audit daemon", "failed to configure the audit daemon", "attempted to configure the audit daemon"},
	"rotate_audit_log":         {"rotated the audit log", "failed to rotate the audit log", "attempted to rotate the audit log"},
	"resume_audit_logging":     {"resumed audit logging", "failed to resume audit logging", "attempted to resume audit logging"},
	"change_audit_feature":     {"changed an audit feature", "failed to change an audit feature", "attempted to change an audit feature"},
	"policy_error":             {"reported an access-control policy error", "reported an access-control policy error", "reported an access-control policy error"},
	"terminate_by_policy":      {"was terminated by access-control policy", "could not be terminated by access-control policy", "was selected for termination by access-control policy"},
	"change_policy_status":     {"changed access-control policy status", "failed to change access-control policy status", "attempted to change access-control policy status"},
	"load_mac_policy":          {"loaded mandatory access-control policy", "failed to load mandatory access-control policy", "attempted to load mandatory access-control policy"},
	"block_syscall":            {"blocked a system call", "failed to block a system call", "attempted to block a system call"},
	"bpf_operation":            {"performed a BPF operation", "failed to perform a BPF operation", "attempted a BPF operation"},
	"change_capabilities":      {"changed process capabilities", "failed to change process capabilities", "attempted to change process capabilities"},
	"apply_file_capabilities":  {"applied file capabilities", "failed to apply file capabilities", "attempted to apply file capabilities"},
	"kernel_module_operation":  {"performed a kernel module operation", "failed to perform a kernel module operation", "attempted a kernel module operation"},
	"detect_anomaly":           {"reported a security anomaly", "reported a security anomaly", "reported a security anomaly"},
	"check_integrity":          {"reported an integrity event", "reported an integrity failure", "reported an integrity event"},
}

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
	case "enforce_access_control":
		return renderAccessControlMessage(event)
	default:
		if wording, ok := securityActionWording[event.Event.Action]; ok {
			return renderSecurityFamilyMessage(event, wording), true
		}
		return renderProcessMessage(event)
	}
}

func renderSecurityFamilyMessage(event CanonicalEvent, wording actionWording) string {
	phrase := wording.unknown
	if event.Event.Success != nil && *event.Event.Success {
		phrase = wording.success
	} else if event.Event.Success != nil {
		phrase = wording.failure
	}
	var builder strings.Builder
	builder.WriteString(renderedActor(event))
	builder.WriteByte(' ')
	builder.WriteString(phrase)
	appendRenderedTarget(&builder, event)
	appendRenderedOrigin(&builder, event)
	if event.Event.OriginalAction != "" && (event.Event.Category == "authentication" || event.Event.Category == "identity") {
		builder.WriteString(" during ")
		builder.WriteString(renderedArgument(event.Event.OriginalAction))
	}
	return builder.String()
}

func renderAccessControlMessage(event CanonicalEvent) (string, bool) {
	decision := "triggered an access-control decision"
	if event.Security != nil {
		switch strings.ToLower(event.Security.Decision) {
		case "denied", "deny":
			decision = "was denied access by mandatory access-control policy"
			if event.Security.Permissive != nil && *event.Security.Permissive {
				decision = "triggered a policy denial that was not enforced in permissive mode"
			}
		case "allowed", "allow", "granted":
			decision = "was allowed access by mandatory access-control policy"
		}
	}
	var builder strings.Builder
	builder.WriteString(renderedActor(event))
	builder.WriteByte(' ')
	builder.WriteString(decision)
	if event.Security != nil && len(event.Security.Permissions) > 0 {
		builder.WriteString(" for ")
		builder.WriteString(strings.Join(event.Security.Permissions, ", "))
	}
	appendRenderedTarget(&builder, event)
	return builder.String(), true
}

func appendRenderedTarget(builder *strings.Builder, event CanonicalEvent) {
	if event.Target == nil {
		if targets := renderedTargets(event.Paths); targets != "" {
			builder.WriteString(" on ")
			builder.WriteString(targets)
		}
		return
	}
	if event.Target.User != "" || event.Target.UserID != "" {
		builder.WriteString(" for account ")
		builder.WriteString(renderedIdentity(event.Target.User, event.Target.UserID))
	}
	if event.Target.Service != "" {
		builder.WriteString(" ")
		builder.WriteString(renderedArgument(event.Target.Service))
	}
	if event.Target.Name != "" {
		builder.WriteString(" on ")
		builder.WriteString(renderedArgument(event.Target.Name))
	}
}

func appendRenderedOrigin(builder *strings.Builder, event CanonicalEvent) {
	if event.Origin == nil {
		return
	}
	remote := event.Origin.Address
	if remote == "" {
		remote = event.Origin.Host
	}
	if remote != "" {
		builder.WriteString(" from ")
		builder.WriteString(renderedArgument(remote))
	}
	if event.Origin.Terminal != "" {
		builder.WriteString(" via ")
		builder.WriteString(renderedArgument(event.Origin.Terminal))
	}
}

func renderProcessMessage(event CanonicalEvent) (string, bool) {
	if event.Process == nil {
		return "", false
	}
	process := event.Process
	if process.Syscall != "execve" && process.Syscall != "execveat" && process.ArgvSource != "execve" && event.Event.Action != "execute" {
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
