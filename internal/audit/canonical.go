package audit

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	mappingdata "github.com/kstone-sa/audit2json/data"
)

// CanonicalSchemaVersion identifies the emitted canonical contract.
const CanonicalSchemaVersion = "0.3"

// CanonicalOptions supplies optional source identity. Source metadata is
// emitted only when explicitly configured by the caller.
type CanonicalOptions struct {
	Host string
}

// CanonicalEvent is the SIEM-agnostic v0.3 event representation.
type CanonicalEvent struct {
	SchemaVersion string             `json:"schema_version"`
	Audit         CanonicalAudit     `json:"audit"`
	Source        *CanonicalSource   `json:"source,omitempty"`
	Event         CanonicalEventMeta `json:"event"`
	Rule          *CanonicalRule     `json:"rule,omitempty"`
	Actor         *CanonicalActor    `json:"actor,omitempty"`
	Process       *CanonicalProcess  `json:"process,omitempty"`
	Target        *CanonicalTarget   `json:"target,omitempty"`
	Origin        *CanonicalOrigin   `json:"origin,omitempty"`
	Security      *CanonicalSecurity `json:"security,omitempty"`
	Paths         []CanonicalPath    `json:"paths,omitempty"`
	Message       string             `json:"message,omitempty"`
	Renderer      string             `json:"renderer_version,omitempty"`
}

type CanonicalAudit struct {
	ID   string `json:"id,omitempty"`
	Time string `json:"time,omitempty"`
	Raw  string `json:"raw,omitempty"`
}

// BuildParseFailureEvent preserves one malformed physical input line in the
// event stream so a durable checkpoint can advance without silent data loss.
func BuildParseFailureEvent(line string, parseErr error, options CanonicalOptions) CanonicalEvent {
	event := CanonicalEvent{
		SchemaVersion: CanonicalSchemaVersion,
		Audit:         CanonicalAudit{Raw: line},
		Event: CanonicalEventMeta{
			Type:     "PARSE_ERROR",
			Category: "conversion",
			Action:   "parse_failure",
			Issues: []CanonicalIssue{{
				Code:  "parse_failure",
				Value: parseErr.Error(),
			}},
		},
	}
	if id := auditIDFromMessage(line); id != "" {
		event.Audit = canonicalAudit(id)
		event.Audit.Raw = line
	}
	if options.Host != "" {
		event.Source = &CanonicalSource{Host: options.Host}
	}
	return event
}

type CanonicalSource struct {
	Host string `json:"host"`
}

type CanonicalEventMeta struct {
	Type           string              `json:"type"`
	Category       string              `json:"category,omitempty"`
	Action         string              `json:"action,omitempty"`
	OriginalAction string              `json:"original_action,omitempty"`
	Success        *bool               `json:"success,omitempty"`
	Integrity      *CanonicalIntegrity `json:"integrity,omitempty"`
	Issues         []CanonicalIssue    `json:"issues,omitempty"`
}

type CanonicalIntegrity struct {
	State  string     `json:"state"`
	Reason Completion `json:"reason"`
}

type CanonicalIssue struct {
	Code       string `json:"code"`
	RecordType string `json:"record_type,omitempty"`
	Field      string `json:"field,omitempty"`
	Value      string `json:"value,omitempty"`
}

type CanonicalRule struct {
	Keys []string `json:"keys"`
}

type CanonicalActor struct {
	User   string `json:"user,omitempty"`
	UserID string `json:"user_id,omitempty"`
}

type CanonicalTarget struct {
	User    string `json:"user,omitempty"`
	UserID  string `json:"user_id,omitempty"`
	Service string `json:"service,omitempty"`
	Name    string `json:"name,omitempty"`
}

type CanonicalOrigin struct {
	Address  string `json:"address,omitempty"`
	Host     string `json:"host,omitempty"`
	Terminal string `json:"terminal,omitempty"`
}

type CanonicalSecurity struct {
	Decision       string   `json:"decision,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
	SubjectContext string   `json:"subject_context,omitempty"`
	TargetContext  string   `json:"target_context,omitempty"`
	TargetClass    string   `json:"target_class,omitempty"`
	Profile        string   `json:"profile,omitempty"`
	Permissive     *bool    `json:"permissive,omitempty"`
}

type CanonicalProcess struct {
	PID              string   `json:"pid,omitempty"`
	PPID             string   `json:"ppid,omitempty"`
	User             string   `json:"user,omitempty"`
	UserID           string   `json:"user_id,omitempty"`
	RealUser         string   `json:"real_user,omitempty"`
	RealUserID       string   `json:"real_user_id,omitempty"`
	Name             string   `json:"name,omitempty"`
	Executable       string   `json:"executable,omitempty"`
	Argv             []string `json:"argv,omitempty"`
	CWD              string   `json:"cwd,omitempty"`
	TTY              string   `json:"tty,omitempty"`
	ArchitectureCode string   `json:"architecture_code,omitempty"`
	Syscall          string   `json:"syscall,omitempty"`
	SyscallNumber    string   `json:"syscall_number,omitempty"`
	ReturnValue      string   `json:"return_value,omitempty"`
}

type CanonicalPath struct {
	Name         string                     `json:"name,omitempty"`
	NameType     string                     `json:"name_type,omitempty"`
	Owner        string                     `json:"owner,omitempty"`
	OwnerID      string                     `json:"owner_id,omitempty"`
	Group        string                     `json:"group,omitempty"`
	GroupID      string                     `json:"group_id,omitempty"`
	Capabilities *CanonicalFileCapabilities `json:"capabilities,omitempty"`
}

type CanonicalFileCapabilities struct {
	Permitted   []string `json:"permitted,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
	Effective   bool     `json:"effective,omitempty"`
}

var linuxCapabilityNames = mustLinuxCapabilityNames()

type sourceIdentity struct {
	name string
	id   string
}

// BuildCanonicalEvent converts one assembled logical event into schema v0.3.
func BuildCanonicalEvent(assembled AssembledEvent, options CanonicalOptions) CanonicalEvent {
	event := CanonicalEvent{
		SchemaVersion: CanonicalSchemaVersion,
		Audit:         canonicalAudit(assembled.ID),
		Event: CanonicalEventMeta{
			Type: primaryRecordType(assembled.Records),
		},
	}
	if recordType := preferredSecurityRecordType(assembled.Records); recordType != "" {
		event.Event.Type = recordType
	}

	if event.Audit.Time == "" {
		event.Event.Issues = append(event.Event.Issues, CanonicalIssue{
			Code:  "invalid_audit_id",
			Field: "audit.id",
			Value: assembled.ID,
		})
	}
	if !assembled.Complete {
		event.Event.Integrity = &CanonicalIntegrity{
			State:  "incomplete",
			Reason: assembled.Completion,
		}
	}
	if success, ok := canonicalSuccess(assembled.Records); ok {
		event.Event.Success = &success
	} else if raw := firstNonemptySemanticRecordValue(assembled.Records, "success", "res"); raw != "" {
		event.Event.Issues = append(event.Event.Issues, CanonicalIssue{
			Code:  "unknown_result",
			Field: "event.success",
			Value: raw,
		})
	}
	for _, recordType := range unsupportedRecordTypes(assembled.Records) {
		event.Event.Issues = append(event.Event.Issues, CanonicalIssue{
			Code:       "unsupported_record",
			RecordType: recordType,
		})
	}
	for _, record := range assembled.Records {
		if record.EmbeddedParseError != "" {
			event.Event.Issues = append(event.Event.Issues, CanonicalIssue{
				Code:       "embedded_parse_failure",
				RecordType: record.Type,
				Field:      "msg",
				Value:      record.EmbeddedParseError,
			})
		}
	}

	if options.Host != "" {
		event.Source = &CanonicalSource{Host: options.Host}
	}

	keys := uniqueRecordValues(assembled.Records, "key")
	if len(keys) > 0 {
		event.Rule = &CanonicalRule{Keys: keys}
	}

	login := recordIdentity(assembled.Records, "AUID", "auid")
	real := recordIdentity(assembled.Records, "UID", "uid")
	effective := recordIdentity(assembled.Records, "EUID", "euid")
	if identityEmpty(effective) {
		effective = real
	}
	if !identityEmpty(login) {
		actor := CanonicalActor{}
		setActorIdentity(&actor, login)
		event.Actor = &actor
	}

	process := buildCanonicalProcess(assembled.Records)
	if !identityEmpty(effective) && !sameIdentity(effective, login) {
		setProcessIdentity(&process, effective)
	}
	if !identityEmpty(real) && !sameIdentity(real, login) && !sameIdentity(real, effective) {
		setRealProcessIdentity(&process, real)
	}
	if hasCanonicalProcess(process) {
		event.Process = &process
	}
	event.Event.OriginalAction = meaningfulAuditValue(firstNonemptySemanticRecordValue(assembled.Records, "op", "operation"))
	event.Target = buildCanonicalTarget(assembled.Records, event.Event.Type)
	event.Origin = buildCanonicalOrigin(assembled.Records)
	event.Security = buildCanonicalSecurity(assembled.Records, event.Event.Type)
	var pathIssues []CanonicalIssue
	event.Paths, pathIssues = buildCanonicalPaths(assembled.Records)
	event.Event.Issues = append(event.Event.Issues, pathIssues...)
	classifyCanonicalEvent(&event)
	return event
}

func canonicalAudit(id string) CanonicalAudit {
	audit := CanonicalAudit{ID: id}
	if timestamp, ok := auditTimeFromID(id); ok {
		audit.Time = timestamp.Format(time.RFC3339Nano)
	}
	return audit
}

func canonicalSuccess(records []Record) (bool, bool) {
	switch strings.ToLower(firstNonemptySemanticRecordValue(records, "success", "res")) {
	case "yes", "success", "succeeded":
		return true, true
	case "no", "failed", "failure":
		return false, true
	default:
		return false, false
	}
}

func buildCanonicalProcess(records []Record) CanonicalProcess {
	process := CanonicalProcess{
		PID:         firstSemanticRecordValue(records, "pid"),
		PPID:        firstSemanticRecordValue(records, "ppid"),
		Name:        firstSemanticRecordValue(records, "comm"),
		Executable:  firstSemanticRecordValue(records, "exe"),
		CWD:         firstSemanticRecordValue(records, "cwd"),
		TTY:         firstSemanticRecordValue(records, "tty"),
		ReturnValue: firstSemanticRecordValue(records, "exit"),
	}
	if name := interpretedValue(records, "SYSCALL"); name != "" {
		process.Syscall = name
	} else if number := firstRecordValue(records, "syscall"); number != "" {
		process.SyscallNumber = number
		process.ArchitectureCode = firstRecordValue(records, "arch")
	}

	argv := map[int]*execArg{}
	for _, record := range records {
		if record.Type == "EXECVE" {
			collectExecArgs(argv, record.AllFields)
		}
	}
	if len(argv) > 0 {
		indexes := make([]int, 0, len(argv))
		for index := range argv {
			indexes = append(indexes, index)
		}
		sort.Ints(indexes)
		for _, index := range indexes {
			if value, ok := argv[index].value(); ok {
				process.Argv = append(process.Argv, value)
			}
		}
	}
	if len(process.Argv) == 0 {
		for _, record := range records {
			if record.Type != "PROCTITLE" {
				continue
			}
			if decoded, ok := decodeProctitleArgs(recordValue(record, "proctitle")); ok {
				process.Argv = decoded
				break
			}
		}
	}
	return process
}

func buildCanonicalTarget(records []Record, primaryType string) *CanonicalTarget {
	target := CanonicalTarget{}
	account := meaningfulAuditValue(firstSemanticRecordValue(records, "acct"))
	if account != "" {
		if isDecimal(account) {
			target.UserID = account
		} else {
			target.User = account
		}
	}
	target.Service = meaningfulAuditValue(firstNonemptySemanticRecordValue(records, "unit", "service"))
	if primaryType != "PATH" {
		target.Name = meaningfulAuditValue(firstSemanticRecordValueExcludingType(records, "name", "PATH"))
	}
	if target.User == "" && target.UserID == "" && target.Service == "" && target.Name == "" {
		return nil
	}
	return &target
}

func buildCanonicalOrigin(records []Record) *CanonicalOrigin {
	origin := CanonicalOrigin{
		Address:  meaningfulAuditValue(firstNonemptySemanticRecordValue(records, "addr", "ip")),
		Host:     meaningfulAuditValue(firstNonemptySemanticRecordValue(records, "hostname", "host")),
		Terminal: meaningfulAuditValue(firstSemanticRecordValue(records, "terminal")),
	}
	if origin.Address == "" && origin.Host == "" && origin.Terminal == "" {
		return nil
	}
	return &origin
}

func buildCanonicalSecurity(records []Record, recordType string) *CanonicalSecurity {
	family, mapped := securityEventFamilyForType(recordType)
	if !mapped || (family.Category != "access_control" && family.Category != "security" && family.Category != "integrity") {
		return nil
	}
	security := CanonicalSecurity{
		Decision:       strings.ToLower(meaningfulAuditValue(firstNonemptySemanticRecordValue(records, "decision", "apparmor"))),
		SubjectContext: meaningfulAuditValue(firstNonemptySemanticRecordValue(records, "scontext", "subj")),
		TargetContext:  meaningfulAuditValue(firstSemanticRecordValue(records, "tcontext")),
		TargetClass:    meaningfulAuditValue(firstSemanticRecordValue(records, "tclass")),
		Profile:        meaningfulAuditValue(firstSemanticRecordValue(records, "profile")),
	}
	if permissions := meaningfulAuditValue(firstNonemptySemanticRecordValue(records, "permissions", "requested_mask")); permissions != "" {
		security.Permissions = strings.Fields(strings.Trim(permissions, `"{} `))
	}
	if permissive := firstSemanticRecordValue(records, "permissive"); permissive != "" {
		value := permissive == "1" || strings.EqualFold(permissive, "yes") || strings.EqualFold(permissive, "true")
		if value || permissive == "0" || strings.EqualFold(permissive, "no") || strings.EqualFold(permissive, "false") {
			security.Permissive = &value
		}
	}
	if security.Decision == "" && len(security.Permissions) == 0 && security.SubjectContext == "" &&
		security.TargetContext == "" && security.TargetClass == "" && security.Profile == "" && security.Permissive == nil {
		return nil
	}
	return &security
}

func meaningfulAuditValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "?", "unset", "(none)", "unknown":
		return ""
	default:
		return value
	}
}

func hasCanonicalProcess(process CanonicalProcess) bool {
	return process.PID != "" || process.PPID != "" || process.User != "" ||
		process.UserID != "" || process.RealUser != "" || process.RealUserID != "" ||
		process.Name != "" || process.Executable != "" || len(process.Argv) > 0 ||
		process.CWD != "" || process.TTY != "" || process.ArchitectureCode != "" ||
		process.Syscall != "" ||
		process.SyscallNumber != "" || process.ReturnValue != ""
}

type canonicalPathEntry struct {
	path        CanonicalPath
	item        int
	hasItem     bool
	recordIndex int
}

func buildCanonicalPaths(records []Record) ([]CanonicalPath, []CanonicalIssue) {
	entries := make([]canonicalPathEntry, 0)
	issues := make([]CanonicalIssue, 0)
	for index, record := range records {
		if record.Type != "PATH" {
			continue
		}
		owner := singleRecordIdentity(record, "OUID", "ouid")
		group := singleRecordIdentity(record, "OGID", "ogid")
		capabilities, capabilityIssues := fileCapabilities(record)
		issues = append(issues, capabilityIssues...)
		path := CanonicalPath{
			Name:         recordValue(record, "name"),
			NameType:     recordValue(record, "nametype"),
			Capabilities: capabilities,
		}
		setPathOwner(&path, owner)
		setPathGroup(&path, group)
		entry := canonicalPathEntry{path: path, recordIndex: index}
		if item, err := strconv.Atoi(recordValue(record, "item")); err == nil {
			entry.item = item
			entry.hasItem = true
		}
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].hasItem != entries[j].hasItem {
			return entries[i].hasItem
		}
		if entries[i].hasItem && entries[i].item != entries[j].item {
			return entries[i].item < entries[j].item
		}
		return entries[i].recordIndex < entries[j].recordIndex
	})
	paths := make([]CanonicalPath, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.path)
	}
	return paths, issues
}

func fileCapabilities(record Record) (*CanonicalFileCapabilities, []CanonicalIssue) {
	permitted, permittedIssue := decodeCapabilityMask(recordValue(record, "cap_fp"), "paths.capabilities.permitted")
	inheritable, inheritableIssue := decodeCapabilityMask(recordValue(record, "cap_fi"), "paths.capabilities.inheritable")
	capabilities := CanonicalFileCapabilities{
		Permitted:   permitted,
		Inheritable: inheritable,
	}
	issues := append(permittedIssue, inheritableIssue...)
	switch strings.ToLower(recordValue(record, "cap_fe")) {
	case "", "none", "0":
	case "1":
		capabilities.Effective = true
	default:
		issues = append(issues, CanonicalIssue{
			Code:       "unknown_capability_effective",
			RecordType: record.Type,
			Field:      "paths.capabilities.effective",
			Value:      recordValue(record, "cap_fe"),
		})
	}
	if len(capabilities.Permitted) == 0 && len(capabilities.Inheritable) == 0 && !capabilities.Effective {
		return nil, issues
	}
	return &capabilities, issues
}

func decodeCapabilityMask(value, field string) ([]string, []CanonicalIssue) {
	trimmed := strings.TrimPrefix(strings.ToLower(value), "0x")
	if trimmed == "" || trimmed == "none" {
		return nil, nil
	}
	mask, err := strconv.ParseUint(trimmed, 16, 64)
	if err != nil {
		return nil, []CanonicalIssue{{
			Code:       "invalid_capability_mask",
			RecordType: "PATH",
			Field:      field,
			Value:      value,
		}}
	}
	if mask == 0 {
		return nil, nil
	}

	names := make([]string, 0)
	remaining := mask
	for bit, name := range linuxCapabilityNames {
		bitMask := uint64(1) << bit
		if mask&bitMask == 0 {
			continue
		}
		names = append(names, name)
		remaining &^= bitMask
	}
	if remaining != 0 {
		return names, []CanonicalIssue{{
			Code:       "unknown_capability_bits",
			RecordType: "PATH",
			Field:      field,
			Value:      value,
		}}
	}
	return names, nil
}

func mustLinuxCapabilityNames() []string {
	var names []string
	if err := json.Unmarshal([]byte(mappingdata.LinuxCapabilityNamesJSON()), &names); err != nil {
		panic("invalid embedded Linux capability mapping: " + err.Error())
	}
	if len(names) == 0 || len(names) > 64 {
		panic("invalid embedded Linux capability mapping length")
	}
	return names
}

func recordIdentity(records []Record, nameKey, idKey string) sourceIdentity {
	return sourceIdentity{
		name: interpretedValue(records, nameKey),
		id:   firstRecordValue(records, idKey),
	}
}

func singleRecordIdentity(record Record, nameKey, idKey string) sourceIdentity {
	return sourceIdentity{
		name: interpretedRecordValue(record, nameKey),
		id:   recordValue(record, idKey),
	}
}

func interpretedValue(records []Record, key string) string {
	for _, record := range records {
		if value := interpretedRecordValue(record, key); value != "" {
			return value
		}
	}
	return ""
}

func interpretedRecordValue(record Record, key string) string {
	value := recordValue(record, key)
	if value == "" || strings.EqualFold(value, "unset") || isDecimal(value) {
		return ""
	}
	return value
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func identityEmpty(identity sourceIdentity) bool {
	return identity.name == "" && identity.id == ""
}

func sameIdentity(left, right sourceIdentity) bool {
	if identityEmpty(left) || identityEmpty(right) {
		return false
	}
	if left.id != "" && right.id != "" {
		return left.id == right.id
	}
	return left.name != "" && right.name != "" && left.name == right.name
}

func setActorIdentity(actor *CanonicalActor, identity sourceIdentity) {
	if identity.name != "" {
		actor.User = identity.name
	} else {
		actor.UserID = identity.id
	}
}

func setProcessIdentity(process *CanonicalProcess, identity sourceIdentity) {
	if identity.name != "" {
		process.User = identity.name
	} else {
		process.UserID = identity.id
	}
}

func setRealProcessIdentity(process *CanonicalProcess, identity sourceIdentity) {
	if identity.name != "" {
		process.RealUser = identity.name
	} else {
		process.RealUserID = identity.id
	}
}

func setPathOwner(path *CanonicalPath, identity sourceIdentity) {
	if identity.name != "" {
		path.Owner = identity.name
	} else {
		path.OwnerID = identity.id
	}
}

func setPathGroup(path *CanonicalPath, identity sourceIdentity) {
	if identity.name != "" {
		path.Group = identity.name
	} else {
		path.GroupID = identity.id
	}
}

func firstRecordValue(records []Record, key string) string {
	for _, record := range records {
		if value := recordValue(record, key); value != "" {
			return value
		}
	}
	return ""
}

func firstSemanticRecordValue(records []Record, key string) string {
	for _, record := range records {
		if value := semanticRecordValue(record, key); value != "" {
			return value
		}
	}
	return ""
}

func firstSemanticRecordValueExcludingType(records []Record, key, excludedType string) string {
	for _, record := range records {
		if record.Type == excludedType {
			continue
		}
		if value := semanticRecordValue(record, key); value != "" {
			return value
		}
	}
	return ""
}

func firstNonemptyRecordValue(records []Record, keys ...string) string {
	for _, key := range keys {
		if value := firstRecordValue(records, key); value != "" {
			return value
		}
	}
	return ""
}

func firstNonemptySemanticRecordValue(records []Record, keys ...string) string {
	for _, key := range keys {
		if value := firstSemanticRecordValue(records, key); value != "" {
			return value
		}
	}
	return ""
}

func uniqueRecordValues(records []Record, key string) []string {
	values := make([]string, 0)
	for _, record := range records {
		values = append(values, record.Values[key]...)
	}
	return uniqueNonempty(values)
}

func uniqueNonempty(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func unsupportedRecordTypes(records []Record) []string {
	known := map[string]struct{}{
		"SYSCALL": {}, "EXECVE": {}, "CWD": {}, "PATH": {},
		"PROCTITLE": {}, "EOE": {},
	}
	result := make([]string, 0)
	seen := map[string]struct{}{}
	for _, record := range records {
		_, mapped := securityEventFamilyForType(record.Type)
		if _, supported := known[record.Type]; supported || mapped {
			continue
		}
		if _, exists := seen[record.Type]; exists {
			continue
		}
		seen[record.Type] = struct{}{}
		result = append(result, record.Type)
	}
	return result
}
