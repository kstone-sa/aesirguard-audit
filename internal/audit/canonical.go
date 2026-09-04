package audit

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// CanonicalSchemaVersion identifies the emitted canonical contract.
const CanonicalSchemaVersion = "0.2"

// CanonicalOptions supplies source identity that is not present in every
// audit record. Explicit options take precedence over the record node field.
type CanonicalOptions struct {
	Host   string
	BootID string
}

// CanonicalEvent is the SIEM-agnostic v0.2 event representation.
type CanonicalEvent struct {
	SchemaVersion string             `json:"schema_version"`
	Audit         CanonicalAudit     `json:"audit"`
	Source        *CanonicalSource   `json:"source,omitempty"`
	Event         CanonicalEventMeta `json:"event"`
	Rule          *CanonicalRule     `json:"rule,omitempty"`
	Actor         *CanonicalActor    `json:"actor,omitempty"`
	Process       *CanonicalProcess  `json:"process,omitempty"`
	Paths         []CanonicalPath    `json:"paths,omitempty"`
	Unmapped      []UnmappedRecord   `json:"unmapped,omitempty"`
}

type CanonicalAudit struct {
	ID     string  `json:"id"`
	Time   string  `json:"time,omitempty"`
	Serial *uint64 `json:"serial,omitempty"`
}

type CanonicalSource struct {
	Host   string `json:"host,omitempty"`
	BootID string `json:"boot_id,omitempty"`
}

type CanonicalEventMeta struct {
	Type        string           `json:"type"`
	RecordTypes []string         `json:"record_types"`
	RecordCount int              `json:"record_count"`
	Complete    bool             `json:"complete"`
	Completion  Completion       `json:"completion"`
	Result      *CanonicalResult `json:"result,omitempty"`
	Issues      []CanonicalIssue `json:"issues,omitempty"`
}

type CanonicalResult struct {
	Raw string `json:"raw"`
}

type CanonicalIssue struct {
	Code  string `json:"code"`
	Field string `json:"field,omitempty"`
	Value string `json:"value,omitempty"`
}

type CanonicalRule struct {
	Keys []string `json:"keys"`
}

type CanonicalActor struct {
	AUID string `json:"auid,omitempty"`
	UID  string `json:"uid,omitempty"`
	EUID string `json:"euid,omitempty"`
	GID  string `json:"gid,omitempty"`
	EGID string `json:"egid,omitempty"`
	Ses  string `json:"session,omitempty"`
}

type CanonicalProcess struct {
	PID        string   `json:"pid,omitempty"`
	PPID       string   `json:"ppid,omitempty"`
	Executable string   `json:"executable,omitempty"`
	Command    string   `json:"command,omitempty"`
	Argv       []string `json:"argv,omitempty"`
	CWD        string   `json:"cwd,omitempty"`
	TTY        string   `json:"tty,omitempty"`
	ArchRaw    string   `json:"arch_raw,omitempty"`
	SyscallRaw string   `json:"syscall_raw,omitempty"`
}

type CanonicalPath struct {
	Item     *int   `json:"item,omitempty"`
	Name     string `json:"name,omitempty"`
	NameType string `json:"name_type,omitempty"`
	Inode    string `json:"inode,omitempty"`
	Device   string `json:"device,omitempty"`
	Mode     string `json:"mode,omitempty"`
	OUID     string `json:"ouid,omitempty"`
	OGID     string `json:"ogid,omitempty"`
}

// UnmappedRecord preserves fields that the canonical v0.2 model does not yet
// understand. Values are always arrays so repeated fields remain loss-aware.
type UnmappedRecord struct {
	Type   string              `json:"type"`
	Fields map[string][]string `json:"fields"`
}

// BuildCanonicalEvent converts one assembled logical event into schema v0.2.
func BuildCanonicalEvent(assembled AssembledEvent, options CanonicalOptions) CanonicalEvent {
	event := CanonicalEvent{
		SchemaVersion: CanonicalSchemaVersion,
		Audit:         canonicalAudit(assembled.ID),
		Event: CanonicalEventMeta{
			Type:        primaryRecordType(assembled.Records),
			RecordTypes: recordTypes(assembled.Records),
			RecordCount: len(assembled.Records),
			Complete:    assembled.Complete,
			Completion:  assembled.Completion,
		},
	}

	if event.Audit.Time == "" || event.Audit.Serial == nil {
		event.Event.Issues = append(event.Event.Issues, CanonicalIssue{
			Code:  "invalid_audit_id",
			Field: "audit.id",
			Value: assembled.ID,
		})
	}

	host := options.Host
	if host == "" {
		host = firstRecordValue(assembled.Records, "node")
	}
	if host != "" || options.BootID != "" {
		event.Source = &CanonicalSource{Host: host, BootID: options.BootID}
	}

	keys := uniqueRecordValues(assembled.Records, "key")
	if len(keys) > 0 {
		event.Rule = &CanonicalRule{Keys: keys}
	}

	actor := CanonicalActor{
		AUID: firstRecordValue(assembled.Records, "auid"),
		UID:  firstRecordValue(assembled.Records, "uid"),
		EUID: firstRecordValue(assembled.Records, "euid"),
		GID:  firstRecordValue(assembled.Records, "gid"),
		EGID: firstRecordValue(assembled.Records, "egid"),
		Ses:  firstRecordValue(assembled.Records, "ses"),
	}
	if actor != (CanonicalActor{}) {
		event.Actor = &actor
	}

	process := buildCanonicalProcess(assembled.Records)
	if hasCanonicalProcess(process) {
		event.Process = &process
	}
	event.Paths = buildCanonicalPaths(assembled.Records)

	if result := firstNonemptyRecordValue(assembled.Records, "success", "res"); result != "" {
		event.Event.Result = &CanonicalResult{Raw: result}
	}
	event.Unmapped = buildUnmappedRecords(assembled.Records)
	return event
}

func canonicalAudit(id string) CanonicalAudit {
	audit := CanonicalAudit{ID: id}
	if timestamp, ok := auditTimeFromID(id); ok {
		audit.Time = timestamp.Format(time.RFC3339Nano)
	}
	colon := strings.LastIndexByte(id, ':')
	if colon < 0 || colon == len(id)-1 {
		return audit
	}
	serial, err := strconv.ParseUint(id[colon+1:], 10, 64)
	if err == nil {
		audit.Serial = &serial
	}
	return audit
}

func buildCanonicalProcess(records []Record) CanonicalProcess {
	process := CanonicalProcess{
		PID:        firstRecordValue(records, "pid"),
		PPID:       firstRecordValue(records, "ppid"),
		Executable: firstRecordValue(records, "exe"),
		CWD:        firstRecordValue(records, "cwd"),
		TTY:        firstRecordValue(records, "tty"),
		ArchRaw:    firstRecordValue(records, "arch"),
		SyscallRaw: firstRecordValue(records, "syscall"),
	}

	argv := map[int]*execArg{}
	for _, record := range records {
		if record.Type == "EXECVE" {
			collectExecArgs(argv, record.AllFields)
		}
		if record.Type == "PROCTITLE" && process.Command == "" {
			process.Command = decodeProctitle(recordValue(record, "proctitle"))
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
		process.Command = strings.Join(process.Argv, " ")
	}
	return process
}

func hasCanonicalProcess(process CanonicalProcess) bool {
	return process.PID != "" || process.PPID != "" || process.Executable != "" ||
		process.Command != "" || len(process.Argv) > 0 || process.CWD != "" ||
		process.TTY != "" || process.ArchRaw != "" || process.SyscallRaw != ""
}

type canonicalPathEntry struct {
	path        CanonicalPath
	recordIndex int
}

func buildCanonicalPaths(records []Record) []CanonicalPath {
	entries := make([]canonicalPathEntry, 0)
	for index, record := range records {
		if record.Type != "PATH" {
			continue
		}
		path := CanonicalPath{
			Name:     recordValue(record, "name"),
			NameType: recordValue(record, "nametype"),
			Inode:    recordValue(record, "inode"),
			Device:   recordValue(record, "dev"),
			Mode:     recordValue(record, "mode"),
			OUID:     recordValue(record, "ouid"),
			OGID:     recordValue(record, "ogid"),
		}
		if item, err := strconv.Atoi(recordValue(record, "item")); err == nil {
			path.Item = &item
		}
		entries = append(entries, canonicalPathEntry{path: path, recordIndex: index})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		left, right := entries[i].path.Item, entries[j].path.Item
		if (left != nil) != (right != nil) {
			return left != nil
		}
		if left != nil && *left != *right {
			return *left < *right
		}
		return entries[i].recordIndex < entries[j].recordIndex
	})
	paths := make([]CanonicalPath, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.path)
	}
	return paths
}

func recordTypes(records []Record) []string {
	seen := map[string]struct{}{}
	types := make([]string, 0)
	for _, record := range records {
		if record.Type == "" {
			continue
		}
		if _, exists := seen[record.Type]; exists {
			continue
		}
		seen[record.Type] = struct{}{}
		types = append(types, record.Type)
	}
	return types
}

func firstRecordValue(records []Record, key string) string {
	for _, record := range records {
		if value := recordValue(record, key); value != "" {
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

func buildUnmappedRecords(records []Record) []UnmappedRecord {
	result := make([]UnmappedRecord, 0)
	for _, record := range records {
		consumed := consumedFields(record.Type)
		fields := map[string][]string{}
		for _, field := range record.AllFields {
			if field.Key == "msg" && auditIDFromMessage(field.Value) != "" {
				continue
			}
			if record.Type == "EXECVE" {
				_, _, kind, isArgument := parseExecArgKey(field.Key)
				if isArgument && kind == execArgWhole && field.Quoted {
					continue
				}
			}
			if record.Type == "PATH" && field.Key == "item" {
				if _, err := strconv.Atoi(field.Value); err != nil {
					fields[field.Key] = append(fields[field.Key], field.Value)
					continue
				}
			}
			if _, exists := consumed[field.Key]; exists {
				continue
			}
			fields[field.Key] = append(fields[field.Key], field.Value)
		}
		if len(fields) > 0 {
			result = append(result, UnmappedRecord{Type: record.Type, Fields: fields})
		}
	}
	return result
}

func consumedFields(recordType string) map[string]struct{} {
	fields := map[string]struct{}{
		"type": {}, "node": {}, "key": {}, "success": {}, "res": {},
		"auid": {}, "uid": {}, "euid": {}, "gid": {}, "egid": {}, "ses": {},
		"pid": {}, "ppid": {}, "exe": {}, "cwd": {}, "tty": {},
		"arch": {}, "syscall": {},
	}
	switch recordType {
	case "EXECVE":
		fields["argc"] = struct{}{}
	case "PROCTITLE":
		fields["proctitle"] = struct{}{}
	case "PATH":
		for _, key := range []string{"item", "name", "nametype", "inode", "dev", "mode", "ouid", "ogid"} {
			fields[key] = struct{}{}
		}
	}
	return fields
}
