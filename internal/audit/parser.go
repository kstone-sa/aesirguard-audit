package audit

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Field is one parsed key/value pair. Fields remain ordered so repeated keys
// and their quoting state are not lost.
type Field struct {
	Key    string
	Value  string
	Quoted bool
}

// Record is one raw auditd record parsed into key/value fields.
type Record struct {
	Type      string
	ID        string
	Fields    map[string]string
	Values    map[string][]string
	AllFields []Field
}

// Event is the compact JSON representation emitted by audit2json.
type Event struct {
	ID    string   `json:"id"`
	Key   string   `json:"key,omitempty"`
	Type  string   `json:"type,omitempty"`
	Res   string   `json:"res,omitempty"`
	AUID  string   `json:"auid,omitempty"`
	UID   string   `json:"uid,omitempty"`
	EUID  string   `json:"euid,omitempty"`
	GID   string   `json:"gid,omitempty"`
	EGID  string   `json:"egid,omitempty"`
	Ses   string   `json:"ses,omitempty"`
	PID   string   `json:"pid,omitempty"`
	PPID  string   `json:"ppid,omitempty"`
	Arch  string   `json:"arch,omitempty"`
	SC    string   `json:"sc,omitempty"`
	Exe   string   `json:"exe,omitempty"`
	Cmd   string   `json:"cmd,omitempty"`
	CWD   string   `json:"cwd,omitempty"`
	Path  string   `json:"path,omitempty"`
	Paths []string `json:"paths,omitempty"`
	TTY   string   `json:"tty,omitempty"`
}

// ParseRecord parses one auditd line without depending on libauparse.
func ParseRecord(line string) (Record, error) {
	allFields, fields, values, err := parseFields(line)
	if err != nil {
		return Record{}, err
	}

	r := Record{
		Fields:    fields,
		Values:    values,
		AllFields: allFields,
		Type:      firstValue(values, "type"),
	}
	for _, msg := range values["msg"] {
		if id := auditIDFromMessage(msg); id != "" {
			r.ID = id
			break
		}
	}
	if r.ID == "" {
		return Record{}, fmt.Errorf("audit id not found")
	}
	if r.Type == "" {
		return Record{}, fmt.Errorf("record type not found for audit id %s", r.ID)
	}
	return r, nil
}

// BuildEvent merges all records sharing one audit ID into one compact event.
func BuildEvent(records []Record) Event {
	e := Event{}
	argv := map[int]*execArg{}
	var paths []pathEntry

	for recordIndex, r := range records {
		if e.ID == "" {
			e.ID = r.ID
		}
		set := func(dst *string, key string) {
			if *dst == "" {
				*dst = recordValue(r, key)
			}
		}

		set(&e.Key, "key")
		set(&e.AUID, "auid")
		set(&e.UID, "uid")
		set(&e.EUID, "euid")
		set(&e.GID, "gid")
		set(&e.EGID, "egid")
		set(&e.Ses, "ses")
		set(&e.PID, "pid")
		set(&e.PPID, "ppid")
		set(&e.Arch, "arch")
		set(&e.SC, "syscall")
		set(&e.Exe, "exe")
		set(&e.CWD, "cwd")
		set(&e.TTY, "tty")

		if e.Res == "" {
			if v := recordValue(r, "success"); v != "" {
				e.Res = v
			} else if v := recordValue(r, "res"); v != "" {
				e.Res = v
			}
		}

		switch r.Type {
		case "EXECVE":
			collectExecArgs(argv, r.AllFields)
		case "PROCTITLE":
			if e.Cmd == "" {
				e.Cmd = decodeProctitle(recordValue(r, "proctitle"))
			}
		case "PATH":
			if name := recordValue(r, "name"); name != "" {
				entry := pathEntry{name: name, recordIndex: recordIndex}
				if item, err := strconv.Atoi(recordValue(r, "item")); err == nil {
					entry.item = item
					entry.hasItem = true
				}
				paths = append(paths, entry)
			}
		}
	}

	if len(argv) > 0 {
		idx := make([]int, 0, len(argv))
		for n := range argv {
			idx = append(idx, n)
		}
		sort.Ints(idx)
		parts := make([]string, 0, len(idx))
		for _, n := range idx {
			if value, ok := argv[n].value(); ok {
				parts = append(parts, value)
			}
		}
		e.Cmd = strings.Join(parts, " ")
	}

	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].hasItem != paths[j].hasItem {
			return paths[i].hasItem
		}
		if paths[i].hasItem && paths[i].item != paths[j].item {
			return paths[i].item < paths[j].item
		}
		return paths[i].recordIndex < paths[j].recordIndex
	})
	pathNames := make([]string, 0, len(paths))
	for _, path := range paths {
		pathNames = append(pathNames, path.name)
	}
	pathNames = unique(pathNames)
	if len(pathNames) == 1 {
		e.Path = pathNames[0]
	} else if len(pathNames) > 1 {
		e.Paths = pathNames
	}
	if e.Key == "" {
		e.Type = primaryRecordType(records)
	}
	return e
}

func parseFields(line string) ([]Field, map[string]string, map[string][]string, error) {
	all := make([]Field, 0, 16)
	first := map[string]string{}
	values := map[string][]string{}

	for i := 0; i < len(line); {
		for i < len(line) && line[i] == ' ' {
			i++
		}
		if i >= len(line) {
			break
		}

		keyStart := i
		for i < len(line) && line[i] != '=' && line[i] != ' ' {
			i++
		}
		if i == keyStart {
			return nil, nil, nil, fmt.Errorf("empty field name at byte %d", i)
		}
		if i >= len(line) || line[i] != '=' {
			end := i
			for end < len(line) && line[end] != ' ' {
				end++
			}
			return nil, nil, nil, fmt.Errorf("malformed field %q at byte %d", line[keyStart:end], keyStart)
		}

		key := line[keyStart:i]
		i++
		value := ""
		quoted := false
		if i < len(line) && (line[i] == '"' || line[i] == '\'') {
			quoted = true
			quote := line[i]
			i++
			var builder strings.Builder
			closed := false
			for i < len(line) {
				if line[i] == quote {
					i++
					closed = true
					break
				}
				if line[i] == '\\' && i+1 < len(line) {
					next := line[i+1]
					if next == quote || next == '\\' {
						builder.WriteByte(next)
						i += 2
						continue
					}
				}
				builder.WriteByte(line[i])
				i++
			}
			if !closed {
				return nil, nil, nil, fmt.Errorf("unterminated quoted value for field %q", key)
			}
			value = builder.String()
		} else {
			valueStart := i
			for i < len(line) && line[i] != ' ' {
				i++
			}
			value = line[valueStart:i]
		}

		field := Field{Key: key, Value: value, Quoted: quoted}
		all = append(all, field)
		values[key] = append(values[key], value)
		if _, exists := first[key]; !exists {
			first[key] = value
		}
	}

	return all, first, values, nil
}

func auditIDFromMessage(msg string) string {
	start := strings.Index(msg, "audit(")
	if start < 0 {
		return ""
	}
	start += len("audit(")
	end := strings.IndexByte(msg[start:], ')')
	if end < 0 {
		return ""
	}
	return msg[start : start+end]
}

func firstValue(values map[string][]string, key string) string {
	for _, value := range values[key] {
		if value != "" {
			return value
		}
	}
	return ""
}

func recordValue(record Record, key string) string {
	if record.Values != nil {
		return firstValue(record.Values, key)
	}
	return record.Fields[key]
}

type execArg struct {
	whole     *Field
	fragments map[int]Field
}

func (arg *execArg) value() (string, bool) {
	if len(arg.fragments) > 0 {
		parts := make([]int, 0, len(arg.fragments))
		for part := range arg.fragments {
			parts = append(parts, part)
		}
		sort.Ints(parts)
		var builder strings.Builder
		for _, part := range parts {
			builder.WriteString(decodeExecValue(arg.fragments[part]))
		}
		return builder.String(), true
	}
	if arg.whole != nil {
		return decodeExecValue(*arg.whole), true
	}
	return "", false
}

func collectExecArgs(argv map[int]*execArg, fields []Field) {
	for _, field := range fields {
		argIndex, partIndex, kind, ok := parseExecArgKey(field.Key)
		if !ok || kind == execArgLength {
			continue
		}
		arg := argv[argIndex]
		if arg == nil {
			arg = &execArg{}
			argv[argIndex] = arg
		}
		switch kind {
		case execArgWhole:
			if arg.whole == nil {
				copy := field
				arg.whole = &copy
			}
		case execArgFragment:
			if arg.fragments == nil {
				arg.fragments = map[int]Field{}
			}
			if _, exists := arg.fragments[partIndex]; !exists {
				arg.fragments[partIndex] = field
			}
		}
	}
}

type execArgKind int

const (
	execArgWhole execArgKind = iota
	execArgLength
	execArgFragment
)

func parseExecArgKey(key string) (argIndex, partIndex int, kind execArgKind, ok bool) {
	if len(key) < 2 || key[0] != 'a' || key[1] < '0' || key[1] > '9' {
		return 0, 0, 0, false
	}
	i := 1
	for i < len(key) && key[i] >= '0' && key[i] <= '9' {
		i++
	}
	argIndex, err := strconv.Atoi(key[1:i])
	if err != nil {
		return 0, 0, 0, false
	}
	if i == len(key) {
		return argIndex, 0, execArgWhole, true
	}
	if key[i:] == "_len" {
		return argIndex, 0, execArgLength, true
	}
	if key[i] != '[' || key[len(key)-1] != ']' || i+2 > len(key) {
		return 0, 0, 0, false
	}
	partIndex, err = strconv.Atoi(key[i+1 : len(key)-1])
	if err != nil {
		return 0, 0, 0, false
	}
	return argIndex, partIndex, execArgFragment, true
}

func decodeExecValue(field Field) string {
	if field.Quoted || len(field.Value)%2 != 0 {
		return field.Value
	}
	decoded, err := hex.DecodeString(field.Value)
	if err != nil {
		return field.Value
	}
	return string(decoded)
}

func decodeProctitle(value string) string {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return value
	}
	return strings.TrimSpace(strings.ReplaceAll(string(decoded), "\x00", " "))
}

type pathEntry struct {
	name        string
	item        int
	hasItem     bool
	recordIndex int
}

func primaryRecordType(records []Record) string {
	seen := map[string]struct{}{}
	for _, record := range records {
		if record.Type != "" && record.Type != "EOE" {
			seen[record.Type] = struct{}{}
		}
	}
	if _, exists := seen["SYSCALL"]; exists {
		return "SYSCALL"
	}
	contextTypes := map[string]struct{}{
		"CWD": {}, "EXECVE": {}, "PATH": {}, "PROCTITLE": {}, "SOCKADDR": {},
	}
	primary := make([]string, 0, len(seen))
	fallback := make([]string, 0, len(seen))
	for recordType := range seen {
		fallback = append(fallback, recordType)
		if _, context := contextTypes[recordType]; !context {
			primary = append(primary, recordType)
		}
	}
	if len(primary) > 0 {
		sort.Strings(primary)
		return primary[0]
	}
	sort.Strings(fallback)
	if len(fallback) > 0 {
		return fallback[0]
	}
	return ""
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
