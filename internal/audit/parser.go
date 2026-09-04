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
	Type               string
	ID                 string
	Fields             map[string]string
	Values             map[string][]string
	AllFields          []Field
	EmbeddedFields     map[string]string
	EmbeddedValues     map[string][]string
	EmbeddedParseError string
	SourceBytes        int
	Source             SourcePosition
}

// SourcePosition identifies a complete physical source line. It is internal
// recovery metadata and is never copied into the canonical event.
type SourcePosition struct {
	Device     uint64
	Inode      uint64
	Generation uint64
	Start      int64
	End        int64
	Bytes      int
	Valid      bool
}

// ParseRecord parses one auditd line without depending on libauparse.
func ParseRecord(line string) (Record, error) {
	allFields, fields, values, err := parseFields(normalizeKnownRecordSyntax(line))
	if err != nil {
		return Record{}, err
	}

	r := Record{
		Fields:      fields,
		Values:      values,
		AllFields:   allFields,
		Type:        firstValue(values, "type"),
		SourceBytes: len(line),
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
	r.EmbeddedFields, r.EmbeddedValues, r.EmbeddedParseError = parseEmbeddedMessages(values["msg"])
	return r, nil
}

// normalizeKnownRecordSyntax converts the small amount of documented Audit
// prose surrounding otherwise structured fields. Unknown bare tokens remain
// parse errors instead of making the general field grammar permissive.
func normalizeKnownRecordSyntax(line string) string {
	boundary := strings.Index(line, "): ")
	if boundary < 0 {
		return line
	}
	prefix := line[:boundary+3]
	payload := line[boundary+3:]
	if strings.HasPrefix(payload, "user ") {
		return prefix + payload[len("user "):]
	}
	if !strings.HasPrefix(payload, "avc:") {
		return line
	}

	remainder := strings.TrimSpace(strings.TrimPrefix(payload, "avc:"))
	decisionEnd := strings.IndexByte(remainder, ' ')
	if decisionEnd <= 0 {
		return line
	}
	decision := remainder[:decisionEnd]
	remainder = strings.TrimSpace(remainder[decisionEnd+1:])
	if !strings.HasPrefix(remainder, "{") {
		return line
	}
	permissionsEnd := strings.IndexByte(remainder, '}')
	if permissionsEnd < 0 {
		return line
	}
	permissions := strings.TrimSpace(remainder[1:permissionsEnd])
	remainder = strings.TrimSpace(remainder[permissionsEnd+1:])
	remainder = strings.TrimSpace(strings.TrimPrefix(remainder, "for"))
	return prefix + "decision=" + strconv.Quote(decision) + " permissions=" + strconv.Quote(permissions) + " " + remainder
}

func parseEmbeddedMessages(messages []string) (map[string]string, map[string][]string, string) {
	first := map[string]string{}
	values := map[string][]string{}
	for _, message := range messages {
		if auditIDFromMessage(message) != "" || !strings.Contains(message, "=") {
			continue
		}
		_, parsedFirst, parsedValues, err := parseFields(message)
		if err != nil {
			return first, values, err.Error()
		}
		for key, value := range parsedFirst {
			if _, exists := first[key]; !exists {
				first[key] = value
			}
		for key, entries := range parsedValues {
			values[key] = append(values[key], entries...)
		}
	}
	return first, values, ""
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

func semanticRecordValue(record Record, key string) string {
	if value := recordValue(record, key); value != "" {
		return value
	}
	if record.EmbeddedValues != nil {
		return firstValue(record.EmbeddedValues, key)
	}
	return record.EmbeddedFields[key]
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

func decodeProctitleArgs(value string) ([]string, bool) {
	if value == "" || len(value)%2 != 0 {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, false
	}
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return nil, false
	}
	return parts, true
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
