package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Field is one parsed key/value pair. Fields remain ordered so repeated keys
// and their quoting state are not lost.
type Field struct {
	Key         string
	Value       string
	Quoted      bool
	Interpreted bool
}

// Record is one raw auditd record parsed into key/value fields.
type Record struct {
	Type               string
	ID                 string
	Fields             map[string]string
	Values             map[string][]string
	AllFields          []Field
	EmbeddedAllFields  []Field
	EmbeddedFields     map[string]string
	EmbeddedValues     map[string][]string
	EmbeddedParseError string
	EmbeddedFailures   []Field
	SourceBytes        int
	Source             SourcePosition
}

// SourcePosition identifies a complete physical source line. It is internal
// recovery metadata and is never copied into the canonical event.
type SourcePosition struct {
	Anchor     string
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
	envelope := -1
	for i, field := range allFields {
		if field.Key == "msg" && !field.Quoted && !field.Interpreted {
			if id := auditIDFromMessage(field.Value); id != "" {
				r.ID = id
				envelope = i
				break
			}
		}
	}
	if r.ID == "" {
		return Record{}, fmt.Errorf("audit id not found")
	}
	if r.Type == "" {
		return Record{}, fmt.Errorf("record type not found for audit id %s", r.ID)
	}
	if !utf8.ValidString(r.Type) || !utf8.ValidString(r.ID) {
		return Record{}, fmt.Errorf("invalid UTF-8 in Audit envelope")
	}
	var messages []Field
	for i, field := range allFields {
		if field.Key == "msg" && i != envelope {
			messages = append(messages, field)
		}
	}
	r.EmbeddedAllFields, r.EmbeddedFields, r.EmbeddedValues, r.EmbeddedFailures, r.EmbeddedParseError = parseEmbeddedMessages(messages)
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
	return line[:boundary+3] + normalizeAuditPayload(line[boundary+3:])
}

func normalizeAuditPayload(payload string) string {
	if strings.HasPrefix(payload, "user ") {
		return normalizeAuditPayload(payload[len("user "):])
	}
	if !strings.HasPrefix(payload, "avc:") {
		return payload
	}

	remainder := strings.TrimSpace(strings.TrimPrefix(payload, "avc:"))
	decisionEnd := strings.IndexByte(remainder, ' ')
	if decisionEnd <= 0 {
		return payload
	}
	decision := remainder[:decisionEnd]
	remainder = strings.TrimSpace(remainder[decisionEnd+1:])
	if !strings.HasPrefix(remainder, "{") {
		return payload
	}
	permissionsEnd := strings.IndexByte(remainder, '}')
	if permissionsEnd < 0 {
		return payload
	}
	permissions := strings.TrimSpace(remainder[1:permissionsEnd])
	remainder = strings.TrimSpace(remainder[permissionsEnd+1:])
	remainder = strings.TrimSpace(strings.TrimPrefix(remainder, "for"))
	return "decision=" + strconv.Quote(decision) + " permissions=" + strconv.Quote(permissions) + " " + remainder
}

func parseEmbeddedMessages(messages []Field) ([]Field, map[string]string, map[string][]string, []Field, string) {
	var all []Field
	first := map[string]string{}
	values := map[string][]string{}
	var failures []Field
	var firstError string
	for _, field := range messages {
		message := field.Value
		parsedAll, parsedFirst, parsedValues, err := parseFields(normalizeAuditPayload(message))
		if err != nil {
			failures = append(failures, field)
			if firstError == "" {
				firstError = err.Error()
			}
			continue
		}
		all = append(all, parsedAll...)
		for key, value := range parsedFirst {
			if _, exists := first[key]; !exists {
				first[key] = value
			}
		}
		for key, entries := range parsedValues {
			values[key] = append(values[key], entries...)
		}
	}
	return all, first, values, failures, firstError
}

func parseFields(line string) ([]Field, map[string]string, map[string][]string, error) {
	all := make([]Field, 0, 16)
	first := map[string]string{}
	values := map[string][]string{}

	interpreted := false
	for i := 0; i < len(line); {
		for i < len(line) && fieldBoundary(line[i]) {
			if line[i] == 0x1d {
				interpreted = true
			}
			i++
		}
		if i >= len(line) {
			break
		}

		keyStart := i
		for i < len(line) && line[i] != '=' && !fieldBoundary(line[i]) {
			i++
		}
		if i == keyStart {
			return nil, nil, nil, fmt.Errorf("empty field name at byte %d", i)
		}
		if i >= len(line) || line[i] != '=' {
			end := i
			for end < len(line) && !fieldBoundary(line[end]) {
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
			nestedDouble := false
			for i < len(line) {
				// Userspace msg='...' can contain double-quoted values with
				// literal apostrophes. Those apostrophes do not end msg.
				if quote == '\'' && line[i] == '"' {
					nestedDouble = !nestedDouble
				}
				if line[i] == quote && !nestedDouble {
					i++
					closed = true
					break
				}
				builder.WriteByte(line[i])
				i++
			}
			if !closed {
				return nil, nil, nil, fmt.Errorf("unterminated quoted value for field %q", key)
			}
			if i < len(line) && !fieldBoundary(line[i]) {
				return nil, nil, nil, fmt.Errorf("missing boundary after quoted field %q", key)
			}
			value = builder.String()
		} else {
			valueStart := i
			for i < len(line) && !fieldBoundary(line[i]) {
				i++
			}
			value = line[valueStart:i]
		}

		field := Field{Key: key, Value: value, Quoted: quoted, Interpreted: interpreted}
		all = append(all, field)
		values[key] = append(values[key], value)
		if _, exists := first[key]; !exists {
			first[key] = value
		}
	}

	return all, first, values, nil
}

func fieldBoundary(b byte) bool { return b == ' ' || b == 0x1d }

func auditIDFromMessage(msg string) string {
	start := 0
	if !strings.HasPrefix(msg, "audit(") || !strings.HasSuffix(msg, "):") {
		return ""
	}
	start += len("audit(")
	end := strings.IndexByte(msg[start:], ')')
	if end < 0 || start+end != len(msg)-2 {
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

// Recover only a structurally parsed envelope prefix from a malformed line.
func auditIDFromLinePrefix(line string) string {
	end := strings.Index(line, "):")
	if end < 0 {
		return ""
	}
	fields, _, _, err := parseFields(line[:end+2])
	if err != nil {
		return ""
	}
	for _, f := range fields {
		if f.Key == "msg" && !f.Quoted && !f.Interpreted {
			if id := auditIDFromMessage(f.Value); id != "" {
				return id
			}
		}
	}
	return ""
}
