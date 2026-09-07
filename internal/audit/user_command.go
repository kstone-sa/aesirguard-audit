package audit

import (
	"strings"
	"unicode/utf8"
)

// USER_CMD contains producer-supplied command text, not an argv encoding.
// Never shell-split it or promote it to evidence of completed execution.
func buildUserCommand(records []Record) (string, string, []CanonicalIssue) {
	var command, source string
	var evidence []CanonicalIssue
	seen, valid := false, true
	for index, record := range records {
		if record.Type != "USER_CMD" {
			continue
		}
		source = "user_cmd"
		for _, section := range []struct {
			fields   []Field
			embedded bool
		}{{record.AllFields, false}, {record.EmbeddedAllFields, true}} {
			for _, field := range section.fields {
				if field.Key != "cmd" {
					continue
				}
				evidence = append(evidence, sourceFieldIssue("invalid_user_command", record, index, field, section.embedded))
				value, ok := untrustedString(field, true)
				if !ok || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') || (seen && value != command) {
					valid = false
				}
				command, seen = value, true
			}
		}
	}
	if !valid {
		return "", source, evidence
	}
	return command, source, nil
}

// These sentinels belong to Linux Audit login/session IDs, not arbitrary IDs.
func auditIDUnset(value string) bool {
	return value == "4294967295" || value == "-1" || strings.EqualFold(value, "unset")
}
