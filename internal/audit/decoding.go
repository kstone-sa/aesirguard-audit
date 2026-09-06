package audit

import (
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// sourceFieldIssue preserves the exact source value bytes, not a lossy UTF-8
// rendering. Quoting and section remain available to interpret those bytes.
func sourceFieldIssue(code string, record Record, index int, field Field, embedded bool) CanonicalIssue {
	source := "raw"
	if field.Interpreted {
		source = "interpreted"
	}
	if embedded {
		source = "embedded"
	}
	quoted := field.Quoted
	return CanonicalIssue{Code: code, RecordType: record.Type, RecordIndex: &index, Field: field.Key,
		Value: hex.EncodeToString([]byte(field.Value)), ValueEncoding: "hex", Quoted: &quoted, Source: source}
}

// Audit's untrusted-string fields are literal when quoted, hex when encoded.
// Unknown nonhex spellings remain text for userspace producer compatibility.
// Strict argument decoding below rejects malformed unquoted values instead.
func untrustedString(field Field, strict bool) (string, bool) {
	if field.Quoted || field.Interpreted {
		return field.Value, true
	}
	decoded, err := hex.DecodeString(field.Value)
	if err == nil {
		return string(decoded), true
	}
	if strict {
		return "", false
	}
	return field.Value, true
}

func encodedTextField(recordType, key string) bool {
	switch key {
	case "comm", "exe", "key":
		return true
	case "cwd":
		return recordType == "CWD"
	case "name":
		return recordType == "PATH" || recordType == "AVC" || strings.HasPrefix(recordType, "APPARMOR_") || recordType == "KERN_MODULE"
	case "acct":
		return strings.HasPrefix(recordType, "USER_") || strings.HasPrefix(recordType, "CRED_") || recordType == "ADD_USER" || recordType == "DEL_USER"
	}
	return false
}

// decodedRecords builds semantic views without modifying raw ordered Fields.
// Raw fields are still used for argv validation and anomaly evidence.
func decodedRecords(records []Record) ([]Record, []CanonicalIssue) {
	result := append([]Record(nil), records...)
	var issues []CanonicalIssue
	for i := range result {
		r := &result[i]
		decode := func(fields []Field, embedded bool) (map[string]string, map[string][]string) {
			first := map[string]string{}
			values := map[string][]string{}
			for _, f := range fields {
				value := f.Value
				// EXECVE and PROCTITLE must retain their encoding until byte fragments
				// have been assembled. Other fields can be decoded independently.
				if encodedTextField(r.Type, f.Key) {
					value, _ = untrustedString(f, false)
				}
				if !utf8.ValidString(value) {
					issues = append(issues, sourceFieldIssue("invalid_utf8", *r, i, f, embedded))
					value = ""
				}
				values[f.Key] = append(values[f.Key], value)
				if _, ok := first[f.Key]; !ok {
					first[f.Key] = value
				}
			}
			return first, values
		}
		if len(r.AllFields) > 0 {
			r.Fields, r.Values = decode(r.AllFields, false)
		}
		if len(r.EmbeddedAllFields) > 0 {
			r.EmbeddedFields, r.EmbeddedValues = decode(r.EmbeddedAllFields, true)
		}
	}
	return result, issues
}
