package audit

import (
	"encoding/json"
	"strings"

	mappingdata "github.com/kstone-sa/audit2json/data"
)

type canonicalClassificationDocument struct {
	Version string                        `json:"version"`
	Rules   []canonicalClassificationRule `json:"rules"`
}

type canonicalClassificationRule struct {
	Category       string   `json:"category"`
	Action         string   `json:"action"`
	Keys           []string `json:"keys"`
	Syscalls       []string `json:"syscalls"`
	Paths          []string `json:"paths"`
	PathPrefixes   []string `json:"path_prefixes"`
	RequireFailure bool     `json:"require_failure"`
}

type securityEventFamilyDocument struct {
	Version           string                          `json:"version"`
	RecordTypes       map[string]securityEventFamily  `json:"record_types"`
	RecordPrefixes    []securityEventFamilyPrefixRule `json:"record_prefixes"`
	SingleRecordTypes []string                        `json:"single_record_types"`
}

type securityEventFamily struct {
	Category string `json:"category"`
	Action   string `json:"action"`
}

type securityEventFamilyPrefixRule struct {
	Prefix   string `json:"prefix"`
	Category string `json:"category"`
	Action   string `json:"action"`
}

var cisAuditClassification = mustCISAuditClassification()
var securityEventFamilies = mustSecurityEventFamilies()

func classifyCanonicalEvent(event *CanonicalEvent) {
	if event.Process != nil && (event.Process.Syscall == "execve" || event.Process.Syscall == "execveat" || len(event.Process.Argv) > 0) {
		event.Event.Category = "process"
		event.Event.Action = "execute"
		return
	}
	family, hasSecurityFamily := securityEventFamilyForType(event.Event.Type)
	if hasSecurityFamily && event.Event.Type != "KERN_MODULE" {
		event.Event.Category = family.Category
		event.Event.Action = family.Action
		return
	}

	for _, rule := range cisAuditClassification.Rules {
		if classificationRuleMatches(*event, rule) {
			event.Event.Category = rule.Category
			event.Event.Action = rule.Action
			return
		}
	}
	if hasSecurityFamily {
		event.Event.Category = family.Category
		event.Event.Action = family.Action
	}
}

func securityEventFamilyForType(recordType string) (securityEventFamily, bool) {
	if family, ok := securityEventFamilies.RecordTypes[recordType]; ok {
		return family, true
	}
	for _, rule := range securityEventFamilies.RecordPrefixes {
		if strings.HasPrefix(recordType, rule.Prefix) {
			return securityEventFamily{Category: rule.Category, Action: rule.Action}, true
		}
	}
	return securityEventFamily{}, false
}

func isKnownSingleRecordType(recordType string) bool {
	return containsString(securityEventFamilies.SingleRecordTypes, recordType)
}

func preferredSecurityRecordType(records []Record) string {
	for _, record := range records {
		if _, ok := securityEventFamilyForType(record.Type); ok {
			return record.Type
		}
	}
	return ""
}

func classificationRuleMatches(event CanonicalEvent, rule canonicalClassificationRule) bool {
	if rule.RequireFailure && (event.Event.Success == nil || *event.Event.Success) {
		return false
	}
	if event.Process != nil && containsString(rule.Syscalls, strings.ToLower(event.Process.Syscall)) {
		return true
	}
	if event.Rule != nil {
		for _, key := range event.Rule.Keys {
			if containsString(rule.Keys, normalizedAuditKey(key)) {
				return true
			}
		}
	}
	for _, path := range event.Paths {
		if containsString(rule.Paths, path.Name) && pathEvidenceIsMutation(event) {
			return true
		}
		for _, prefix := range rule.PathPrefixes {
			if strings.HasPrefix(path.Name, prefix) && pathEvidenceIsMutation(event) {
				return true
			}
		}
	}
	return false
}

func pathEvidenceIsMutation(event CanonicalEvent) bool {
	if event.Process == nil {
		return false
	}
	switch strings.ToLower(event.Process.Syscall) {
	case "write", "pwrite64", "writev", "pwritev", "pwritev2",
		"creat", "truncate", "ftruncate",
		"chmod", "fchmod", "fchmodat", "fchmodat2",
		"chown", "fchown", "fchownat", "lchown",
		"setxattr", "lsetxattr", "fsetxattr",
		"removexattr", "lremovexattr", "fremovexattr",
		"unlink", "unlinkat", "rename", "renameat", "renameat2":
		return true
	default:
		return false
	}
}

func normalizedAuditKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	return value
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func mustCISAuditClassification() canonicalClassificationDocument {
	var document canonicalClassificationDocument
	if err := json.Unmarshal([]byte(mappingdata.CISAuditFamiliesJSON()), &document); err != nil {
		panic("invalid embedded CIS Audit family mapping: " + err.Error())
	}
	if document.Version == "" || len(document.Rules) == 0 {
		panic("empty embedded CIS Audit family mapping")
	}
	for _, rule := range document.Rules {
		if rule.Category == "" || rule.Action == "" {
			panic("incomplete embedded CIS Audit family mapping")
		}
	}
	return document
}

func mustSecurityEventFamilies() securityEventFamilyDocument {
	var document securityEventFamilyDocument
	if err := json.Unmarshal([]byte(mappingdata.SecurityEventFamiliesJSON()), &document); err != nil {
		panic("invalid embedded security event family mapping: " + err.Error())
	}
	if document.Version == "" || len(document.RecordTypes) == 0 {
		panic("empty embedded security event family mapping")
	}
	for recordType, family := range document.RecordTypes {
		if recordType == "" || family.Category == "" || family.Action == "" {
			panic("incomplete embedded security event family mapping")
		}
	}
	for _, rule := range document.RecordPrefixes {
		if rule.Prefix == "" || rule.Category == "" || rule.Action == "" {
			panic("incomplete embedded security event prefix mapping")
		}
	}
	return document
}
