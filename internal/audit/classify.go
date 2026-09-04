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

var cisAuditClassification = mustCISAuditClassification()

func classifyCanonicalEvent(event *CanonicalEvent) {
	if event.Process != nil && (event.Process.Syscall == "execve" || event.Process.Syscall == "execveat" || len(event.Process.Argv) > 0) {
		event.Event.Category = "process"
		event.Event.Action = "execute"
		return
	}

	for _, rule := range cisAuditClassification.Rules {
		if classificationRuleMatches(*event, rule) {
			event.Event.Category = rule.Category
			event.Event.Action = rule.Action
			return
		}
	}
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
