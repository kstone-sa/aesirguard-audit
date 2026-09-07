package audit

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Only LOGIN supplies these old/new fields. New is the requested attribution;
// event.success establishes whether the kernel applied it.
type CanonicalAuditAttribution struct {
	Old *CanonicalAuditAttributionIdentity `json:"old,omitempty"`
	New *CanonicalAuditAttributionIdentity `json:"new,omitempty"`
}

type CanonicalAuditAttributionIdentity struct {
	LoginUID      string `json:"loginuid,omitempty"`
	User          string `json:"user,omitempty"`
	LoginUIDUnset bool   `json:"loginuid_unset,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	SessionUnset  bool   `json:"session_unset,omitempty"`
}

func buildAuditAttribution(records []Record) (*CanonicalAuditAttribution, []CanonicalIssue) {
	values := map[string]string{}
	var evidence []CanonicalIssue
	valid := true
	for index, record := range records {
		if record.Type != "LOGIN" {
			continue
		}
		// Read original LOGIN tokens: correlated SYSCALL auid describes current
		// identity, which may differ from the requested auid after a failure.
		for _, section := range []struct {
			fields   []Field
			embedded bool
		}{{record.AllFields, false}, {record.EmbeddedAllFields, true}} {
			for _, field := range section.fields {
				switch field.Key {
				case "old-auid", "OLD-AUID", "auid", "AUID", "old-ses", "OLD-SES", "ses", "SES":
				default:
					continue
				}
				evidence = append(evidence, sourceFieldIssue("invalid_audit_attribution", record, index, field, section.embedded))
				if old, seen := values[field.Key]; seen && old != field.Value {
					valid = false
				}
				if field.Value == "" || !utf8.ValidString(field.Value) || strings.ContainsRune(field.Value, '\x00') {
					valid = false
				}
				values[field.Key] = field.Value
			}
		}
	}
	old, oldOK := attributionIdentity(values["old-auid"], values["OLD-AUID"], values["old-ses"], values["OLD-SES"])
	newIdentity, newOK := attributionIdentity(values["auid"], values["AUID"], values["ses"], values["SES"])
	if !valid || !oldOK || !newOK {
		return nil, evidence
	}
	if old == nil && newIdentity == nil {
		return nil, nil
	}
	return &CanonicalAuditAttribution{Old: old, New: newIdentity}, nil
}

func attributionIdentity(loginuid, user, session, sessionName string) (*CanonicalAuditAttributionIdentity, bool) {
	validID := func(value string) bool {
		if value == "" || auditIDUnset(value) {
			return true
		}
		_, err := strconv.ParseUint(value, 10, 32)
		return isDecimal(value) && err == nil
	}
	identity := CanonicalAuditAttributionIdentity{LoginUID: loginuid, SessionID: session}
	identity.LoginUIDUnset = auditIDUnset(loginuid) || strings.EqualFold(user, "unset")
	identity.SessionUnset = auditIDUnset(session) || strings.EqualFold(sessionName, "unset")
	if !validID(loginuid) || !validID(session) ||
		(identity.LoginUIDUnset && loginuid != "" && !auditIDUnset(loginuid)) ||
		(identity.SessionUnset && session != "" && !auditIDUnset(session)) ||
		(sessionName != "" && !strings.EqualFold(sessionName, "unset") && sessionName != session) {
		return nil, false
	}
	if user != "" && !strings.EqualFold(user, "unset") {
		if identity.LoginUIDUnset || (isDecimal(user) && user != loginuid) {
			return nil, false
		}
		if !isDecimal(user) {
			identity.User = user
		}
	}
	if identity == (CanonicalAuditAttributionIdentity{}) {
		return nil, true
	}
	return &identity, true
}

func renderAuditAttribution(event CanonicalEvent) string {
	subject := "A process"
	if event.Process != nil && event.Process.PID != "" {
		subject = "Process " + event.Process.PID
	}
	verb := " attempted to change Audit attribution"
	if event.Event.Success != nil {
		if *event.Event.Success {
			verb = " changed Audit attribution"
		} else {
			verb = " failed to change Audit attribution"
		}
	}
	message := subject + verb
	if event.Process == nil || event.Process.AuditAttribution == nil {
		return message
	}
	format := func(identity *CanonicalAuditAttributionIdentity) string {
		login, session := "unknown", "unknown"
		if identity != nil {
			if identity.LoginUIDUnset {
				login = "unset"
			} else if identity.LoginUID != "" {
				login = identity.LoginUID
			}
			if identity.User != "" {
				login = strconv.Quote(identity.User) + " (" + login + ")"
			}
			if identity.SessionUnset {
				session = "unset"
			} else if identity.SessionID != "" {
				session = identity.SessionID
			}
		}
		return "loginuid " + login + ", session " + session
	}
	transition := event.Process.AuditAttribution
	return message + " from [" + format(transition.Old) + "] to [" + format(transition.New) + "]"
}
