package audit

import (
	"sort"
	"strings"
)

func canonicalSuccess(records []Record, primary string) (bool, bool, []CanonicalIssue) {
	// The primary action's result precedes syscall transport success (e.g.
	// auditctl sendmsg succeeding does not prove that its rule change succeeded).
	types := []string{primary}
	if primary != "SYSCALL" {
		types = append(types, "SYSCALL")
	}
	seen := map[string]bool{primary: true, "SYSCALL": true}
	var others []string
	for _, r := range records {
		if !seen[r.Type] {
			seen[r.Type] = true
			others = append(others, r.Type)
		}
	}
	sort.Strings(others)
	types = append(types, others...)
	for _, kind := range types {
		found, known, result := false, true, false
		var evidence []CanonicalIssue
		for ri, r := range records {
			if r.Type != kind {
				continue
			}
			fields := append(append([]Field(nil), r.AllFields...), r.EmbeddedAllFields...)
			for fi, f := range fields {
				if f.Key != "success" && f.Key != "res" {
					continue
				}
				value, ok := decodeResult(kind, f.Value)
				if !ok || (found && result != value) {
					known = false
				}
				result = value
				found = true
				evidence = append(evidence, sourceFieldIssue("unknown_result", r, ri, f, fi >= len(r.AllFields)))
			}
		}
		if found {
			if known {
				return result, true, nil
			}
			if len(evidence) > 1 {
				for i := range evidence {
					evidence[i].Code = "conflicting_result"
				}
			}
			return false, false, evidence
		}
	}
	return false, false, nil
}

func decodeResult(recordType, raw string) (bool, bool) {
	switch strings.ToLower(raw) {
	case "yes", "success", "succeeded":
		return true, true
	case "no", "failed", "failure":
		return false, true
	}
	switch recordType {
	case "CONFIG_CHANGE", "FEATURE_CHANGE", "MAC_STATUS", "MAC_POLICY_LOAD":
		switch raw {
		case "1":
			return true, true
		case "0":
			return false, true
		}
	}
	return false, false
}
