package audit

import (
	"encoding/json"
	"sort"
)

func buildCanonicalSecurity(records []Record) (*CanonicalSecurity, []CanonicalIssue) {
	type candidate struct {
		index    int
		record   Record
		security *CanonicalSecurity
		key      string
	}
	var candidates []candidate
	for i, r := range records {
		if r.Type == "SECCOMP" {
			continue
		}
		if security := buildCanonicalSecurityRecord(r); security != nil {
			encoded, _ := json.Marshal(security)
			candidates = append(candidates, candidate{i, r, security, string(encoded)})
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if securityRecordRank(left.record.Type) != securityRecordRank(right.record.Type) {
			return securityRecordRank(left.record.Type) < securityRecordRank(right.record.Type)
		}
		if left.record.Type != right.record.Type {
			return left.record.Type < right.record.Type
		}
		return left.key < right.key
	})
	selected := candidates[0]
	var issues []CanonicalIssue
	for _, extra := range candidates[1:] {
		if extra.key == selected.key {
			continue
		}
		// A single flat decision must never combine unrelated subject/target
		// contexts. Preserve additional distinct decisions as explicit evidence.
		for _, f := range extra.record.AllFields {
			if securityEvidenceField(f.Key) {
				issues = append(issues, sourceFieldIssue("additional_security_evidence", extra.record, extra.index, f, false))
			}
		}
		for _, f := range extra.record.EmbeddedAllFields {
			if securityEvidenceField(f.Key) {
				issues = append(issues, sourceFieldIssue("additional_security_evidence", extra.record, extra.index, f, true))
			}
		}
	}
	return selected.security, issues
}

func securityEvidenceField(key string) bool {
	switch key {
	case "decision", "apparmor", "permissions", "requested_mask", "scontext", "subj", "tcontext", "tclass", "profile", "permissive":
		return true
	}
	return false
}
