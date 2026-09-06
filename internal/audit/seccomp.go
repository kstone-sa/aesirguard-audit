package audit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

type seccompAction struct {
	Action      string `json:"action"`
	EventAction string `json:"event_action"`
}

type CanonicalSeccomp struct {
	Action             string `json:"action"`
	Code               string `json:"code,omitempty"`
	Signal             string `json:"signal,omitempty"`
	InstructionPointer string `json:"instruction_pointer,omitempty"`
}

func buildCanonicalSeccomp(records []Record) (*CanonicalSeccomp, []CanonicalIssue) {
	type candidate struct {
		index  int
		record Record
		value  CanonicalSeccomp
		key    string
	}
	var candidates []candidate
	var issues []CanonicalIssue
	for ri, r := range records {
		if r.Type != "SECCOMP" {
			continue
		}
		value := CanonicalSeccomp{Action: "unknown", Code: recordValue(r, "code"), Signal: recordValue(r, "sig"), InstructionPointer: recordValue(r, "ip")}
		code, err := strconv.ParseUint(value.Code, 0, 32)
		action, ok := securityEventFamilies.SeccompActions[fmt.Sprintf("%08x", code&0xffff0000)]
		consistent := true
		for _, other := range r.Values["code"] {
			if other != value.Code {
				consistent = false
			}
		}
		if err == nil && ok && consistent {
			value.Action = action.Action
		} else {
			found := false
			for _, f := range r.AllFields {
				if f.Key == "code" {
					issues = append(issues, sourceFieldIssue("unknown_seccomp_action", r, ri, f, false))
					found = true
				}
			}
			if !found {
				issues = append(issues, CanonicalIssue{Code: "missing_seccomp_code", RecordType: r.Type, RecordIndex: &ri, Field: "code"})
			}
		}
		encoded, _ := json.Marshal(value)
		candidates = append(candidates, candidate{ri, r, value, string(encoded)})
	}
	if len(candidates) == 0 {
		return nil, issues
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].key < candidates[j].key })
	for _, extra := range candidates[1:] {
		if extra.key == candidates[0].key {
			continue
		}
		for _, f := range extra.record.AllFields {
			switch f.Key {
			case "code", "sig", "ip", "syscall", "arch", "compat":
				issues = append(issues, sourceFieldIssue("additional_seccomp_evidence", extra.record, extra.index, f, false))
			}
		}
	}
	return &candidates[0].value, issues
}
