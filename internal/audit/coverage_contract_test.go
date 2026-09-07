package audit

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestEveryAdvertisedFamilyHasAnExplicitCoverageBoundary(t *testing.T) {
	doc, err := os.ReadFile("../../docs/security-event-coverage.md")
	if err != nil {
		t.Fatal(err)
	}
	types := make([]string, 0, len(securityEventFamilies.RecordTypes)+2)
	for typ := range securityEventFamilies.RecordTypes {
		if !strings.Contains(string(doc), "`"+typ+"`") {
			t.Errorf("mapped type %s lacks documented boundary", typ)
		}
		types = append(types, typ)
	}
	for _, rule := range securityEventFamilies.RecordPrefixes {
		if !strings.Contains(string(doc), "`"+rule.Prefix+"*`") {
			t.Errorf("mapped prefix %s lacks documented boundary", rule.Prefix)
		}
		types = append(types, rule.Prefix+"TEST")
	}
	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			record := mustParseRecord(t, "type="+typ+` msg=audit(1700000000.000:1): pid=42 auid=1000 exe="/usr/bin/tool" op=observed`)
			if typ == "LOGIN" {
				record = mustParseRecord(t, "type=LOGIN msg=audit(1700000000.000:1): pid=42 auid=1000 exe=\"/usr/bin/tool\" op=observed res=1")
			}
			event := BuildCanonicalEvent(AssembledEvent{ID: record.ID, Records: []Record{record}, Complete: true}, CanonicalOptions{})
			if event.Event.Type != typ || event.Event.Category == "" || event.Event.Action == "" {
				t.Fatalf("recognition missing: %#v", event.Event)
			}
			if event.Actor == nil || event.Actor.UserID != "1000" || event.Process == nil || event.Process.PID != "42" || event.Process.Executable != "/usr/bin/tool" || event.Event.OriginalAction != "observed" {
				t.Fatalf("documented common evidence missing: %#v", event)
			}
			for _, issue := range event.Event.Issues {
				if issue.Code == "unsupported_record" {
					t.Fatalf("recognized type reported unsupported: %#v", issue)
				}
			}
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip CanonicalEvent
			if err := json.Unmarshal(encoded, &roundTrip); err != nil {
				t.Fatal(err)
			}
			WithHumanMessage(roundTrip) // Renderer must accept the compact typed projection.
		})
	}
}

func TestClassificationOnlyDetailsDoNotMasqueradeAsTypedEvidence(t *testing.T) {
	for typ, fields := range map[string]string{
		"CAPSET":          "cap_pi=111111 cap_pp=222222 cap_pe=333333",
		"BPRM_FCAPS":      "old_pp=111111 new_pp=222222 old_pe=333333 new_pe=444444",
		"CONFIG_CHANGE":   "audit_enabled=111111 old=222222",
		"FEATURE_CHANGE":  "feature=111111 old=222222 new=333333",
		"BPF":             "prog-id=111111",
		"MAC_STATUS":      "enforcing=111111 old_enforcing=222222",
		"MAC_POLICY_LOAD": "lsm=unmodeled_lsm policy=unmodeled_policy",
		"INTEGRITY_DATA":  "hash=unmodeled_hash algo=unmodeled_algorithm",
		"SYSTEM_RUNLEVEL": "old-level=unmodeled_old new-level=unmodeled_new",
	} {
		t.Run(typ, func(t *testing.T) {
			base := mustParseRecord(t, "type="+typ+" msg=audit(1700000000.000:1):")
			rich := mustParseRecord(t, "type="+typ+" msg=audit(1700000000.000:1): "+fields)
			build := func(r Record) string {
				b, err := json.Marshal(BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{}))
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			// These intentionally unmodeled values have no canonical representation.
			// A future typed implementation must update this contract and the matrix.
			if build(base) != build(rich) {
				t.Fatal("coverage boundary changed; document and test the new typed evidence")
			}
		})
	}
}
