package audit

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestEmbeddedPayloadEnvelopeAndEvidence(t *testing.T) {
	for _, payload := range []string{`acct="audit(garbage)" addr=192.0.2.1 res=failed`, `op=PAM:authentication acct="audit(1.2:3):" res=failed`} {
		r := mustParseRecord(t, `type=USER_AUTH msg=audit(100.1:7): msg='`+payload+`'`)
		if r.ID != "100.1:7" || r.EmbeddedFields["res"] != "failed" || r.EmbeddedParseError != "" {
			t.Fatalf("%#v", r)
		}
	}
	for _, payload := range []string{`PAM: authentication acct="root" res=failed`, `acct=root broken res=failed`, `legacy prose`, `acct=root bad=` + "\"" + `unclosed`} {
		// Double quoted outer payload permits malformed inner single quotes; the
		// other cases use ordinary single quoted userspace envelopes.
		if strings.Contains(payload, "unclosed") {
			payload = "acct=root bad='unclosed"
		}
		quote := "'"
		if strings.Contains(payload, "unclosed") {
			quote = "\""
		}
		r := mustParseRecord(t, `type=USER_AUTH msg=audit(100.1:7): msg=`+quote+payload+quote+` msg='acct=second res=failed'`)
		e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
		found := false
		for _, issue := range e.Event.Issues {
			if issue.Code == "embedded_parse_failure" {
				raw, err := hex.DecodeString(issue.Value)
				if err != nil || string(raw) != payload {
					t.Fatalf("evidence: %#v", issue)
				}
				found = true
			}
		}
		if !found || r.EmbeddedFields["acct"] != "second" {
			t.Fatalf("lost evidence or subsequent valid payload: %#v", e)
		}
	}
	if _, err := ParseRecord(`type=USER_AUTH msg='acct="audit(100.1:7):" res=failed'`); err == nil {
		t.Fatal("user content impersonated envelope")
	}
}
