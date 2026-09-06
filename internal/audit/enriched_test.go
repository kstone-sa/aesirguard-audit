package audit

import "testing"

func TestEnrichedBoundaryPreservesBothSections(t *testing.T) {
	for _, ending := range []string{`last=0`, `last="literal"`, `msg='op=PAM:authentication acct="root" res=success'`} {
		r := mustParseRecord(t, `type=USER_AUTH msg=audit(100.0:1): `+ending+"\x1d"+`UID="root" AUID="operator"`)
		if r.Fields["UID"] != "root" || r.Fields["AUID"] != "operator" {
			t.Fatalf("lost interpreted fields: %#v", r)
		}
		if r.AllFields[len(r.AllFields)-3].Interpreted || !r.AllFields[len(r.AllFields)-2].Interpreted {
			t.Fatal("lost section provenance")
		}
		if ending[0:3] == "msg" && (r.EmbeddedFields["acct"] != "root" || len(r.EmbeddedAllFields) == 0) {
			t.Fatal("lost embedded provenance")
		}
	}
	r := mustParseRecord(t, "type=TEST msg=audit(100.0:1): value=\"a\x1db\" next=ok")
	if r.Fields["value"] != "a\x1db" || r.AllFields[len(r.AllFields)-1].Interpreted {
		t.Fatal("separator inside quoted text changed structure")
	}
}

func TestEnrichedPathNamesSurviveActualSeparator(t *testing.T) {
	r := mustParseRecord(t, `type=PATH msg=audit(100.0:1): item=0 name="/etc/shadow" ouid=0 ogid=0 cap_fver=0`+"\x1d"+`OUID="root" OGID="root"`)
	e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
	if e.Paths[0].Owner != "root" || e.Paths[0].Group != "root" || r.Fields["cap_fver"] != "0" {
		t.Fatalf("corrupted ENRICHED boundary: %#v", e)
	}
}
