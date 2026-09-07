package audit

import (
	"encoding/hex"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func loginFixture(t *testing.T) []Record {
	t.Helper()
	data, err := os.ReadFile("../../testdata/login_transition.audit")
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		records = append(records, mustParseRecord(t, line))
	}
	return records
}

func TestLOGINRealCompoundTransition(t *testing.T) {
	records := loginFixture(t)
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		a := NewAssembler(time.Second)
		for _, i := range order {
			if events := a.Add(records[i]); len(events) != 0 {
				t.Fatalf("premature standalone completion: %#v", events)
			}
		}
		if a.Pending() != 1 {
			t.Fatal("lost correlation")
		}
		events := a.Add(mustParseRecord(t, `type=EOE msg=audit(1788768576.891:863):`))
		if len(events) != 1 || !events[0].Complete || len(events[0].Records) != 4 {
			t.Fatalf("assembly: %#v", events)
		}
		e := WithHumanMessage(BuildCanonicalEvent(events[0], CanonicalOptions{}))
		if e.Event.Type != "LOGIN" || e.Event.Category != "session" || e.Event.Action != "set_audit_attribution" || e.Event.Success == nil || !*e.Event.Success || e.Event.Integrity != nil || e.Rule != nil {
			t.Fatalf("event: %#v", e)
		}
		p := e.Process
		if p == nil || p.PID != "1234" || p.Executable != "/usr/sbin/sshd" || p.Syscall != "write" || p.ArgvSource != "proctitle" || !reflect.DeepEqual(p.Argv, []string{"sshd: test [priv]"}) {
			t.Fatalf("process: %#v", p)
		}
		want := &CanonicalAuditAttribution{Old: &CanonicalAuditAttributionIdentity{LoginUID: "4294967295", LoginUIDUnset: true, SessionID: "4294967295", SessionUnset: true}, New: &CanonicalAuditAttributionIdentity{LoginUID: "1000", User: "test", SessionID: "42"}}
		if !reflect.DeepEqual(p.AuditAttribution, want) {
			t.Fatalf("transition: %#v", p.AuditAttribution)
		}
		if e.Actor == nil || e.Actor.User != "test" {
			t.Fatalf("actor: %#v", e.Actor)
		}
		for _, issue := range e.Event.Issues {
			if issue.Code == "unsupported_record" {
				t.Fatal(issue)
			}
		}
		if e.Message != `Process 1234 changed Audit attribution from [loginuid unset, session unset] to [loginuid "test" (1000), session 42]` {
			t.Fatal(e.Message)
		}
	}
}

func TestLOGINBoundaryAndUserLoginDistinction(t *testing.T) {
	records := loginFixture(t)
	for _, timeout := range []bool{false, true} {
		a := NewAssembler(time.Second)
		now := time.Unix(1, 0)
		for _, r := range records {
			if got := a.AddAt(r, now); len(got) != 0 {
				t.Fatal("premature completion")
			}
		}
		var events []AssembledEvent
		if timeout {
			events = a.FlushExpired(now.Add(2 * time.Second))
		} else {
			events = a.FlushAll()
		}
		if len(events) != 1 || events[0].Complete || len(events[0].Records) != 3 {
			t.Fatalf("boundary: %#v", events)
		}
		e := BuildCanonicalEvent(events[0], CanonicalOptions{})
		if e.Event.Type != "LOGIN" || e.Event.Integrity == nil || e.Process.AuditAttribution == nil {
			t.Fatalf("event: %#v", e)
		}
	}
	a := NewAssembler(time.Second)
	events := a.Add(mustParseRecord(t, `type=USER_LOGIN msg=audit(100.1:1): auid=1000 res=success`))
	if len(events) != 1 || !events[0].Complete {
		t.Fatal("changed USER_LOGIN completion")
	}
	e := BuildCanonicalEvent(events[0], CanonicalOptions{})
	if e.Event.Action != "login" || e.Event.Category != "authentication" || (e.Process != nil && e.Process.AuditAttribution != nil) {
		t.Fatalf("conflated USER_LOGIN: %#v", e)
	}
}

func TestLOGINRawUnsetAndEnrichedAttribution(t *testing.T) {
	for _, fields := range []string{
		`old-auid=4294967295 auid=1000 old-ses=4294967295 ses=42`,
		`old-auid=-1 auid=1000 old-ses=-1 ses=42`,
		`OLD-AUID="unset" AUID="test" OLD-SES="unset" ses=42`,
	} {
		e := canonicalLines(t, `type=LOGIN msg=audit(100.1:1): res=1 `+fields)
		x := e.Process.AuditAttribution
		if x == nil || x.Old == nil || !x.Old.LoginUIDUnset || !x.Old.SessionUnset || x.New == nil || x.New.SessionID != "42" || x.New.LoginUIDUnset {
			t.Fatalf("transition: %#v", x)
		}
	}
	e := canonicalLines(t, `type=LOGIN msg=audit(100.1:1): old-auid=1000 OLD-AUID="old" auid=4294967295 AUID="unset" old-ses=42 ses=4294967295 res=1`)
	x := e.Process.AuditAttribution
	if x.Old.LoginUID != "1000" || x.Old.User != "old" || x.New.LoginUID != "4294967295" || !x.New.LoginUIDUnset || !x.New.SessionUnset {
		t.Fatalf("clear transition: %#v", x)
	}
}

func TestLOGINResultBelongsToAttribution(t *testing.T) {
	for _, result := range []string{"res=0", "res=1", "res=maybe", "res=1 res=0", ""} {
		e := WithHumanMessage(canonicalLines(t, `type=LOGIN msg=audit(100.1:1): old-auid=0 auid=1000 old-ses=1 ses=42 `+result, `type=SYSCALL msg=audit(100.1:1): auid=0 success=yes SYSCALL=write`))
		x := e.Process.AuditAttribution
		if x == nil || x.New.LoginUID != "1000" {
			t.Fatal("correlated current auid concealed request")
		}
		if result == "res=0" {
			if e.Event.Success == nil || *e.Event.Success || !strings.Contains(e.Message, "failed to change") {
				t.Fatal(e)
			}
		} else if result == "res=1" {
			if e.Event.Success == nil || !*e.Event.Success {
				t.Fatal(e)
			}
		} else if e.Event.Success != nil || !strings.Contains(e.Message, "attempted to change") {
			t.Fatal("inferred transition success from write")
		}
	}
}

func TestLOGINInvalidTransitionPreservesSource(t *testing.T) {
	for _, fields := range []string{
		`old-auid=0 old-auid=1 auid=1000`, `old-ses=1 old-ses=2 ses=42`,
		`old-auid=4294967296 auid=1000`, `old-auid=oops auid=1000`,
		`old-auid=0 OLD-AUID="unset" auid=1000`, `old-auid=4294967295 OLD-AUID="root" auid=1000`,
		`old-auid=0 OLD-AUID="a" OLD-AUID="b" auid=1000`,
	} {
		r := mustParseRecord(t, `type=LOGIN msg=audit(100.1:1): `+fields)
		e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
		if e.Process != nil && e.Process.AuditAttribution != nil {
			t.Fatalf("invented transition: %#v", e.Process.AuditAttribution)
		}
		found := 0
		for _, issue := range e.Event.Issues {
			if issue.Code == "invalid_audit_attribution" {
				raw, err := hex.DecodeString(issue.Value)
				if err != nil || !strings.Contains(fields, string(raw)) || issue.RecordType != "LOGIN" || issue.Source != "raw" || issue.RecordIndex == nil || *issue.RecordIndex != 0 || issue.Quoted == nil {
					t.Fatalf("nonreversible issue: %#v", issue)
				}
				found++
			}
		}
		if found < 2 {
			t.Fatal("lost transition tokens")
		}
	}
}

func TestLOGINPartialAndRepeatedTransition(t *testing.T) {
	e := canonicalLines(t, `type=LOGIN msg=audit(100.1:1): auid=1000 auid=1000`)
	if e.Process.AuditAttribution.Old != nil || e.Process.AuditAttribution.New.LoginUID != "1000" {
		t.Fatal("fabricated old attribution")
	}
	e = canonicalLines(t, `type=LOGIN msg=audit(100.1:1): pid=42`)
	if e.Process.AuditAttribution != nil {
		t.Fatal("invented absent attribution")
	}
}

func TestLOGINUnappliedAttributionIsNotActorIdentity(t *testing.T) {
	for _, result := range []string{"res=0", ""} {
		e := canonicalLines(t, `type=LOGIN msg=audit(100.1:1): pid=42 old-auid=0 auid=1000 addr=192.0.2.1 `+result)
		if e.Actor != nil || e.Origin != nil || e.Process.AuditAttribution.New.LoginUID != "1000" {
			t.Fatalf("invented actor or origin: %#v", e)
		}
	}
}
