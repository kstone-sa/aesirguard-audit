package audit

import (
	"encoding/hex"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRealFormatUserCommand(t *testing.T) {
	data, err := os.ReadFile("../../testdata/user_cmd.audit")
	if err != nil {
		t.Fatal(err)
	}
	r := mustParseRecord(t, strings.TrimSpace(string(data)))
	a := NewAssembler(time.Second)
	events, err := a.AddChecked(r)
	if err != nil || len(events) != 1 || !events[0].Complete || events[0].Completion != CompletionSingleRecord || a.PendingBytes() != 0 {
		t.Fatalf("completion: %#v %v", events, err)
	}
	e := WithHumanMessage(BuildCanonicalEvent(events[0], CanonicalOptions{}))
	if e.Event.Type != "USER_CMD" || e.Event.Action != "user_command" || e.Event.Integrity != nil || len(e.Event.Issues) != 0 || e.Event.Success == nil || !*e.Event.Success {
		t.Fatalf("event: %#v", e)
	}
	if e.Actor == nil || e.Actor.User != "test" || e.Process == nil || e.Process.Command != "auditctl -v" || e.Process.CommandSource != "user_cmd" || len(e.Process.Argv) != 0 || e.Process.ArgvSource != "" || e.Process.CWD != "/home/test/audit2json" || e.Process.Executable != "/usr/bin/sudo" || e.Process.PID != "1234" || e.Origin == nil || e.Origin.Terminal != "pts/0" {
		t.Fatalf("evidence: %#v", e)
	}
	if e.Message != `test generated a USER_CMD record for "auditctl -v" (USER_CMD operation succeeded)` {
		t.Fatal(e.Message)
	}
}

func TestUserCommandDecodingAndEvidence(t *testing.T) {
	for _, tc := range []struct {
		token, want string
		invalid     bool
	}{
		{`"echo a b"`, "echo a b", false}, {`"6162"`, "6162", false}, {`"a\b"`, `a\b`, false}, {`6162`, "ab", false},
		{`xyz`, "", true}, {`123`, "", true}, {`ff`, "", true}, {`610062`, "", true}, {`""`, "", false},
		{`6162 cmd="ab"`, "ab", false}, {`6162 cmd="cd"`, "", true},
	} {
		t.Run(tc.token, func(t *testing.T) {
			r := mustParseRecord(t, `type=USER_CMD msg=audit(100.1:1): msg='cmd=`+tc.token+` cwd=2f746d702061 res=failed'`)
			e := WithHumanMessage(BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{}))
			if e.Process == nil || e.Process.Command != tc.want || e.Process.CommandSource != "user_cmd" || e.Process.CWD != "/tmp a" || e.Event.Success == nil || *e.Event.Success {
				t.Fatalf("event: %#v", e)
			}
			if strings.Contains(e.Message, "executed") || !strings.Contains(e.Message, "USER_CMD operation failed") {
				t.Fatal(e.Message)
			}
			count := 0
			for _, issue := range e.Event.Issues {
				if issue.Code == "invalid_user_command" {
					count++
					bytes, err := hex.DecodeString(issue.Value)
					if err != nil || len(bytes) == 0 || issue.Source != "embedded" || issue.RecordType != "USER_CMD" || issue.RecordIndex == nil || *issue.RecordIndex != 0 || issue.Quoted == nil {
						t.Fatalf("issue: %#v", issue)
					}
				}
			}
			if (count > 0) != tc.invalid {
				t.Fatalf("issues: %#v", e.Event.Issues)
			}
		})
	}
}

func TestUserCommandDoesNotReplaceExecutionArguments(t *testing.T) {
	records := []Record{mustParseRecord(t, `type=USER_CMD msg=audit(100.1:1): cmd="echo a b"`), mustParseRecord(t, `type=EXECVE msg=audit(100.1:1): argc=2 a0="echo" a1="a b"`)}
	e := BuildCanonicalEvent(AssembledEvent{ID: records[0].ID, Records: records, Complete: true}, CanonicalOptions{})
	if e.Process.Command != "echo a b" || e.Process.ArgvSource != "execve" || !reflect.DeepEqual(e.Process.Argv, []string{"echo", "a b"}) {
		t.Fatalf("process: %#v", e.Process)
	}
}

func TestUnsetAuditIdentityEvidence(t *testing.T) {
	for _, fields := range []string{`auid=4294967295 ses=4294967295`, `auid=4294967295 ses=4294967295 AUID="unset"`, `auid=-1 ses=-1`, `AUID="unset" SES="unset"`} {
		r := mustParseRecord(t, `type=DAEMON_START msg=audit(100.1:1): uid=0 res=success `+fields)
		e := WithHumanMessage(BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{}))
		if e.Actor != nil || strings.Contains(e.Message, "4294967295") || e.Process == nil || e.Process.UserID != "0" {
			t.Fatalf("event: %#v", e)
		}
		if len(e.Event.Issues) < 2 {
			t.Fatalf("lost sentinel evidence: %#v", e.Event.Issues)
		}
		for _, issue := range e.Event.Issues {
			if issue.Code != "unset_audit_id" || issue.ValueEncoding != "hex" || issue.RecordIndex == nil {
				t.Fatalf("issue: %#v", issue)
			}
		}
	}
	r := mustParseRecord(t, `type=USER_AUTH msg=audit(100.1:1): auid=1000 uid=4294967295 pid=4294967295 AUID="test"`)
	e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
	if e.Actor.User != "test" || e.Process.UserID != "4294967295" || e.Process.PID != "4294967295" {
		t.Fatalf("overbroad sentinel: %#v", e)
	}
}

func TestNullRuleKeySentinel(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want []string
	}{{`(null)`, nil}, {`"(null)"`, []string{"(null)"}}, {`286e756c6c29`, []string{"(null)"}}, {`"real"`, []string{"real"}}, {`7265616c016f74686572`, []string{"real", "other"}}} {
		r := mustParseRecord(t, `type=SYSCALL msg=audit(100.1:1): comm="(null)" key=`+tc.key+"\x1dARCH=aarch64")
		e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
		var got []string
		if e.Rule != nil {
			got = e.Rule.Keys
		}
		if !reflect.DeepEqual(got, tc.want) || e.Process.Name != "(null)" {
			t.Fatalf("event: %#v", e)
		}
	}
}

func TestUserCommandMalformedPayloadAndBounds(t *testing.T) {
	r := mustParseRecord(t, `type=USER_CMD msg=audit(100.1:1): msg='cmd="echo" broken'`)
	e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
	if e.Process.Command != "" || len(e.Event.Issues) != 1 || e.Event.Issues[0].Code != "embedded_parse_failure" {
		t.Fatalf("malformed payload: %#v", e)
	}
	original, err := hex.DecodeString(e.Event.Issues[0].Value)
	if err != nil || string(original) != `cmd="echo" broken` {
		t.Fatal("payload evidence lost")
	}
	if _, err := ParseRecord(`type=USER_CMD msg=audit(100.1:1): msg='cmd="echo"'UID="test"`); err == nil {
		t.Fatal("missing boundary accepted")
	}
	for _, limit := range []int{r.SourceBytes - 1, r.SourceBytes} {
		a, err := NewBoundedAssembler(time.Second, AssemblerLimits{MaxPendingEvents: 1, MaxRecordsPerEvent: 1, MaxPendingBytes: limit})
		if err != nil {
			t.Fatal(err)
		}
		events, err := a.AddChecked(r)
		if limit < r.SourceBytes {
			if err == nil || len(events) != 0 {
				t.Fatal("bypassed byte bound")
			}
		} else if err != nil || len(events) != 1 || !events[0].Complete {
			t.Fatalf("completion: %#v %v", events, err)
		}
		if a.Pending() != 0 || a.PendingBytes() != 0 {
			t.Fatal("leaked pending state")
		}
	}
}

func TestUserCommandUnknownResultAndRawEvidence(t *testing.T) {
	r := mustParseRecord(t, `type=USER_CMD msg=audit(100.1:1): cmd=nothex res=maybe`)
	e := WithHumanMessage(BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{}))
	if e.Event.Success != nil || strings.Contains(e.Message, "succeeded") || strings.Contains(e.Message, "failed") {
		t.Fatal(e.Message)
	}
	found := false
	for _, issue := range e.Event.Issues {
		if issue.Code == "invalid_user_command" {
			raw, err := hex.DecodeString(issue.Value)
			if err != nil || string(raw) != "nothex" || issue.Source != "raw" || issue.Quoted == nil || *issue.Quoted {
				t.Fatalf("source: %#v", issue)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("lost raw command evidence")
	}
}
