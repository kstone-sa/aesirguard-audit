package audit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func canonicalLines(t *testing.T, lines ...string) CanonicalEvent {
	t.Helper()
	var records []Record
	for _, line := range lines {
		records = append(records, mustParseRecord(t, line))
	}
	return BuildCanonicalEvent(AssembledEvent{ID: records[0].ID, Records: records, Complete: true}, CanonicalOptions{})
}

func TestAuditPathBytesAreDecodedOrPreservedExplicitly(t *testing.T) {
	for b := 0; b < 256; b++ {
		raw := string([]byte{'/', 'x', byte(b)})
		field := hex.EncodeToString([]byte(raw))
		e := canonicalLines(t, `type=PATH msg=audit(100.0:1): item=0 name=`+field)
		if utf8.ValidString(raw) {
			if e.Paths[0].Name != raw {
				t.Fatalf("byte %x changed: %q", b, e.Paths[0].Name)
			}
		} else {
			if e.Paths[0].Name != "" || len(e.Event.Issues) != 1 {
				t.Fatalf("byte %x silently lost: %#v", b, e)
			}
			issue := e.Event.Issues[0]
			original, err := hex.DecodeString(issue.Value)
			if err != nil || string(original) != field || issue.ValueEncoding != "hex" || issue.RecordIndex == nil || *issue.RecordIndex != 0 || issue.Quoted == nil || *issue.Quoted {
				t.Fatalf("nonreversible evidence: %#v", issue)
			}
		}
		encoded, err := json.Marshal(e)
		if err != nil || strings.Contains(string(encoded), "\\ufffd") {
			t.Fatalf("lossy JSON for byte %x", b)
		}
	}
	for _, raw := range []string{`a\\b`, `trailing\`, `deadbeef`, `1234`, "café"} {
		e := canonicalLines(t, `type=PATH msg=audit(100.0:1): item=0 name="`+raw+`"`)
		if e.Paths[0].Name != raw {
			t.Fatalf("literal %q became %q", raw, e.Paths[0].Name)
		}
	}
}

func TestProcessAndEmbeddedStringsUseFieldEncoding(t *testing.T) {
	e := canonicalLines(t, `type=USER_AUTH msg=audit(100.0:1): msg='acct=612062 exe=2F612062 res=success'`)
	if e.Target.User != "a b" || e.Process.Executable != "/a b" {
		t.Fatalf("encoded payload: %#v", e)
	}
	r := mustParseRecord(t, `type=SYSCALL msg=audit(100.0:1): comm=612062 exe=2F612062`)
	e = BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
	if e.Process.Name != "a b" || e.Process.Executable != "/a b" || r.Fields["comm"] != "612062" {
		t.Fatal("decoding lost text or modified provenance")
	}
}

func TestExecveRequiresCompleteConsistentIndexedEvidence(t *testing.T) {
	for _, fields := range []string{
		`argc=3 a0="tool" a2="last"`,
		`argc=3 a0="tool" a1_len=6 a1[0]="ab" a1[2]="ef" a2="last"`,
		`argc=1 a0_len=6 a0[0]="ab" a0[1]="cd"`,
		`argc=2 a0="tool"`,
		`argc=1 a0="one" a0="different"`,
		`argc=1 argc=2 a0="one"`,
		`argc=1 a0=FF`,
		`argc=1 a0=ZZ`,
		`argc=1 a0="whole" a0_len=4 a0[0]="part"`,
		`argc=999999999999999999999 a999999="bounded"`,
	} {
		t.Run(fields, func(t *testing.T) {
			r := mustParseRecord(t, `type=EXECVE msg=audit(100.0:1): `+fields)
			e := BuildCanonicalEvent(AssembledEvent{ID: r.ID, Records: []Record{r}, Complete: true}, CanonicalOptions{})
			if e.Process == nil || len(e.Process.Argv) != 0 || e.Process.ArgvSource != "execve" || len(e.Event.Issues) == 0 {
				t.Fatalf("invented complete argv: %#v", e)
			}
			// Every source argc, length, argument and fragment remains recoverable,
			// including duplicates and explicit empty strings, in source order.
			var recovered []string
			for _, issue := range e.Event.Issues {
				b, err := hex.DecodeString(issue.Value)
				if err != nil {
					t.Fatal(err)
				}
				recovered = append(recovered, issue.Field+"="+string(b))
			}
			var wanted []string
			for _, f := range r.AllFields {
				if f.Key != "type" && f.Key != "msg" {
					wanted = append(wanted, f.Key+"="+f.Value)
				}
			}
			if !reflect.DeepEqual(recovered, wanted) {
				t.Fatalf("lost argv evidence: %v != %v", recovered, wanted)
			}
		})
	}
}

func TestExecveFragmentsPreserveBytesAcrossUnicodeBoundaries(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		parts := []string{`type=EXECVE msg=audit(100.0:1): argc=2 a0="" a1_len=6 a1[0]=E2`, `type=EXECVE msg=audit(100.0:1): a1[1]=82AC`}
		if reverse {
			parts[0], parts[1] = parts[1], parts[0]
		}
		e := canonicalLines(t, parts...)
		if !reflect.DeepEqual(e.Process.Argv, []string{"", "€"}) || len(e.Event.Issues) != 0 {
			t.Fatalf("fragment reconstruction: %#v", e)
		}
	}
}

func TestProctitleQuotingControlsDecoding(t *testing.T) {
	for _, tc := range []struct {
		field string
		argv  []string
	}{{`"bash"`, []string{"bash"}}, {`"deadbeef"`, []string{"deadbeef"}}, {`"a\\b"`, []string{`a\\b`}}, {`6100006200`, []string{"a", "", "b"}}} {
		e := canonicalLines(t, `type=PROCTITLE msg=audit(100.0:1): proctitle=`+tc.field)
		if e.Process.ArgvSource != "proctitle" || !reflect.DeepEqual(e.Process.Argv, tc.argv) {
			t.Fatalf("%s: %#v", tc.field, e.Process)
		}
	}
}

func TestMalformedNonUTF8LineIsReversible(t *testing.T) {
	line := string([]byte{0xff, 'x'})
	e := BuildParseFailureEvent(line, fmt.Errorf("malformed input"), CanonicalOptions{})
	b, err := hex.DecodeString(e.Audit.Raw)
	if err != nil || string(b) != line || e.Audit.RawEncoding != "hex" {
		t.Fatalf("lost malformed bytes: %#v", e)
	}
}

func TestEmbeddedQuotedApostropheAndEncodedAVCName(t *testing.T) {
	e := canonicalLines(t, `type=USER_AUTH msg=audit(100.0:1): msg='acct="O'Reilly" exe="/bin/tool" res=success'`)
	if e.Target == nil || e.Target.User != "O'Reilly" || len(e.Event.Issues) != 0 {
		t.Fatalf("lost nested quoted account: %#v", e)
	}
	e = canonicalLines(t, `type=USER_AVC msg=audit(100.0:1): msg='avc: denied { read } for name=612062 scontext=a tcontext=b permissive=0'`)
	if e.Target == nil || e.Target.Name != "a b" {
		t.Fatalf("lost encoded userspace AVC name: %#v", e)
	}
}

func TestMalformedEnvelopeDoesNotEmitReplacementIdentity(t *testing.T) {
	line := "type=PATH msg=audit(100.0:" + string([]byte{0xff}) + "): name=FF"
	_, err := ParseRecord(line)
	if err == nil {
		t.Fatal("accepted non-UTF-8 envelope")
	}
	e := BuildParseFailureEvent(line, err, CanonicalOptions{})
	if e.Audit.ID != "" || e.Audit.RawEncoding != "hex" {
		t.Fatalf("invented identity: %#v", e.Audit)
	}
	raw, decodeErr := hex.DecodeString(e.Audit.Raw)
	if decodeErr != nil || string(raw) != line {
		t.Fatal("lost original envelope bytes")
	}
}
