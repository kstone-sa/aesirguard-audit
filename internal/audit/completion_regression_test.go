package audit

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestArm64ProctitleCompletionWithoutEOE(t *testing.T) {
	data, err := os.ReadFile("../../testdata/arm64_proctitle_completion.audit")
	if err != nil {
		t.Fatal(err)
	}
	a := NewAssembler(time.Second)
	var events []AssembledEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		r := mustParseRecord(t, line)
		got := a.Add(r)
		if r.Type != "PROCTITLE" && len(got) != 0 {
			t.Fatalf("premature boundary: %#v", got)
		}
		if r.Type == "PROCTITLE" && len(got) != 1 {
			t.Fatalf("missing terminal boundary: %#v", got)
		}
		events = append(events, got...)
	}
	if len(events) != 2 || a.Pending() != 0 || a.PendingBytes() != 0 {
		t.Fatalf("assembly: %#v", events)
	}
	for i, event := range events {
		if !event.Complete || event.Completion != CompletionProctitle || len(event.Records) != []int{6, 4}[i] {
			t.Fatalf("boundary: %#v", event)
		}
		e := BuildCanonicalEvent(event, CanonicalOptions{})
		if e.Event.Integrity != nil || e.Process == nil || len(e.Paths) != []int{2, 1}[i] {
			t.Fatalf("canonical: %#v", e)
		}
		if i == 0 && (e.Event.Action != "execute" || e.Process.ArgvSource != "execve") {
			t.Fatalf("execution: %#v", e)
		}
		if i == 1 && (e.Rule != nil || e.Process.ArgvSource != "proctitle") {
			t.Fatalf("context: %#v", e)
		}
	}
	if got := a.FlushAll(); len(got) != 0 {
		t.Fatalf("duplicate EOF output: %#v", got)
	}
}

func TestProctitleBoundaryUsesFullNodeCorrelationKey(t *testing.T) {
	a := NewAssembler(0)
	for _, prefix := range []string{`node="a" `, `node="b" `, ""} {
		a.Add(mustParseRecord(t, prefix+`type=SYSCALL msg=audit(100.0:1): pid=123`))
	}
	for i, prefix := range []string{`node="b" `, "", `node="a" `} {
		got := a.Add(mustParseRecord(t, prefix+`type=PROCTITLE msg=audit(100.0:1): proctitle="tool"`))
		if len(got) != 1 || !got[0].Complete || len(got[0].Records) != 2 || a.Pending() != 2-i {
			t.Fatalf("cross-node completion: %#v", got)
		}
		if got[0].Records[0].Node != got[0].Records[1].Node {
			t.Fatal("merged nodes")
		}
	}
}

func TestOrphanProctitleRemainsPending(t *testing.T) {
	a := NewAssembler(time.Second)
	if got := a.Add(mustParseRecord(t, `type=PROCTITLE msg=audit(100.0:1): proctitle="tool"`)); len(got) != 0 {
		t.Fatalf("standalone completion: %#v", got)
	}
	got := a.FlushAll()
	if len(got) != 1 || got[0].Complete || got[0].Completion != CompletionEOF {
		t.Fatalf("lost orphan context: %#v", got)
	}
}

func TestProctitleCompletionRetainsUnresolvedReplayPosition(t *testing.T) {
	a := NewAssembler(0)
	add := func(id, kind string, start int64) []AssembledEvent {
		r := mustParseRecord(t, "type="+kind+" msg=audit("+id+"):")
		r.Source = SourcePosition{Device: 1, Inode: 2, Start: start, End: start + 10, Valid: true}
		return a.Add(r)
	}
	add("100.0:1", "SYSCALL", 0)
	add("100.0:2", "SYSCALL", 10)
	if got := add("100.0:2", "PROCTITLE", 20); len(got) != 1 || !got[0].Complete {
		t.Fatal(got)
	}
	fallback := SourcePosition{Device: 1, Inode: 2, Start: 30, End: 30, Valid: true}
	if safe := a.SafeSourcePosition(fallback); safe.End != 0 {
		t.Fatalf("skipped unresolved input: %#v", safe)
	}
	if got := add("100.0:1", "PROCTITLE", 30); len(got) != 1 || !got[0].Complete {
		t.Fatal(got)
	}
	fallback.Start, fallback.End = 40, 40
	if safe := a.SafeSourcePosition(fallback); safe.End != 40 {
		t.Fatalf("completed input not released: %#v", safe)
	}
}

func TestUnterminatedKernelGroupsRemainIncomplete(t *testing.T) {
	for _, boundary := range []Completion{CompletionTimeout, CompletionEOF, CompletionShutdown} {
		t.Run(string(boundary), func(t *testing.T) {
			a := NewAssembler(time.Second)
			now := time.Unix(1, 0)
			a.AddAt(mustParseRecord(t, `type=SYSCALL msg=audit(100.0:1): syscall=221`), now)
			a.AddAt(mustParseRecord(t, `type=EXECVE msg=audit(100.0:1): argc=2 a0="id"`), now)
			var got []AssembledEvent
			if boundary == CompletionTimeout {
				got = a.FlushExpired(now.Add(time.Second))
			} else {
				got = a.FlushAllWith(boundary)
			}
			if len(got) != 1 || got[0].Complete || got[0].Completion != boundary {
				t.Fatalf("incomplete boundary: %#v", got)
			}
			e := BuildCanonicalEvent(got[0], CanonicalOptions{})
			if e.Event.Integrity == nil {
				t.Fatal("missing incomplete integrity")
			}
		})
	}
}

func TestWatermarkCompletionKeepsExceptionalEvidence(t *testing.T) {
	a := NewAssembler(time.Second)
	now := time.Unix(1, 0)
	a.AddAt(mustParseRecord(t, `type=SYSCALL msg=audit(100.0:1): syscall=221`), now)
	a.AddAt(mustParseRecord(t, `type=EXECVE msg=audit(100.0:1): argc=2 a0="id"`), now)
	got := a.AddAt(mustParseRecord(t, `type=SYSCALL msg=audit(102.0:2): syscall=56`), now)
	if len(got) != 1 || !got[0].Complete || got[0].Completion != CompletionWatermark {
		t.Fatalf("watermark: %#v", got)
	}
	e := BuildCanonicalEvent(got[0], CanonicalOptions{})
	if e.Event.Integrity != nil {
		t.Fatal("ordinary stream boundary marked incomplete")
	}
	for _, issue := range e.Event.Issues {
		if issue.Code == "incomplete_argv" {
			return
		}
	}
	t.Fatal("watermark concealed exceptional argument evidence")
}

func TestWatermarkCannotCompleteAnotherNodeByItsClock(t *testing.T) {
	for _, other := range []string{`node="b" `, ""} {
		a := NewAssembler(time.Second)
		now := time.Unix(1, 0)
		a.AddAt(mustParseRecord(t, `node="a" type=SYSCALL msg=audit(100.0:1): pid=1`), now)
		if got := a.AddAt(mustParseRecord(t, other+`type=SYSCALL msg=audit(105.0:2): pid=2`), now); len(got) != 0 {
			t.Fatalf("foreign clock completed pending event: %#v", got)
		}
		got := a.FlushExpired(now.Add(time.Second))
		if len(got) != 2 {
			t.Fatalf("lost pending groups: %#v", got)
		}
		for _, event := range got {
			if event.Complete || event.Completion != CompletionTimeout {
				t.Fatalf("foreign watermark: %#v", event)
			}
		}
	}
}
