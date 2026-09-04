package audit

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func mustParseRecord(t *testing.T, line string) Record {
	t.Helper()
	record, err := ParseRecord(line)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestParseRecord(t *testing.T) {
	line := `type=SYSCALL msg=audit(1721721600.123:42): arch=c000003e syscall=59 success=yes exit=0 a0=55 auid=1000 uid=0 euid=0 gid=0 egid=0 tty=pts0 ses=3 pid=200 ppid=100 exe="/usr/bin/sudo" key="privileged"`

	record := mustParseRecord(t, line)
	if record.Type != "SYSCALL" {
		t.Fatalf("type = %q", record.Type)
	}
	if record.ID != "1721721600.123:42" {
		t.Fatalf("id = %q", record.ID)
	}
	if record.Fields["exe"] != "/usr/bin/sudo" {
		t.Fatalf("exe = %q", record.Fields["exe"])
	}
	if record.SourceBytes != len(line) {
		t.Fatalf("source bytes = %d, want %d", record.SourceBytes, len(line))
	}
}

func TestParseRecordPreservesRepeatedMessages(t *testing.T) {
	line := `type=USER_AUTH msg=audit(1721721601.456:43): pid=300 uid=0 auid=1000 msg='op=PAM:authentication acct="mario" terminal=ssh res=failed'`

	record := mustParseRecord(t, line)
	if record.ID != "1721721601.456:43" {
		t.Fatalf("id = %q", record.ID)
	}
	if got := record.Values["msg"]; len(got) != 2 {
		t.Fatalf("msg values = %#v", got)
	}
	if record.Fields["msg"] != "audit(1721721601.456:43):" {
		t.Fatalf("first msg = %q", record.Fields["msg"])
	}
}

func TestParseRecordUnescapesQuotedDelimiters(t *testing.T) {
	line := `type=TEST msg=audit(1721721602.000:44): note="say \"hello\" and \\ continue"`

	record := mustParseRecord(t, line)
	if got, want := record.Fields["note"], `say "hello" and \ continue`; got != want {
		t.Fatalf("note = %q, want %q", got, want)
	}
}

func TestParseRecordRejectsUnterminatedQuote(t *testing.T) {
	line := `type=TEST msg=audit(1721721602.000:44): note="unfinished`
	if _, err := ParseRecord(line); err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseRecordRejectsMalformedField(t *testing.T) {
	line := `type=TEST msg=audit(1721721602.000:44): malformed`
	if _, err := ParseRecord(line); err == nil {
		t.Fatal("expected an error")
	}
}

func TestCanonicalEventReconstructsFragmentedAndHexExecArgs(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1721721603.000:45): syscall=59`,
		`type=EXECVE msg=audit(1721721603.000:45): argc=3 a0="tool" a1_len=9 a1[0]="very " a1[1]="long" a2=2F6574632F736861646F77`,
	}
	records := make([]Record, 0, len(lines))
	for _, line := range lines {
		records = append(records, mustParseRecord(t, line))
	}

	assembled := AssembledEvent{ID: records[0].ID, Records: records, Completion: CompletionEOF}
	got := BuildCanonicalEvent(assembled, CanonicalOptions{})
	if want := []string{"tool", "very long", "/etc/shadow"}; got.Process == nil || !reflect.DeepEqual(got.Process.Argv, want) {
		t.Fatalf("argv = %#v, want %#v", got.Process, want)
	}
}

func TestCanonicalEventOrdersPathsByItem(t *testing.T) {
	lines := []string{
		`type=PATH msg=audit(1721721604.000:46): item=1 name="/second"`,
		`type=PATH msg=audit(1721721604.000:46): item=0 name="/first"`,
	}
	records := make([]Record, 0, len(lines))
	for _, line := range lines {
		records = append(records, mustParseRecord(t, line))
	}

	assembled := AssembledEvent{ID: records[0].ID, Records: records, Completion: CompletionEOF}
	got := BuildCanonicalEvent(assembled, CanonicalOptions{})
	want := []CanonicalPath{{Name: "/first"}, {Name: "/second"}}
	if !reflect.DeepEqual(got.Paths, want) {
		t.Fatalf("paths = %#v, want %#v", got.Paths, want)
	}
}

func TestAssemblerHandlesInterleavedEventsAndConsumesStandaloneEOE(t *testing.T) {
	assembler := NewAssembler(0)
	first := mustParseRecord(t, `type=SYSCALL msg=audit(1721721610.000:50): syscall=59`)
	second := mustParseRecord(t, `type=SYSCALL msg=audit(1721721611.000:51): syscall=2`)
	terminal := mustParseRecord(t, `type=PROCTITLE msg=audit(1721721610.000:50): proctitle=746F6F6C`)
	eoe := mustParseRecord(t, `type=EOE msg=audit(1721721610.000:50):`)

	if events := assembler.Add(first); len(events) != 0 {
		t.Fatalf("unexpected events: %#v", events)
	}
	assembler.Add(second)
	events := assembler.Add(terminal)
	if len(events) != 1 || events[0].ID != first.ID {
		t.Fatalf("terminal events = %#v", events)
	}
	if !events[0].Complete || events[0].Completion != CompletionProctitle {
		t.Fatalf("terminal completion = %#v", events[0])
	}
	if events := assembler.Add(eoe); len(events) != 0 {
		t.Fatalf("standalone EOE produced events: %#v", events)
	}
	remaining := assembler.FlushAll()
	if len(remaining) != 1 || remaining[0].ID != second.ID {
		t.Fatalf("remaining events = %#v", remaining)
	}
}

func TestAssemblerFlushesExpiredEvents(t *testing.T) {
	assembler := NewAssembler(2 * time.Second)
	observed := time.Unix(100, 0)
	record := mustParseRecord(t, `type=SYSCALL msg=audit(1721721620.000:60): syscall=59`)
	assembler.AddAt(record, observed)

	if events := assembler.FlushExpired(observed.Add(time.Second)); len(events) != 0 {
		t.Fatalf("early events = %#v", events)
	}
	events := assembler.FlushExpired(observed.Add(2 * time.Second))
	if len(events) != 1 || events[0].ID != record.ID {
		t.Fatalf("expired events = %#v", events)
	}
	if events[0].Complete || events[0].Completion != CompletionTimeout {
		t.Fatalf("expired completion = %#v", events[0])
	}
}

func TestAssemblerUsesAuditTimeWatermark(t *testing.T) {
	assembler := NewAssembler(2 * time.Second)
	observed := time.Unix(100, 0)
	oldRecord := mustParseRecord(t, `type=SYSCALL msg=audit(1721721620.000:60): syscall=59`)
	newRecord := mustParseRecord(t, `type=SYSCALL msg=audit(1721721623.000:61): syscall=2`)
	assembler.AddAt(oldRecord, observed)

	events := assembler.AddAt(newRecord, observed)
	if len(events) != 1 || events[0].ID != oldRecord.ID {
		t.Fatalf("watermark events = %#v", events)
	}
	if events[0].Complete || events[0].Completion != CompletionWatermark {
		t.Fatalf("watermark completion = %#v", events[0])
	}
}

func TestAssemblerEmitsKnownSingleRecordType(t *testing.T) {
	assembler := NewAssembler(2 * time.Second)
	record := mustParseRecord(t, `type=KERNEL msg=audit(1721721625.000:62): device=test`)

	events := assembler.Add(record)
	if len(events) != 1 || events[0].ID != record.ID {
		t.Fatalf("kernel events = %#v", events)
	}
}

func TestAssemblerFlushAllIsDeterministic(t *testing.T) {
	assembler := NewAssembler(0)
	lines := []string{
		`type=SYSCALL msg=audit(1721721630.000:70): syscall=1`,
		`type=SYSCALL msg=audit(1721721631.000:71): syscall=2`,
		`type=SYSCALL msg=audit(1721721632.000:72): syscall=3`,
	}
	for _, line := range lines {
		assembler.Add(mustParseRecord(t, line))
	}
	events := assembler.FlushAll()
	for index, serial := range []string{"70", "71", "72"} {
		if !strings.HasSuffix(events[index].ID, ":"+serial) {
			t.Fatalf("event %d = %q", index, events[index].ID)
		}
	}
}

func TestBoundedAssemblerRejectsExcessPendingEvents(t *testing.T) {
	assembler, err := NewBoundedAssembler(time.Second, AssemblerLimits{
		MaxPendingEvents:   1,
		MaxRecordsPerEvent: 2,
		MaxPendingBytes:    1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := mustParseRecord(t, `type=SYSCALL msg=audit(1721721630.000:70): syscall=1`)
	second := mustParseRecord(t, `type=SYSCALL msg=audit(1721721631.000:71): syscall=2`)
	if _, err := assembler.AddChecked(first); err != nil {
		t.Fatal(err)
	}
	if _, err := assembler.AddChecked(second); err == nil {
		t.Fatal("expected pending-event limit error")
	}
	if assembler.Pending() != 1 || assembler.PendingBytes() != first.SourceBytes {
		t.Fatalf("pending state = %d events, %d bytes", assembler.Pending(), assembler.PendingBytes())
	}
}

func TestBoundedAssemblerReleasesBytesOnCompletion(t *testing.T) {
	assembler, err := NewBoundedAssembler(time.Second, AssemblerLimits{
		MaxPendingEvents:   1,
		MaxRecordsPerEvent: 2,
		MaxPendingBytes:    1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := mustParseRecord(t, `type=KERNEL msg=audit(1721721630.000:70): device=test`)
	events, err := assembler.AddChecked(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || assembler.PendingBytes() != 0 {
		t.Fatalf("completion state = %#v, %d pending bytes", events, assembler.PendingBytes())
	}
}

func TestAssemblerUsesShutdownCompletion(t *testing.T) {
	assembler := NewAssembler(0)
	assembler.Add(mustParseRecord(t, `type=SYSCALL msg=audit(1721721630.000:70): syscall=1`))
	events := assembler.FlushAllWith(CompletionShutdown)
	if len(events) != 1 || events[0].Complete || events[0].Completion != CompletionShutdown {
		t.Fatalf("shutdown events = %#v", events)
	}
}

func TestAssemblerSafePositionStopsAtOldestUnresolvedLine(t *testing.T) {
	assembler := NewAssembler(time.Hour)
	first := mustParseRecord(t, `type=SYSCALL msg=audit(1721721630.000:70): syscall=1`)
	first.Source = SourcePosition{Device: 1, Inode: 2, Start: 100, End: 150, Valid: true}
	if _, err := assembler.AddChecked(first); err != nil {
		t.Fatal(err)
	}
	safe := assembler.SafeSourcePosition(SourcePosition{Device: 1, Inode: 2, Start: 300, End: 300, Valid: true})
	if !safe.Valid || safe.End != 100 {
		t.Fatalf("safe position = %#v", safe)
	}
	assembler.FlushAll()
	safe = assembler.SafeSourcePosition(SourcePosition{Device: 1, Inode: 2, Start: 300, End: 300, Valid: true})
	if safe.End != 300 {
		t.Fatalf("safe position after flush = %#v", safe)
	}
}

func FuzzParseRecordDoesNotPanic(f *testing.F) {
	f.Add(`type=SYSCALL msg=audit(1721721600.123:42): syscall=59 exe="/usr/bin/true"`)
	f.Add(`type=USER_AUTH msg=audit(1721721601.456:43): msg='op=PAM:authentication res=failed'`)
	f.Add(`type=TEST msg=audit(1.0:1): value="unterminated`)
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = ParseRecord(line)
	})
}
