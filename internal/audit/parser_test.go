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

func TestBuildEvent(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1721721600.123:42): arch=c000003e syscall=59 success=yes auid=1000 uid=0 euid=0 gid=0 egid=0 tty=pts0 ses=3 pid=200 ppid=100 exe="/usr/bin/sudo" key="privileged"`,
		`type=EXECVE msg=audit(1721721600.123:42): argc=3 a0="sudo" a1="cat" a2="/etc/shadow"`,
		`type=CWD msg=audit(1721721600.123:42): cwd="/home/mario"`,
		`type=PATH msg=audit(1721721600.123:42): item=0 name="/etc/shadow" inode=123 dev=08:01 mode=0100640`,
		`type=EOE msg=audit(1721721600.123:42):`,
	}

	records := make([]Record, 0, len(lines))
	for _, line := range lines {
		records = append(records, mustParseRecord(t, line))
	}

	got := BuildEvent(records)
	want := Event{
		ID:   "1721721600.123:42",
		Key:  "privileged",
		Res:  "yes",
		AUID: "1000",
		UID:  "0",
		EUID: "0",
		GID:  "0",
		EGID: "0",
		Ses:  "3",
		PID:  "200",
		PPID: "100",
		Arch: "c000003e",
		SC:   "59",
		Exe:  "/usr/bin/sudo",
		Cmd:  "sudo cat /etc/shadow",
		CWD:  "/home/mario",
		Path: "/etc/shadow",
		TTY:  "pts0",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("event mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestBuildEventReconstructsFragmentedAndHexExecArgs(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1721721603.000:45): syscall=59`,
		`type=EXECVE msg=audit(1721721603.000:45): argc=3 a0="tool" a1_len=9 a1[0]="very " a1[1]="long" a2=2F6574632F736861646F77`,
	}
	records := make([]Record, 0, len(lines))
	for _, line := range lines {
		records = append(records, mustParseRecord(t, line))
	}

	if got, want := BuildEvent(records).Cmd, "tool very long /etc/shadow"; got != want {
		t.Fatalf("cmd = %q, want %q", got, want)
	}
}

func TestBuildEventOrdersPathsByItem(t *testing.T) {
	lines := []string{
		`type=PATH msg=audit(1721721604.000:46): item=1 name="/second"`,
		`type=PATH msg=audit(1721721604.000:46): item=0 name="/first"`,
	}
	records := make([]Record, 0, len(lines))
	for _, line := range lines {
		records = append(records, mustParseRecord(t, line))
	}

	if got, want := BuildEvent(records).Paths, []string{"/first", "/second"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %#v, want %#v", got, want)
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

func FuzzParseRecordDoesNotPanic(f *testing.F) {
	f.Add(`type=SYSCALL msg=audit(1721721600.123:42): syscall=59 exe="/usr/bin/true"`)
	f.Add(`type=USER_AUTH msg=audit(1721721601.456:43): msg='op=PAM:authentication res=failed'`)
	f.Add(`type=TEST msg=audit(1.0:1): value="unterminated`)
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = ParseRecord(line)
	})
}
