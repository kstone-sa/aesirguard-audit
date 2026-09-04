package audit

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func FuzzAssemblerPreservesAcceptedRecords(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Add([]byte{3, 7, 11, 15, 0, 4, 8, 12})
	f.Add([]byte("interleaved audit records"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 512 {
			input = input[:512]
		}
		assembler, err := NewBoundedAssembler(time.Hour, AssemblerLimits{
			MaxPendingEvents:   4,
			MaxRecordsPerEvent: len(input) + 1,
			MaxPendingBytes:    len(input) + 1,
		})
		if err != nil {
			t.Fatal(err)
		}

		active := [4]bool{}
		accepted := 0
		emittedRecords := 0
		observedAt := time.Unix(1, 0)
		for index, value := range input {
			eventIndex := int(value % 4)
			recordType := []string{"SYSCALL", "PATH", "PROCTITLE", "EOE"}[int(value/4)%4]
			if recordType == "EOE" && !active[eventIndex] {
				recordType = "PATH"
			}
			record := Record{
				Type:        recordType,
				ID:          fmt.Sprintf("1721723000.000:%d", eventIndex),
				SourceBytes: 1,
			}
			events, err := assembler.AddCheckedAt(record, observedAt.Add(time.Duration(index)))
			if err != nil {
				t.Fatalf("record %d rejected despite sized limits: %v", index, err)
			}
			accepted++
			if recordType == "EOE" {
				active[eventIndex] = false
			} else {
				active[eventIndex] = true
			}
			for _, event := range events {
				emittedRecords += len(event.Records)
			}
		}
		for _, event := range assembler.FlushAll() {
			emittedRecords += len(event.Records)
		}
		if emittedRecords != accepted {
			t.Fatalf("emitted %d of %d accepted records", emittedRecords, accepted)
		}
		if assembler.Pending() != 0 || assembler.PendingBytes() != 0 {
			t.Fatalf("state retained after flush: events=%d bytes=%d", assembler.Pending(), assembler.PendingBytes())
		}
	})
}

func TestSyntheticInterleavingIsDeterministicAndLossless(t *testing.T) {
	records := make([]Record, 0, 256)
	for serial := 0; serial < 64; serial++ {
		id := fmt.Sprintf("1721723100.000:%d", serial)
		records = append(records,
			Record{Type: "PROCTITLE", ID: id, SourceBytes: 1},
			Record{Type: "PATH", ID: id, SourceBytes: 1},
			Record{Type: "SYSCALL", ID: id, SourceBytes: 1},
		)
	}
	for serial := 63; serial >= 0; serial-- {
		records = append(records, Record{Type: "EOE", ID: fmt.Sprintf("1721723100.000:%d", serial), SourceBytes: 1})
	}

	first := assembleSynthetic(t, records)
	second := assembleSynthetic(t, records)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("identical synthetic input produced different assembly")
	}
	seen := make(map[string]int, 64)
	for _, event := range first {
		seen[event.ID] += len(event.Records)
	}
	if len(seen) != 64 {
		t.Fatalf("assembled %d logical events, want 64", len(seen))
	}
	for id, count := range seen {
		if count != 4 {
			t.Fatalf("event %s contains %d records, want 4", id, count)
		}
	}
}

func assembleSynthetic(t *testing.T, records []Record) []AssembledEvent {
	t.Helper()
	assembler, err := NewBoundedAssembler(time.Hour, AssemblerLimits{
		MaxPendingEvents: 64, MaxRecordsPerEvent: 4, MaxPendingBytes: len(records),
	})
	if err != nil {
		t.Fatal(err)
	}
	var events []AssembledEvent
	for _, record := range records {
		ready, err := assembler.AddChecked(record)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, ready...)
	}
	events = append(events, assembler.FlushAll()...)
	return events
}

func TestCanonicalEventReconstructsLargeFragmentedExecve(t *testing.T) {
	var line strings.Builder
	line.WriteString(`type=EXECVE msg=audit(1721723200.000:1): argc=257 a0="tool"`)
	for index := 0; index < 256; index++ {
		fmt.Fprintf(&line, ` a1[%d]="%02x"`, index, index)
	}
	record := mustParseRecord(t, line.String())
	event := BuildCanonicalEvent(AssembledEvent{
		ID: record.ID, Records: []Record{record}, Complete: true, Completion: CompletionEOE,
	}, CanonicalOptions{})
	if event.Process == nil || len(event.Process.Argv) != 2 {
		t.Fatalf("process = %#v", event.Process)
	}
	var want strings.Builder
	for index := 0; index < 256; index++ {
		fmt.Fprintf(&want, "%02x", index)
	}
	if event.Process.Argv[0] != "tool" || event.Process.Argv[1] != want.String() {
		t.Fatal("fragmented argument was not reconstructed exactly")
	}
}

func BenchmarkAuditPipeline(b *testing.B) {
	lines := []string{
		`type=SYSCALL msg=audit(1721723300.000:1): arch=c000003e syscall=59 success=yes exit=0 auid=1000 euid=0 pid=200 exe="/usr/bin/sudo" AUID="analyst" EUID="root" SYSCALL="execve"`,
		`type=EXECVE msg=audit(1721723300.000:1): argc=3 a0="sudo" a1="cat" a2="/etc/shadow"`,
		`type=CWD msg=audit(1721723300.000:1): cwd="/home/analyst"`,
		`type=PATH msg=audit(1721723300.000:1): item=0 name="/etc/shadow" nametype=NORMAL`,
		`type=PROCTITLE msg=audit(1721723300.000:1): proctitle=7375646F00636174002F6574632F736861646F7700`,
		`type=EOE msg=audit(1721723300.000:1):`,
	}
	bytesPerEvent := 0
	for _, line := range lines {
		bytesPerEvent += len(line) + 1
	}
	b.ReportAllocs()
	b.SetBytes(int64(bytesPerEvent))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		assembler := NewAssembler(0)
		for _, line := range lines {
			record, err := ParseRecord(line)
			if err != nil {
				b.Fatal(err)
			}
			for _, assembled := range assembler.Add(record) {
				event := WithHumanMessage(BuildCanonicalEvent(assembled, CanonicalOptions{}))
				if _, err := json.Marshal(event); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
}
