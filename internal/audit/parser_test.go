package audit

import (
	"reflect"
	"testing"
)

func TestParseRecord(t *testing.T) {
	line := `type=SYSCALL msg=audit(1721721600.123:42): arch=c000003e syscall=59 success=yes exit=0 a0=55 auid=1000 uid=0 euid=0 gid=0 egid=0 tty=pts0 ses=3 pid=200 ppid=100 exe="/usr/bin/sudo" key="privileged"`

	r, err := ParseRecord(line)
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "SYSCALL" {
		t.Fatalf("type = %q", r.Type)
	}
	if r.ID != "1721721600.123:42" {
		t.Fatalf("id = %q", r.ID)
	}
	if r.Fields["exe"] != "/usr/bin/sudo" {
		t.Fatalf("exe = %q", r.Fields["exe"])
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
		r, err := ParseRecord(line)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
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
