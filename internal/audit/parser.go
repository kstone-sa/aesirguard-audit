package audit

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Record is one raw auditd record parsed into key/value fields.
type Record struct {
	Type   string
	ID     string
	Fields map[string]string
}

// Event is the compact JSON representation emitted by audit2json.
type Event struct {
	ID    string   `json:"id"`
	Key   string   `json:"key,omitempty"`
	Type  string   `json:"type,omitempty"`
	Res   string   `json:"res,omitempty"`
	AUID  string   `json:"auid,omitempty"`
	UID   string   `json:"uid,omitempty"`
	EUID  string   `json:"euid,omitempty"`
	GID   string   `json:"gid,omitempty"`
	EGID  string   `json:"egid,omitempty"`
	Ses   string   `json:"ses,omitempty"`
	PID   string   `json:"pid,omitempty"`
	PPID  string   `json:"ppid,omitempty"`
	Arch  string   `json:"arch,omitempty"`
	SC    string   `json:"sc,omitempty"`
	Exe   string   `json:"exe,omitempty"`
	Cmd   string   `json:"cmd,omitempty"`
	CWD   string   `json:"cwd,omitempty"`
	Path  string   `json:"path,omitempty"`
	Paths []string `json:"paths,omitempty"`
	TTY   string   `json:"tty,omitempty"`
}

// ParseRecord parses one auditd line without depending on libauparse.
func ParseRecord(line string) (Record, error) {
	fields, err := parseFields(line)
	if err != nil {
		return Record{}, err
	}

	r := Record{Fields: fields, Type: fields["type"]}
	msg := fields["msg"]
	start := strings.Index(msg, "audit(")
	end := strings.Index(msg, ")")
	if start >= 0 && end > start+6 {
		r.ID = msg[start+6 : end]
	}
	if r.ID == "" {
		return Record{}, fmt.Errorf("audit id not found")
	}
	return r, nil
}

// BuildEvent merges all records sharing one audit ID into one compact event.
func BuildEvent(records []Record) Event {
	e := Event{}
	var argv map[int]string
	var paths []string

	for _, r := range records {
		if e.ID == "" {
			e.ID = r.ID
		}
		f := r.Fields
		set := func(dst *string, key string) {
			if *dst == "" && f[key] != "" {
				*dst = f[key]
			}
		}

		set(&e.Key, "key")
		set(&e.AUID, "auid")
		set(&e.UID, "uid")
		set(&e.EUID, "euid")
		set(&e.GID, "gid")
		set(&e.EGID, "egid")
		set(&e.Ses, "ses")
		set(&e.PID, "pid")
		set(&e.PPID, "ppid")
		set(&e.Arch, "arch")
		set(&e.SC, "syscall")
		set(&e.Exe, "exe")
		set(&e.CWD, "cwd")
		set(&e.TTY, "tty")

		if e.Res == "" {
			if f["success"] != "" {
				e.Res = f["success"]
			} else if f["res"] != "" {
				e.Res = f["res"]
			}
		}

		switch r.Type {
		case "EXECVE":
			if argv == nil {
				argv = map[int]string{}
			}
			for k, v := range f {
				var n int
				if _, err := fmt.Sscanf(k, "a%d", &n); err == nil {
					argv[n] = v
				}
			}
		case "PROCTITLE":
			if e.Cmd == "" {
				e.Cmd = decodeProctitle(f["proctitle"])
			}
		case "PATH":
			if f["name"] != "" {
				paths = append(paths, f["name"])
			}
		}
	}

	if len(argv) > 0 {
		idx := make([]int, 0, len(argv))
		for n := range argv {
			idx = append(idx, n)
		}
		sort.Ints(idx)
		parts := make([]string, 0, len(idx))
		for _, n := range idx {
			parts = append(parts, argv[n])
		}
		e.Cmd = strings.Join(parts, " ")
	}

	paths = unique(paths)
	if len(paths) == 1 {
		e.Path = paths[0]
	} else if len(paths) > 1 {
		e.Paths = paths
	}
	if e.Key == "" && len(records) > 0 {
		e.Type = records[0].Type
	}
	return e
}

func parseFields(line string) (map[string]string, error) {
	out := map[string]string{}
	for i := 0; i < len(line); {
		for i < len(line) && line[i] == ' ' {
			i++
		}
		if i >= len(line) {
			break
		}
		ks := i
		for i < len(line) && line[i] != '=' && line[i] != ' ' {
			i++
		}
		if i >= len(line) || line[i] != '=' {
			for i < len(line) && line[i] != ' ' {
				i++
			}
			continue
		}
		key := line[ks:i]
		i++
		if i >= len(line) {
			out[key] = ""
			break
		}
		var val string
		if line[i] == '"' || line[i] == '\'' {
			quote := line[i]
			i++
			vs := i
			for i < len(line) && line[i] != quote {
				i++
			}
			val = line[vs:i]
			if i < len(line) {
				i++
			}
		} else {
			vs := i
			for i < len(line) && line[i] != ' ' {
				i++
			}
			val = line[vs:i]
		}
		out[key] = val
	}
	return out, nil
}

func decodeProctitle(v string) string {
	b, err := hex.DecodeString(v)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
