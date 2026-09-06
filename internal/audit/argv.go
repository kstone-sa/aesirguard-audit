package audit

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type execArgument struct {
	whole     *Field
	length    *int
	fragments map[int]Field
}

func buildArguments(records []Record) ([]string, string, []CanonicalIssue) {
	args := map[int]*execArgument{}
	argc := -1
	found, valid := false, true
	var evidence []CanonicalIssue
	for ri, r := range records {
		if r.Type != "EXECVE" {
			continue
		}
		found = true
		for _, f := range r.AllFields {
			ai, part, kind, ok := parseExecArgKey(f.Key)
			if f.Key != "argc" && !ok {
				continue
			}
			evidence = append(evidence, sourceFieldIssue("incomplete_argv", r, ri, f, false))
			if f.Key == "argc" {
				n, err := strconv.Atoi(f.Value)
				if err != nil || n < 0 || (argc >= 0 && argc != n) {
					valid = false
				} else {
					argc = n
				}
				continue
			}
			if ai < 0 || part < 0 {
				valid = false
				continue
			}
			a := args[ai]
			if a == nil {
				a = &execArgument{fragments: map[int]Field{}}
				args[ai] = a
			}
			switch kind {
			case execArgLength:
				n, err := strconv.Atoi(f.Value)
				if err != nil || n < 0 || (a.length != nil && *a.length != n) {
					valid = false
				} else {
					a.length = &n
				}
			case execArgWhole:
				if a.whole != nil && (a.whole.Value != f.Value || a.whole.Quoted != f.Quoted) {
					valid = false
				}
				copy := f
				a.whole = &copy
			case execArgFragment:
				if old, ok := a.fragments[part]; ok && (old.Value != f.Value || old.Quoted != f.Quoted) {
					valid = false
				}
				a.fragments[part] = f
			}
		}
	}
	if found {
		// Never allocate according to untrusted argc or an argument/fragment index.
		if argc != len(args) {
			valid = false
		}
		indexes := make([]int, 0, len(args))
		for i := range args {
			indexes = append(indexes, i)
		}
		sort.Ints(indexes)
		argv := make([]string, 0, len(args))
		for pos, index := range indexes {
			if pos != index {
				valid = false
			}
			value, ok := args[index].decode()
			if !ok || !utf8.ValidString(value) {
				valid = false
			}
			argv = append(argv, value)
		}
		if valid {
			return argv, "execve", nil
		}
		if len(evidence) == 0 {
			evidence = append(evidence, CanonicalIssue{Code: "incomplete_argv", RecordType: "EXECVE", Field: "argc"})
		}
		return nil, "execve", evidence
	}
	for ri, r := range records {
		if r.Type != "PROCTITLE" {
			continue
		}
		for _, f := range r.AllFields {
			if f.Key != "proctitle" {
				continue
			}
			value, ok := untrustedString(f, true)
			if !ok || !utf8.ValidString(value) {
				return nil, "proctitle", []CanonicalIssue{sourceFieldIssue("invalid_proctitle", r, ri, f, false)}
			}
			parts := strings.Split(value, "\x00")
			if len(parts) > 1 && parts[len(parts)-1] == "" {
				parts = parts[:len(parts)-1]
			}
			return parts, "proctitle", nil
		}
	}
	return nil, "", nil
}

func (arg *execArgument) decode() (string, bool) {
	if arg.whole != nil {
		if len(arg.fragments) > 0 || arg.length != nil {
			return "", false
		}
		return untrustedString(*arg.whole, true)
	}
	if len(arg.fragments) == 0 || arg.length == nil {
		return "", false
	}
	parts := make([]int, 0, len(arg.fragments))
	for p := range arg.fragments {
		parts = append(parts, p)
	}
	sort.Ints(parts)
	var b strings.Builder
	encodedLength := 0
	for pos, p := range parts {
		if pos != p {
			return "", false
		}
		f := arg.fragments[p]
		value, ok := untrustedString(f, true)
		if !ok {
			return "", false
		}
		b.WriteString(value)
		encodedLength += len(f.Value)
	}
	// Kernel aN_len counts encoded hex characters for hex fragments, and
	// literal bytes excluding quotes for quoted fragments.
	return b.String(), encodedLength == *arg.length
}
