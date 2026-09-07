package audit

// Singleton conflicts are scoped to a record except process/identity fields
// that the canonical event otherwise selects across records. PATH ownership and
// security context remain record-local; distinct decisions keep their existing
// record-aware selection and additional-evidence reporting.
func singletonField(key string) bool {
	switch key {
	case "auid", "AUID", "uid", "UID", "euid", "EUID", "pid", "ppid", "comm", "exe", "cwd", "tty", "exit", "arch", "ARCH", "syscall", "SYSCALL",
		"acct", "addr", "hostname", "terminal", "name", "nametype", "item", "ouid", "OUID", "ogid", "OGID", "cap_fp", "cap_fi", "cap_fe",
		"decision", "apparmor", "scontext", "subj", "tcontext", "tclass", "profile", "permissive", "code", "sig", "ip", "compat", "op", "operation", "unit", "service", "reason":
		return true
	}
	return false
}

func eventSingleton(key string) bool {
	switch key {
	case "auid", "AUID", "uid", "UID", "euid", "EUID", "pid", "ppid", "comm", "exe", "cwd", "tty", "exit", "arch", "ARCH", "syscall", "SYSCALL", "acct", "addr", "hostname", "terminal", "unit", "service", "reason", "op", "operation":
		return true
	}
	return false
}

func markSingletonConflicts(records []Record) []CanonicalIssue {
	globalFirst := map[string]string{}
	globalSeen := map[string]bool{}
	globalConflict := map[string]bool{}
	for i := range records {
		r := &records[i]
		r.Conflicts = map[string]bool{}
		first, seen := map[string]string{}, map[string]bool{}
		for _, values := range []map[string][]string{r.Values, r.EmbeddedValues} {
			for key, entries := range values {
				if !singletonField(key) {
					continue
				}
				for _, value := range entries {
					if seen[key] && first[key] != value {
						r.Conflicts[key] = true
					}
					first[key], seen[key] = value, true
					if eventSingleton(key) {
						if globalSeen[key] && globalFirst[key] != value {
							globalConflict[key] = true
						}
						globalFirst[key], globalSeen[key] = value, true
					}
				}
			}
		}
		for _, pair := range [][2]string{{"decision", "apparmor"}, {"scontext", "subj"}, {"op", "operation"}} {
			if seen[pair[0]] && seen[pair[1]] && first[pair[0]] != first[pair[1]] {
				r.Conflicts[pair[0]], r.Conflicts[pair[1]] = true, true
			}
		}

	}
	var issues []CanonicalIssue
	for i := range records {
		r := &records[i]
		for key := range globalConflict {
			r.Conflicts[key] = true
		}
		// An ambiguous identity must not reappear through its interpreted alias.
		for _, pair := range [][2]string{{"auid", "AUID"}, {"uid", "UID"}, {"euid", "EUID"}, {"ouid", "OUID"}, {"ogid", "OGID"}, {"arch", "ARCH"}, {"syscall", "SYSCALL"}} {
			if r.Conflicts[pair[0]] || r.Conflicts[pair[1]] {
				r.Conflicts[pair[0]], r.Conflicts[pair[1]] = true, true
			}
		}
		for _, section := range []struct {
			fields   []Field
			embedded bool
		}{{r.AllFields, false}, {r.EmbeddedAllFields, true}} {
			for _, f := range section.fields {
				if r.Conflicts[f.Key] {
					issues = append(issues, sourceFieldIssue("conflicting_singleton", *r, i, f, section.embedded))
				}
			}
		}
	}
	return issues
}
