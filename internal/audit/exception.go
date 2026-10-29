package audit

import "fmt"

// BuildAssemblyException preserves a physical record, NOT a normalized event
// fragment. No inferred success, argv, or complete-event semantics are assigned.
// Existing v1 raw/issue fields carry reversible evidence and stable provenance.
func BuildAssemblyException(record Record, options CanonicalOptions) CanonicalEvent {
	event := BuildParseFailureEvent(record.Raw, fmt.Errorf("assembly limit: physical record evidence; logical event is incomplete"), options)
	event.Audit.ID = record.ID
	event.Event.Type = "ASSEMBLY_EXCEPTION"
	event.Event.Action = "assembly_limit"
	event.Event.Integrity = &CanonicalIntegrity{State: "incomplete", Reason: CompletionAssemblyLimit}
	event.Event.Issues = []CanonicalIssue{{Code: "assembly_limit", RecordType: record.Type}}
	if record.NodePresent {
		event.Event.Issues = append(event.Event.Issues, CanonicalIssue{Code: "audit_node", Value: record.Node})
		if options.Host == "" {
			event.Source = &CanonicalSource{Host: record.Node}
		}
	}
	if record.Source.Valid {
		event.Event.Issues = append(event.Event.Issues, CanonicalIssue{Code: "source_record", Value: fmt.Sprintf("device=%d inode=%d offset=%d bytes=%d", record.Source.Device, record.Source.Inode, record.Source.Start, record.SourceBytes)})
	}
	return event
}
