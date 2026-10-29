package audit

import (
	"strings"
	"time"
)

// RejectPhysicalLine uses only a complete parsed envelope when available. If
// correlation itself is missing/unsafe, all unresolved groups are potentially
// affected; conservatively fence assembly until untracked input expires instead of joining
// untrustworthy tails. The retained prefix is emitted separately by the caller.
func (a *Assembler) RejectPhysicalLine(prefix string, source SourcePosition, now time.Time) []AssembledEvent {
	end := strings.Index(prefix, "):")
	var record Record
	var err error
	if end >= 0 {
		record, err = ParseRecord(prefix[:end+2])
	}
	if end < 0 || err != nil || record.ID == "" {
		events := a.FlushAllWith(CompletionLineLimit)
		for i := range events {
			events[i].Exceptional = true
		}
		a.startSpill(now, source)
		return events
	}
	key := correlationKey{record.ID, record.Node, record.NodePresent}
	var events []AssembledEvent
	if _, exists := a.pending[key]; exists {
		event := a.finish(key, CompletionLineLimit, false).event
		event.Exceptional = true
		events = append(events, event)
		if len(event.Records) > 0 {
			source = event.Records[0].Source
		}
	}
	if r := a.rejected[key]; r != nil {
		r.lastSeen = now
		return events
	}
	size := len(key.ID) + len(key.Node)
	if len(a.rejected) < a.limits.MaxPendingEvents && size <= a.limits.MaxPendingBytes-a.rejectionBytes {
		if a.rejected == nil {
			a.rejected = make(map[correlationKey]*rejectedEvent)
		}
		a.rejected[key] = &rejectedEvent{source: source, lastSeen: now, keyBytes: size}
		a.rejectionBytes += size
	} else {
		a.startSpill(now, source)
	}
	return events
}

// Rejected keys retain no record payload. Their replay barrier prevents a
// restart in the middle of exceptional evidence from manufacturing a complete
// suffix event. They expire on inactivity or close on a physical terminator.
type rejectedEvent struct {
	source   SourcePosition
	lastSeen time.Time
	keyBytes int
}

func (a *Assembler) expireRejected(now time.Time) {
	for key, r := range a.rejected {
		if a.timeout > 0 && !now.Before(r.lastSeen.Add(a.timeout)) {
			delete(a.rejected, key)
			a.rejectionBytes -= r.keyBytes
		}
	}
	if !a.spillSince.IsZero() && a.timeout > 0 && !now.Before(a.spillSince.Add(a.timeout)) {
		a.spillSince = time.Time{}
		a.spillSource = SourcePosition{}
	}
}

// AddRecovering isolates input-induced bounds. AddChecked retains its strict
// API for callers that need explicit admission testing. The collector uses this
// method and must deliver EVERY returned event before checkpoint advancement.
// A returned limit is diagnostic, not a failure to account for the record.
func (a *Assembler) AddRecovering(record Record, now time.Time) (events []AssembledEvent, diagnostic *AssemblerLimitError) {
	// Admission failure and conservative isolation bypass addAt's normal expiry.
	// Collect stale evidence first on EVERY record, and deliver it even on those
	// early-return paths. Merge using first-observed sequence, just as addAt does.
	expired := a.expired(now)
	defer func() {
		if len(expired) == 0 {
			return
		}
		for _, event := range events {
			expired = append(expired, readyEvent{sequence: event.sequence, event: event})
		}
		events = orderedEvents(expired)
	}()
	a.expireRejected(now)
	key := correlationKey{record.ID, record.Node, record.NodePresent}
	terminal := isTerminalRecord(record.Type) || record.Type == "PROCTITLE"
	pending, exists := a.pending[key]
	exceptional := func(records []Record) AssembledEvent {
		sequence := a.nextSequence
		if exists {
			sequence = pending.sequence
		} else {
			a.nextSequence++
		}
		return AssembledEvent{sequence: sequence, ID: record.ID, Records: records, Exceptional: true, Completion: CompletionAssemblyLimit}
	}
	if rejected := a.rejected[key]; rejected != nil {
		rejected.lastSeen = now
		if terminal {
			delete(a.rejected, key)
			a.rejectionBytes -= rejected.keyBytes
		}
		return []AssembledEvent{exceptional([]Record{record})}, nil
	}
	// EOE carries no event evidence. At a full payload boundary it may close the
	// group without allocating a 257th retained record or misreporting data loss.
	if exists && record.Type == "EOE" && a.limits.MaxRecordsPerEvent > 0 &&
		(len(pending.records) >= a.limits.MaxRecordsPerEvent || record.SourceBytes > a.limits.MaxPendingBytes-a.pendingBytes) {
		return orderedEvents([]readyEvent{a.finish(key, CompletionEOE, true)}), nil
	}
	// Once bounded rejected-key bookkeeping is exhausted, conservatively emit
	// unknown keys as physical-record exceptions until the untracked-input fence expires. Never
	// forget a tainted key and later normalize its tail as a complete event.
	if !exists && !a.spillSince.IsZero() {
		// A terminal record introduces no unresolved tail. If metadata room
		// has recovered, track nonterminal keys individually instead of
		// renewing a global fence for unrelated input. Pin those keys to the
		// original spill boundary so a restart can replay their full prefix.
		if !terminal {
			keyBytes := len(key.ID) + len(key.Node)
			if len(a.rejected) < a.limits.MaxPendingEvents && keyBytes <= a.limits.MaxPendingBytes-a.rejectionBytes {
				if a.rejected == nil {
					a.rejected = make(map[correlationKey]*rejectedEvent)
				}
				a.rejected[key] = &rejectedEvent{source: a.spillSource, lastSeen: now, keyBytes: keyBytes}
				a.rejectionBytes += keyBytes
			} else {
				// Only genuinely untracked, unresolved input extends this fence.
				a.startSpill(now, record.Source)
			}
		}
		return []AssembledEvent{exceptional([]Record{record})}, nil
	}
	events, err := a.AddCheckedAt(record, now)
	if err == nil {
		return events, nil
	}
	limit := err.(*AssemblerLimitError)
	records := []Record(nil)
	if exists {
		records = a.finish(key, CompletionAssemblyLimit, false).event.Records
	}
	records = append(records, record)
	if !terminal {
		keyBytes := len(key.ID) + len(key.Node)
		if len(a.rejected) < a.limits.MaxPendingEvents && keyBytes <= a.limits.MaxPendingBytes-a.rejectionBytes {
			if a.rejected == nil {
				a.rejected = make(map[correlationKey]*rejectedEvent)
			}
			source := record.Source
			if len(records) > 0 {
				source = records[0].Source
			}
			a.rejected[key] = &rejectedEvent{source: source, lastSeen: now, keyBytes: keyBytes}
			a.rejectionBytes += keyBytes
		} else {
			a.startSpill(now, records[0].Source)
		}
	}
	return []AssembledEvent{exceptional(records)}, limit
}

// RejectionTracking reports bounded exceptional-key state for diagnostics and
// resource tests; payload limits and rejection metadata budgets are separate.
func (a *Assembler) RejectionTracking() (int, int, bool) {
	return len(a.rejected), a.rejectionBytes, !a.spillSince.IsZero()
}

func (a *Assembler) startSpill(now time.Time, source SourcePosition) {
	if a.spillSince.IsZero() || (source.Valid && (!a.spillSource.Valid || sourcePositionBefore(source, a.spillSource))) {
		a.spillSource = source
	}
	a.spillSince = now
}
