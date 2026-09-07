package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Assembler groups interleaved records and emits deterministic logical events.
type Assembler struct {
	timeout           time.Duration
	limits            AssemblerLimits
	pending           map[correlationKey]*pendingEvent
	pendingBytes      int
	nextSequence      uint64
	latestAuditTime   time.Time
	latestAuditNode   string
	latestNodePresent bool
}

type correlationKey struct {
	ID, Node    string
	NodePresent bool
}

type pendingEvent struct {
	mixedNode  bool
	records    []Record
	sequence   uint64
	lastSeen   time.Time
	auditTime  time.Time
	hasAuditTS bool
}

// AssemblerLimits bounds unresolved event state. Every value must be positive
// when limits are enabled.
type AssemblerLimits struct {
	MaxPendingEvents   int
	MaxRecordsPerEvent int
	MaxPendingBytes    int
}

// AssemblerLimitError reports a record that could not be retained without
// exceeding a configured memory bound.
type AssemblerLimitError struct {
	Limit string
	Value int
}

func (err *AssemblerLimitError) Error() string {
	return fmt.Sprintf("assembler %s limit reached (%d)", err.Limit, err.Value)
}

// Completion describes why an assembled event was emitted.
type Completion string

const (
	CompletionEOE          Completion = "eoe"
	CompletionProctitle    Completion = "proctitle"
	CompletionSingleRecord Completion = "single_record"
	CompletionWatermark    Completion = "watermark"
	CompletionTimeout      Completion = "timeout"
	CompletionEOF          Completion = "eof"
	CompletionShutdown     Completion = "shutdown"
)

// AssembledEvent retains the physical records and their event boundary.
// Normalizers decide how those records are represented in an output schema.
type AssembledEvent struct {
	MixedNode  bool
	ID         string
	Records    []Record
	Complete   bool
	Completion Completion
}

type readyEvent struct {
	sequence uint64
	event    AssembledEvent
}

// NewAssembler creates an event assembler. A zero timeout disables expiry.
func NewAssembler(timeout time.Duration) *Assembler {
	return &Assembler{
		timeout: timeout,
		pending: make(map[correlationKey]*pendingEvent),
	}
}

// NewBoundedAssembler creates an assembler with explicit unresolved-state
// limits for long-running collection.
func NewBoundedAssembler(timeout time.Duration, limits AssemblerLimits) (*Assembler, error) {
	if limits.MaxPendingEvents <= 0 || limits.MaxRecordsPerEvent <= 0 || limits.MaxPendingBytes <= 0 {
		return nil, fmt.Errorf("assembler limits must be positive")
	}
	assembler := NewAssembler(timeout)
	assembler.limits = limits
	return assembler, nil
}

// Add adds a record using the current time for inactivity tracking.
func (assembler *Assembler) Add(record Record) []AssembledEvent {
	events, _ := assembler.addAt(record, time.Now())
	return events
}

// AddAt adds a record using an explicit observation time for deterministic tests.
func (assembler *Assembler) AddAt(record Record, observedAt time.Time) []AssembledEvent {
	events, _ := assembler.addAt(record, observedAt)
	return events
}

// AddChecked adds a record and reports configured state-limit violations.
func (assembler *Assembler) AddChecked(record Record) ([]AssembledEvent, error) {
	return assembler.addAt(record, time.Now())
}

// AddCheckedAt is AddChecked with an explicit observation time.
func (assembler *Assembler) AddCheckedAt(record Record, observedAt time.Time) ([]AssembledEvent, error) {
	return assembler.addAt(record, observedAt)
}

func (assembler *Assembler) addAt(record Record, observedAt time.Time) ([]AssembledEvent, error) {
	ready := make([]readyEvent, 0, 2)
	key := correlationKey{record.ID, record.Node, record.NodePresent}
	pending, exists := assembler.pending[key]
	mixed := false
	for otherKey, other := range assembler.pending {
		if otherKey.ID == key.ID && otherKey.NodePresent != key.NodePresent {
			other.mixedNode = true
			mixed = true
		}
	}

	// An EOE without cached records contains no event data.
	if record.Type != "EOE" || exists {
		if err := assembler.checkLimits(record, pending, exists); err != nil {
			return nil, err
		}
		if !exists {
			pending = &pendingEvent{sequence: assembler.nextSequence, mixedNode: mixed}
			assembler.nextSequence++
			if auditTime, ok := auditTimeFromID(record.ID); ok {
				pending.auditTime = auditTime
				pending.hasAuditTS = true
				assembler.observeAuditTime(auditTime, key)
			}
			assembler.pending[key] = pending
		}
		pending.records = append(pending.records, record)
		assembler.pendingBytes += record.SourceBytes
		pending.lastSeen = observedAt

		// auditd.conf(5) defines PROCTITLE as the last event record. It
		// closes only an already pending correlation key, never a standalone
		// context record. A following EOE is harmless and carries no data.
		if record.Type == "PROCTITLE" && exists {
			ready = append(ready, assembler.finish(key, CompletionProctitle, true))
		} else if isTerminalRecord(record.Type) {
			ready = append(ready, assembler.finish(key, terminalCompletion(record.Type), true))
		}
	}

	ready = append(ready, assembler.expired(observedAt)...)
	return orderedEvents(ready), nil
}

// FlushExpired emits events whose watermark or inactivity timeout has elapsed.
func (assembler *Assembler) FlushExpired(now time.Time) []AssembledEvent {
	return orderedEvents(assembler.expired(now))
}

// FlushAll emits all pending events in first-observed order.
func (assembler *Assembler) FlushAll() []AssembledEvent {
	return assembler.FlushAllWith(CompletionEOF)
}

// FlushAllWith emits all pending events with the supplied incomplete boundary.
func (assembler *Assembler) FlushAllWith(completion Completion) []AssembledEvent {
	ready := make([]readyEvent, 0, len(assembler.pending))
	for id := range assembler.pending {
		ready = append(ready, assembler.finish(id, completion, false))
	}
	return orderedEvents(ready)
}

// Pending returns the number of incomplete logical events.
func (assembler *Assembler) Pending() int {
	return len(assembler.pending)
}

// PendingBytes returns source bytes retained by unresolved events.
func (assembler *Assembler) PendingBytes() int {
	return assembler.pendingBytes
}

// SafeSourcePosition returns the earliest unresolved source line or fallback
// when every line through fallback can be replayed from its end offset.
func (assembler *Assembler) SafeSourcePosition(fallback SourcePosition) SourcePosition {
	safe := fallback
	for _, pending := range assembler.pending {
		for _, record := range pending.records {
			if !record.Source.Valid {
				continue
			}
			candidate := record.Source
			candidate.End = candidate.Start
			if !safe.Valid || sourcePositionBefore(candidate, safe) {
				safe = candidate
			}
		}
	}
	return safe
}

func sourcePositionBefore(left, right SourcePosition) bool {
	if left.Generation != right.Generation {
		return left.Generation < right.Generation
	}
	return left.Start < right.Start
}

func (assembler *Assembler) finish(id correlationKey, completion Completion, complete bool) readyEvent {
	pending := assembler.pending[id]
	delete(assembler.pending, id)
	for _, record := range pending.records {
		assembler.pendingBytes -= record.SourceBytes
	}
	return readyEvent{
		sequence: pending.sequence,
		event: AssembledEvent{
			ID:         id.ID,
			MixedNode:  pending.mixedNode,
			Records:    pending.records,
			Complete:   complete,
			Completion: completion,
		},
	}
}

func (assembler *Assembler) checkLimits(record Record, pending *pendingEvent, exists bool) error {
	if assembler.limits.MaxPendingEvents == 0 {
		return nil
	}
	if !exists && len(assembler.pending) >= assembler.limits.MaxPendingEvents {
		return &AssemblerLimitError{Limit: "pending events", Value: assembler.limits.MaxPendingEvents}
	}
	if exists && len(pending.records) >= assembler.limits.MaxRecordsPerEvent {
		return &AssemblerLimitError{Limit: "records per event", Value: assembler.limits.MaxRecordsPerEvent}
	}
	if assembler.pendingBytes+record.SourceBytes > assembler.limits.MaxPendingBytes {
		return &AssemblerLimitError{Limit: "pending bytes", Value: assembler.limits.MaxPendingBytes}
	}
	return nil
}

// observeAuditTime confines watermark expiry to a continuous clock epoch.
// A large forward jump is not proof that pending events are old; a rollback
// outside the reorder window must not leave a permanent future watermark.
func (assembler *Assembler) observeAuditTime(timestamp time.Time, key correlationKey) {
	// Different producers need not share a clock. On a node change, keep
	// unresolved groups conservative rather than completing them by another
	// producer's time. This retains no unbounded per-node clock history.
	if !assembler.latestAuditTime.IsZero() && (key.Node != assembler.latestAuditNode || key.NodePresent != assembler.latestNodePresent) {
		for _, pending := range assembler.pending {
			pending.hasAuditTS = false
		}
		assembler.latestAuditTime = time.Time{}
	}
	assembler.latestAuditNode = key.Node
	assembler.latestNodePresent = key.NodePresent
	if !assembler.latestAuditTime.IsZero() && assembler.timeout > 0 {
		forwardWindow := time.Minute
		if assembler.timeout > forwardWindow/2 {
			forwardWindow = assembler.timeout
			// Avoid duration overflow for extreme but valid configuration values.
			if assembler.timeout <= time.Duration(1<<63-1)/2 {
				forwardWindow *= 2
			}
		}
		delta := timestamp.Sub(assembler.latestAuditTime)
		if delta > forwardWindow || delta <= -assembler.timeout {
			for _, pending := range assembler.pending {
				pending.hasAuditTS = false
			}
			assembler.latestAuditTime = timestamp
			return
		}
	}
	if timestamp.After(assembler.latestAuditTime) {
		assembler.latestAuditTime = timestamp
	}
}

func (assembler *Assembler) expired(now time.Time) []readyEvent {
	if assembler.timeout <= 0 {
		return nil
	}
	ids := make([]correlationKey, 0)
	for id, pending := range assembler.pending {
		wallExpired := !pending.lastSeen.IsZero() && !now.Before(pending.lastSeen.Add(assembler.timeout))
		watermarkExpired := pending.hasAuditTS && !assembler.latestAuditTime.Before(pending.auditTime.Add(assembler.timeout))
		if wallExpired || watermarkExpired {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		return assembler.pending[ids[i]].sequence < assembler.pending[ids[j]].sequence
	})
	ready := make([]readyEvent, 0, len(ids))
	for _, id := range ids {
		pending := assembler.pending[id]
		completion := CompletionTimeout
		if pending.hasAuditTS && !assembler.latestAuditTime.Before(pending.auditTime.Add(assembler.timeout)) {
			completion = CompletionWatermark
		}
		// Stream age is an Audit completion boundary; elapsed wall time is
		// only an inactivity bound and does not establish complete delivery.
		ready = append(ready, assembler.finish(id, completion, completion == CompletionWatermark))
	}
	return ready
}

func isTerminalRecord(recordType string) bool {
	return recordType == "EOE" || recordType == "KERNEL" || isKnownSingleRecordType(recordType)
}

func terminalCompletion(recordType string) Completion {
	switch recordType {
	case "EOE":
		return CompletionEOE
	default:
		return CompletionSingleRecord
	}
}

func orderedEvents(ready []readyEvent) []AssembledEvent {
	sort.SliceStable(ready, func(i, j int) bool {
		return ready[i].sequence < ready[j].sequence
	})
	events := make([]AssembledEvent, 0, len(ready))
	for _, item := range ready {
		events = append(events, item.event)
	}
	return events
}

func auditTimeFromID(id string) (time.Time, bool) {
	colon := strings.LastIndexByte(id, ':')
	if colon <= 0 || colon == len(id)-1 {
		return time.Time{}, false
	}
	serial := id[colon+1:]
	for _, digit := range serial {
		if digit < '0' || digit > '9' {
			return time.Time{}, false
		}
	}
	if _, err := strconv.ParseUint(serial, 10, 64); err != nil {
		return time.Time{}, false
	}
	timestamp := id[:colon]
	dot := strings.IndexByte(timestamp, '.')
	secondsText := timestamp
	fractionText := ""
	if dot >= 0 {
		secondsText = timestamp[:dot]
		fractionText = timestamp[dot+1:]
	}
	if secondsText == "" || dot >= 0 && fractionText == "" {
		return time.Time{}, false
	}
	for _, part := range []string{secondsText, fractionText} {
		for _, char := range part {
			if char < '0' || char > '9' {
				return time.Time{}, false
			}
		}
	}
	seconds, err := strconv.ParseInt(secondsText, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	if len(fractionText) > 9 {
		fractionText = fractionText[:9]
	}
	for len(fractionText) < 9 {
		fractionText += "0"
	}
	nanoseconds := int64(0)
	if fractionText != "" {
		nanoseconds, err = strconv.ParseInt(fractionText, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
	}
	timestampValue := time.Unix(seconds, nanoseconds).UTC()
	if year := timestampValue.Year(); year < 0 || year > 9999 {
		return time.Time{}, false
	}
	return timestampValue, true
}
