package audit

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Assembler groups interleaved records and emits deterministic logical events.
type Assembler struct {
	timeout         time.Duration
	pending         map[string]*pendingEvent
	nextSequence    uint64
	latestAuditTime time.Time
}

type pendingEvent struct {
	records    []Record
	sequence   uint64
	lastSeen   time.Time
	auditTime  time.Time
	hasAuditTS bool
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
)

// AssembledEvent retains the physical records and their event boundary.
// Normalizers decide how those records are represented in an output schema.
type AssembledEvent struct {
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
		pending: make(map[string]*pendingEvent),
	}
}

// Add adds a record using the current time for inactivity tracking.
func (assembler *Assembler) Add(record Record) []AssembledEvent {
	return assembler.AddAt(record, time.Now())
}

// AddAt adds a record using an explicit observation time for deterministic tests.
func (assembler *Assembler) AddAt(record Record, observedAt time.Time) []AssembledEvent {
	ready := make([]readyEvent, 0, 2)
	pending, exists := assembler.pending[record.ID]

	// An EOE without cached records contains no event data. This also consumes
	// EOE records that arrive after a PROCTITLE-triggered completion.
	if record.Type != "EOE" || exists {
		if !exists {
			pending = &pendingEvent{sequence: assembler.nextSequence}
			assembler.nextSequence++
			if auditTime, ok := auditTimeFromID(record.ID); ok {
				pending.auditTime = auditTime
				pending.hasAuditTS = true
				if auditTime.After(assembler.latestAuditTime) {
					assembler.latestAuditTime = auditTime
				}
			}
			assembler.pending[record.ID] = pending
		}
		pending.records = append(pending.records, record)
		pending.lastSeen = observedAt

		if isTerminalRecord(record.Type) {
			ready = append(ready, assembler.finish(record.ID, terminalCompletion(record.Type), true))
		}
	}

	ready = append(ready, assembler.expired(observedAt)...)
	return orderedEvents(ready)
}

// FlushExpired emits events whose watermark or inactivity timeout has elapsed.
func (assembler *Assembler) FlushExpired(now time.Time) []AssembledEvent {
	return orderedEvents(assembler.expired(now))
}

// FlushAll emits all pending events in first-observed order.
func (assembler *Assembler) FlushAll() []AssembledEvent {
	ready := make([]readyEvent, 0, len(assembler.pending))
	for id := range assembler.pending {
		ready = append(ready, assembler.finish(id, CompletionEOF, false))
	}
	return orderedEvents(ready)
}

// Pending returns the number of incomplete logical events.
func (assembler *Assembler) Pending() int {
	return len(assembler.pending)
}

func (assembler *Assembler) finish(id string, completion Completion, complete bool) readyEvent {
	pending := assembler.pending[id]
	delete(assembler.pending, id)
	return readyEvent{
		sequence: pending.sequence,
		event: AssembledEvent{
			ID:         id,
			Records:    pending.records,
			Complete:   complete,
			Completion: completion,
		},
	}
}

func (assembler *Assembler) expired(now time.Time) []readyEvent {
	if assembler.timeout <= 0 {
		return nil
	}
	ids := make([]string, 0)
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
		ready = append(ready, assembler.finish(id, completion, false))
	}
	return ready
}

func isTerminalRecord(recordType string) bool {
	return recordType == "EOE" || recordType == "PROCTITLE" || recordType == "KERNEL"
}

func terminalCompletion(recordType string) Completion {
	switch recordType {
	case "EOE":
		return CompletionEOE
	case "PROCTITLE":
		return CompletionProctitle
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
	if colon <= 0 {
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
	return time.Unix(seconds, nanoseconds).UTC(), true
}
