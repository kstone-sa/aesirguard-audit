package main

import (
	"encoding/json"
	"io"
	"time"
)

type operationCounters struct {
	InputLines       uint64 `json:"input_lines"`
	InputBytes       uint64 `json:"input_bytes"`
	EmittedEvents    uint64 `json:"emitted_events"`
	ParseFailures    uint64 `json:"parse_failures"`
	ReplayCandidates uint64 `json:"replay_candidates"`
	Gaps             uint64 `json:"gaps"`
	Rotations        uint64 `json:"rotations"`
}

type operationalDiagnostics struct {
	encoder           *json.Encoder
	started           time.Time
	heartbeatInterval time.Duration
	nextHeartbeat     time.Time
	counters          operationCounters
}

func newOperationalDiagnostics(writer io.Writer, heartbeatInterval time.Duration) *operationalDiagnostics {
	now := time.Now()
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return &operationalDiagnostics{
		encoder: encoder, started: now, heartbeatInterval: heartbeatInterval,
		nextHeartbeat: now.Add(heartbeatInterval),
	}
}

func (diagnostics *operationalDiagnostics) log(level, event string, fields map[string]any) {
	record := make(map[string]any, len(fields)+3)
	record["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	record["level"] = level
	record["event"] = event
	for key, value := range fields {
		record[key] = value
	}
	_ = diagnostics.encoder.Encode(record)
}

func (diagnostics *operationalDiagnostics) heartbeat(processor *eventProcessor, lagBytes int64) {
	diagnostics.nextHeartbeat = time.Now().Add(diagnostics.heartbeatInterval)
	fields := map[string]any{
		"health":          "ok",
		"uptime_seconds":  int64(time.Since(diagnostics.started).Seconds()),
		"counters":        diagnostics.counters,
		"pending_events":  processor.assembler.Pending(),
		"pending_bytes":   processor.assembler.PendingBytes(),
	}
	if lagBytes >= 0 {
		fields["input_lag_bytes"] = lagBytes
	}
	diagnostics.log("info", "heartbeat", fields)
}

func (diagnostics *operationalDiagnostics) heartbeatDue() bool {
	return diagnostics.heartbeatInterval > 0 && !time.Now().Before(diagnostics.nextHeartbeat)
}

func writeFatalDiagnostic(writer io.Writer, err error) {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"level": "error", "event": "fatal", "error": err.Error(),
	})
}
