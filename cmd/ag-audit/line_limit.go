package main

import (
	"fmt"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/audit"
)

func (p *eventProcessor) rejectLine(prefix string, totalBytes int, source audit.SourcePosition) error {
	p.diagnostics.counters.InputLines++
	p.diagnostics.counters.InputBytes += uint64(totalBytes)
	p.diagnostics.counters.LineLimits++
	if err := p.diagnostics.log("error", "physical_line_limit_exceeded", map[string]any{
		"observed_bytes": totalBytes, "retained_bytes": len(prefix), "omitted_bytes": totalBytes - len(prefix), "source": source,
	}); err != nil {
		return err
	}
	if err := p.emit(p.assembler.RejectPhysicalLine(prefix, source, time.Now())); err != nil {
		return err
	}
	e := audit.BuildParseFailureEvent(prefix, fmt.Errorf("physical line exceeds byte limit; retained prefix only; omitted_bytes=%d", totalBytes-len(prefix)), p.canonical)
	e.Event.Type = "LINE_EXCEPTION"
	e.Event.Action = "line_limit"
	e.Event.Issues[0].Code = "physical_line_limit"
	e.Event.Integrity = &audit.CanonicalIntegrity{State: "incomplete", Reason: audit.CompletionLineLimit}
	return p.emitCanonical(e)
}
