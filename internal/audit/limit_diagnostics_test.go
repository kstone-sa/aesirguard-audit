package audit

import (
	"errors"
	"testing"
	"time"
)

func TestLimitDiagnosticCountsCorrelationKeyIncludingTrigger(t *testing.T) {
	a, err := NewBoundedAssembler(time.Hour, AssemblerLimits{MaxPendingEvents: 4, MaxRecordsPerEvent: 256, MaxPendingBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		for _, node := range []string{"alpha", "beta"} {
			r := mustParseRecord(t, `node=`+node+` type=PATH msg=audit(1792000000.123:45678): item=0 name="/safe"`)
			if _, err := a.AddChecked(r); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, err = a.AddChecked(mustParseRecord(t, `node=alpha type=PATH msg=audit(1792000000.123:45678): item=1 name="/safe"`))
	var limit *AssemblerLimitError
	if !errors.As(err, &limit) || limit.AuditID != "1792000000.123:45678" || limit.Node != "alpha" || !limit.NodePresent || limit.Value != 256 || limit.ObservedRecords != 257 || limit.CountComplete {
		t.Fatalf("diagnostic = %#v, %v", limit, err)
	}
}
