package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHeartbeatConfigurationPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		flags        []string
		want         time.Duration
	}{
		{"built-in", "", nil, 10 * time.Minute},
		{"omitted", `{"version":1}`, nil, 10 * time.Minute},
		{"configured", `{"version":1,"operations":{"heartbeat_interval":"15s"}}`, nil, 15 * time.Second},
		{"override", `{"version":1,"operations":{"heartbeat_interval":"15s"}}`, []string{"--heartbeat-interval=2m"}, 2 * time.Minute},
		{"config-disable", `{"version":1,"operations":{"heartbeat_interval":"0s"}}`, nil, 0},
		{"cli-disable", `{"version":1,"operations":{"heartbeat_interval":"15s"}}`, []string{"--heartbeat-interval=0s"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{}
			if tc.config != "" {
				p := filepath.Join(t.TempDir(), "config.json")
				if err := os.WriteFile(p, []byte(tc.config), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--config", p)
			}
			options, err := parseOptions(append(args, tc.flags...), io.Discard)
			if err != nil || options.heartbeatInterval != tc.want {
				t.Fatalf("interval=%v err=%v", options.heartbeatInterval, err)
			}
			d := newOperationalDiagnostics(io.Discard, options.heartbeatInterval)
			d.nextHeartbeat = time.Time{}
			if d.heartbeatDue() != (tc.want > 0) {
				t.Fatal("disable behavior")
			}
		})
	}
	var help bytes.Buffer
	writeUsage(&help)
	if !strings.Contains(help.String(), "default 10m0s") {
		t.Fatal(help.String())
	}
}
