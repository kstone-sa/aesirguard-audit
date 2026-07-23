Project Goals

Breve descrizione del progetto e dei principi:
Native Go
Zero external runtime dependencies
No Python
No CGO
Designed for Splunk Universal Forwarder
High performance
Low memory footprint
Reliable under heavy auditd workloads
Easy to maintain

v0.1 — Parser Foundation ✅

Status: Completed

Features:
Audit record parser
Event grouping
Key/value parser
EXECVE reconstruction
PROCTITLE decoding
PATH deduplication
Compact JSON output

v0.2 — Mapping Engine

Goal
Separate Linux-specific knowledge from the parser.

Deliverables:
External JSON mapping files
Mapping loader
In-memory cache
Result mapping
Architecture mapping
Syscall mapping
Permission mapping
Optional mapping configuration

Future mappings:
errno
socket families
capabilities
audit message types

v0.3 — Collector

Goal
Read audit.log continuously.

Requirements:
tail mode
configurable polling
startup from checkpoint
graceful shutdown
back-pressure support
EOF waiting
configurable input path

No parsing logic.

Only collection.

v0.4 — Checkpoint Engine

Requirements:
JSON checkpoint file
inode
device
offset
timestamp
safe writes
crash recovery
configurable checkpoint interval

No duplicated events after restart.

v0.5 — Log Rotation Support
Questa è una milestone importante e vorrei darle parecchio spazio.

Requirements:
inode tracking
rename detection
copytruncate detection
rotation during partial event
continue reading old inode until EOF
seamlessly switch to new file
zero data loss
no duplicated events

Support:
logrotate
auditd rotation
frequent rotations
very small log sizes

Stress tests:
rotation every minute
rotation every second
rotation during EXECVE
rotation during multi-line events

v0.6 — Configuration
JSON configuration.

Examples:
{
  "input": {
    "path": "/var/log/audit/audit.log"
  },
  "checkpoint": {
    "enabled": true,
    "interval": 5
  },
  "mapping": {
    "syscalls": true
  }
}

Future support:
multiple inputs
include files
environment overrides
v0.7 — Performance

Benchmarks:
events/sec
MB/sec
allocations
memory
CPU

Optimizations only after correctness.
Never optimize prematurely.

v0.8 — Testing
Regression suite
Golden JSON tests
Real audit.log corpus
Fuzz testing
Malformed records
Large EXECVE
Very large PATH lists
Rotation tests
Checkpoint tests

v0.9 — Production Hardening
Logging
Metrics
Graceful shutdown
Signal handling
Error recovery
Corrupted input
Corrupted checkpoint
Configuration validation

v1.0
Stable release.

Requirements:
Fully documented
100% regression tests passing
Stable JSON format
Performance benchmarked
Production ready
