#!/usr/bin/env python3
"""Development-only JSON Schema validation; never used by the collector runtime.

Usage: python3 scripts/validate-schema.py /absolute/path/to/ag-audit
Dependency: jsonschema==4.26.0 (install into a disposable virtual environment).
"""
import copy
import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator, FormatChecker

root = Path(__file__).resolve().parents[1]
binary = str(Path(sys.argv[1]).resolve())
schema = json.loads((root / "schema/aesirguard-audit-v1.schema.json").read_text())
assert schema["$id"] == "https://raw.githubusercontent.com/kstone-sa/aesirguard-audit/main/schema/aesirguard-audit-v1.schema.json"
assert schema["title"] == "AesirGuard Audit canonical event v1"
assert schema["properties"]["schema_version"]["const"] == "1.0"
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema, format_checker=FormatChecker())
count = 0
features = set()
inputs = [(str(p.relative_to(root)), p.read_bytes()) for p in sorted((root / "testdata").rglob("*.audit"))]
inputs += [("malformed bytes", b"\xff\n"), ("malformed text", b"not an audit record\n")]
for name, data in inputs:
    completed = subprocess.run([binary, "--render-message"], input=data, capture_output=True, check=True)
    for line in completed.stdout.splitlines():
        event = json.loads(line)
        errors = list(validator.iter_errors(event))
        if errors:
            raise SystemExit(f"{name}: {errors[0].json_path}: {errors[0].message}")
        count += 1
        if event.get("process", {}).get("argv_source"):
            features.add("argv_source")
        if event.get("process", {}).get("command_source") == "user_cmd":
            features.add("user_command")
        if event.get("process", {}).get("audit_attribution"):
            features.add("audit_attribution")
        if event.get("security", {}).get("seccomp"):
            features.add("seccomp")
        if event["audit"].get("raw_encoding"):
            features.add("raw_encoding")
        if any(i.get("value_encoding") for i in event["event"].get("issues", [])):
            features.add("issue_encoding")

assert features == {"argv_source", "seccomp", "raw_encoding", "issue_encoding", "user_command", "audit_attribution"}, features
valid = {"schema_version": "1.0", "audit": {}, "event": {"type": "TEST"}}
validator.validate(valid)
invalid = []
for key in ("schema_version", "audit", "event"):
    e = copy.deepcopy(valid)
    del e[key]
    invalid.append(e)
for extra in ({"process": {"argv": "scalar"}}, {"event": {"type": "TEST", "success": "yes"}},
              {"process": {"argv_source": "invented"}}, {"security": {"seccomp": {"action": "invented"}}},
              {"process": {"command_source": "invented"}}, {"process": {"command": []}},
              {"process": {"audit_attribution": {"old": {"loginuid_unset": "true"}}}},
              {"process": {"audit_attribution": {"new": {"session_id": 42}}}},
              {"process": {"audit_attribution": {"old": {}}}},
              {"unpublished_field": True}):
    invalid.append(dict(valid, **extra))
for e in invalid:
    assert not validator.is_valid(e), e
print(f"Draft 2020-12: {count} emitted events valid; {len(invalid)} invalid contracts rejected; all new schema features exercised")
