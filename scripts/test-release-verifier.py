#!/usr/bin/env python3
"""Acceptance faults: mutate real packages, including recomputed checksums."""
import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("verifier", Path(__file__).with_name("verify-release.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
source, version, commit, epoch = Path(sys.argv[1]), *sys.argv[2:]


def rewrite(archive, fault):
    with tarfile.open(archive) as tar:
        entries = [(copy.copy(e), tar.extractfile(e).read() if e.isfile() else None) for e in tar]
    changed = []
    for entry, data in entries:
        if fault == "missing-schema" and "/schema/" in entry.name:
            continue
        if entry.name.endswith("/ag-audit"):
            if fault == "wrong-architecture":
                data = data[:18] + b"\xb7\x00" + data[20:]
            elif fault == "dynamic":
                import struct
                offset = struct.unpack_from("<Q", data, 32)[0]
                data = data[:offset] + b"\x03\x00\x00\x00" + data[offset + 4:]
            elif fault == "wrong-identity":
                data = data.replace(commit.encode(), b"0" * 40)
            elif fault == "variant-drift":
                data += b"unexpected payload"
        if fault == "symlink" and entry.name.endswith("/README.md"):
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/etc/passwd"
            data = None
        if fault == "traversal" and entry.name.endswith("/README.md"):
            entry.name = "../escape"
        if fault == "legacy-binary" and entry.name.endswith("/ag-audit"):
            entry.name = entry.name.rsplit("/", 1)[0] + "/audit2json"
        if fault == "legacy-systemd" and entry.name.endswith("/aesirguard-audit.service"):
            entry.name = entry.name.rsplit("/", 1)[0] + "/audit2json.service"
        if fault == "legacy-schema" and entry.name.endswith("/aesirguard-audit-v1.schema.json"):
            entry.name = entry.name.rsplit("/", 1)[0] + "/audit2json-v1.schema.json"
        if fault == "wrong-schema-id" and entry.name.endswith("/aesirguard-audit-v1.schema.json"):
            import json
            document = json.loads(data)
            document["$id"] = "https://example.invalid/wrong.schema.json"
            data = json.dumps(document).encode()
        if fault == "wrong-product" and entry.name.endswith("/BUILD-INFO.json"):
            import json
            document = json.loads(data)
            document["product"] = "Wrong product"
            data = json.dumps(document).encode()
        if data is not None:
            entry.size = len(data)
        changed.append((entry, data))
    if fault in ("wrong-architecture", "dynamic", "wrong-identity", "variant-drift"):
        import json
        binary = next(b for e, b in changed if e.name.endswith("/ag-audit"))
        for entry, data in changed:
            if entry.name.endswith("/BUILD-INFO.json"):
                obj = json.loads(data)
                obj["binary_sha256"] = hashlib.sha256(binary).hexdigest()
                replacement = json.dumps(obj).encode()
                changed = [(e, replacement if e is entry else b) for e, b in changed]
                entry.size = len(replacement)
                break
    with tarfile.open(archive, "w:gz") as tar:
        for entry, data in changed:
            tar.addfile(entry, io.BytesIO(data) if data is not None else None)


for fault in ("missing-schema", "wrong-architecture", "dynamic", "wrong-identity", "variant-drift", "symlink", "traversal", "omitted-checksum", "duplicate-checksum", "bad-checksum", "legacy-binary", "legacy-systemd", "legacy-schema", "wrong-schema-id", "wrong-product", "legacy-archive"):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "dist"
        shutil.copytree(source, root)
        archive = root / f"aesirguard-audit_{version}_linux_amd64_systemd.tar.gz"
        rewrite(archive, fault)
        if fault == "legacy-archive":
            archive.rename(root / f"audit2json_{version}_linux_amd64_systemd.tar.gz")
        lines = [hashlib.sha256(p.read_bytes()).hexdigest() + "  ./" + p.name for p in sorted(root.glob("*.tar.gz"))]
        if fault == "omitted-checksum": lines.pop()
        if fault == "duplicate-checksum": lines.append(lines[0])
        if fault == "bad-checksum": lines[0] = "0" * 64 + lines[0][64:]
        (root / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        try:
            v.verify(root, version, commit, epoch)
        except ValueError as error:
            print(f"Rejected {fault}: {error}")
        else:
            raise SystemExit(f"fault accepted: {fault}")
print("All sixteen release-verifier fault invariants passed")
