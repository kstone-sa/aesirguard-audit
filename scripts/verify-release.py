#!/usr/bin/env python3
"""Development-only verification of all four release archives; no unsafe extraction."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(root, version, commit, epoch):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version), "invalid version")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "expected full commit hash")
    go_version = "go" + Path(".go-version").read_text().strip()
    build_date = datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    identity = f"ag-audit {version} commit={commit} built={build_date} go={go_version}"
    expected = {f"aesirguard-audit_{version}_linux_{arch}_{variant}.tar.gz"
                for arch in ("amd64", "arm64") for variant in ("standalone", "systemd")}
    require({p.name for p in root.iterdir()} == expected | {"SHA256SUMS"}, "unexpected or missing release files")
    sums = {}
    for line in (root / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([^/]+)", line)
        require(match is not None, "malformed checksum entry")
        digest, name = match.groups()
        require(name not in sums, "duplicate checksum entry")
        sums[name] = digest
    require(set(sums) == expected, "checksum manifest must cover exactly four archives")
    payloads = {}
    for arch in ("amd64", "arm64"):
        for variant in ("standalone", "systemd"):
            name = f"aesirguard-audit_{version}_linux_{arch}_{variant}"
            archive = root / (name + ".tar.gz")
            require(hashlib.sha256(archive.read_bytes()).hexdigest() == sums[archive.name], "archive checksum mismatch")
            files = {}
            names = set()
            with tarfile.open(archive) as tar:
                for entry in tar:
                    parts = PurePosixPath(entry.name).parts
                    require(parts and parts[0] == name and ".." not in parts and not entry.name.startswith("/"), "unsafe archive path")
                    require(entry.name not in names, "duplicate archive member")
                    names.add(entry.name)
                    require(entry.isdir() or entry.isfile(), "archive contains a link or special object")
                    require(entry.uid == 0 and entry.gid == 0 and entry.mtime == int(epoch), "non-reproducible archive metadata")
                    relative = "/".join(parts[1:])
                    require(entry.mode == (0o755 if entry.isdir() or relative == "ag-audit" else 0o644), "unexpected archive permissions")
                    if entry.isfile():
                        require(0 <= entry.size <= 100 * 1024 * 1024, "unexpected member size")
                        files[relative] = tar.extractfile(entry).read()
            assets = [Path(p) for p in ("LICENSE", "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "configs/aesirguard-audit.example.json")]
            assets += sorted(Path("docs").rglob("*.md")) + sorted(Path("schema").rglob("*.json"))
            if variant == "systemd":
                assets += sorted(p for p in Path("packaging/systemd").rglob("*") if p.is_file())
            require(set(files) == {p.as_posix() for p in assets} | {"ag-audit", "BUILD-INFO.json"}, "missing or unexpected package assets")
            for asset in assets:
                require(files[asset.as_posix()] == asset.read_bytes(), f"package asset differs: {asset}")
            binary = files["ag-audit"]
            metadata = json.loads(files["BUILD-INFO.json"])
            require(metadata == {"product": "AesirGuard Audit", "binary": "ag-audit",
                                 "version": version, "commit": commit, "build_date": build_date,
                                 "go": go_version, "arch": arch, "binary_sha256": hashlib.sha256(binary).hexdigest()}, "build metadata mismatch")
            require(binary[:6] == b"\x7fELF\x02\x01", "expected 64-bit little-endian ELF")
            require(struct.unpack_from("<H", binary, 18)[0] == {"amd64": 62, "arm64": 183}[arch], "ELF architecture mismatch")
            phoff = struct.unpack_from("<Q", binary, 32)[0]
            size, count = struct.unpack_from("<HH", binary, 54)
            require(size >= 56 and count > 0 and phoff + size * count <= len(binary), "invalid ELF program headers")
            require(all(struct.unpack_from("<I", binary, phoff + i * size)[0] not in (2, 3) for i in range(count)), "dynamic ELF binary")
            require(identity.encode() in binary, "embedded release identity mismatch")
            with tempfile.TemporaryDirectory() as tmp:
                exe = Path(tmp) / "ag-audit"
                exe.write_bytes(binary)
                exe.chmod(0o700)
                info = subprocess.check_output(["go", "version", "-m", str(exe)], text=True)
                require(info.splitlines()[0].endswith(": " + go_version), "embedded Go version mismatch")
                settings = dict(re.findall(r"^\s*build\s+(\S+?)=(.*)$", info, re.M))
                for key, value in {"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": arch, "-trimpath": "true"}.items():
                    require(settings.get(key) == value, f"build setting mismatch: {key}")
                require(not re.search(r"^\s*dep\s", info, re.M), "unexpected runtime module dependency")
                if platform.system() == "Linux" and platform.machine() == {"amd64": "x86_64", "arm64": "aarch64"}[arch]:
                    actual = subprocess.check_output([str(exe), "--version"], text=True, timeout=10).strip()
                    require(actual == identity, "runtime release identity mismatch")
                    config = Path(tmp) / "config.json"
                    config.write_bytes(files["configs/aesirguard-audit.example.json"])
                    subprocess.run([str(exe), "--config", str(config), "--check-config"], check=True, capture_output=True, timeout=10)
                    print(f"Executed {arch} {variant}: version and configuration valid")
            payloads[arch, variant] = files
        standalone, systemd = payloads[arch, "standalone"], payloads[arch, "systemd"]
        require(all(systemd[key] == value for key, value in standalone.items()), "cross-variant payload mismatch")
    print("Verified four archives, exact checksums/assets/metadata, static ELF targets and equal variant payloads")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: verify-release.py DIST VERSION COMMIT SOURCE_DATE_EPOCH")
    try:
        verify(Path(sys.argv[1]), *sys.argv[2:])
    except (ValueError, OSError, KeyError, struct.error, tarfile.TarError, subprocess.SubprocessError) as error:
        raise SystemExit(f"release verification failed: {error}")
