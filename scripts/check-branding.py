#!/usr/bin/env python3
"""Development gate for product identity, deployment contracts and local doc links."""
import configparser
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlparse

root = Path(__file__).resolve().parents[1]
files = [root / p for p in subprocess.check_output(
    ['git', '-C', str(root), 'ls-files'], text=True).splitlines()]
legacy = re.compile('audit2json', re.I)
# Deliberately retained classes: migration/history, source evidence, and negative guards.
allowed = {
    'docs/rebranding.md': lambda line: True,
    'README.md': lambda line: 'audit2json v0.9.0 and v0.9.1 retain' in line,
    'AGENTS.md': lambda line: 'Published audit2json v0.9.0/v0.9.1' in line,
    'ROADMAP.md': lambda line: 'Published audit2json v0.9.0/v0.9.1' in line,
    'CHANGELOG.md': lambda line: ('(audit2json)' in line and line.startswith('## v0.9.')) or 'released as audit2json v0.9.1' in line,
    'docs/release.md': lambda line: 'Published audit2json v0.9.0 and v0.9.1 remain' in line,
    'docs/public-release-checklist.md': lambda line: 'Published audit2json v0.9.0/v0.9.1' in line,
    'docs/compatibility.md': lambda line: '`audit2json_v0.9.0_linux_arm64_standalone.tar.gz`' in line,
    'testdata/user_cmd.audit': lambda line: 'cwd="/home/test/audit2json"' in line,
    'internal/audit/user_command_test.go': lambda line: 'e.Process.CWD != "/home/test/audit2json"' in line,
    'scripts/check-branding.py': lambda line: True,
    'scripts/test-release-verifier.py': lambda line: 'audit2json' in line and ('entry.name =' in line or 'archive.rename(' in line),
}
count = 0
for path in files:
    name = path.relative_to(root).as_posix()
    assert not legacy.search(name), f'legacy tracked filename: {name}'
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if legacy.search(line):
            assert name in allowed and allowed[name](line), f'stale branding: {name}:{number}: {line}'
            count += 1

schema = json.loads((root / 'schema/aesirguard-audit-v1.schema.json').read_text())
assert schema['$id'] == 'https://raw.githubusercontent.com/kstone-sa/aesirguard-audit/main/schema/aesirguard-audit-v1.schema.json'
assert schema['title'] == 'AesirGuard Audit canonical event v1'
assert schema['properties']['schema_version']['const'] == '1.0'
assert sorted(p.name for p in (root / 'schema').glob('*.json')) == ['aesirguard-audit-v1.schema.json']
assert (root / 'go.mod').read_text() == 'module github.com/kstone-sa/aesirguard-audit\n\ngo 1.26\n'
assert (root / '.go-version').read_text().strip() == '1.26.8'
assert (root / 'cmd/ag-audit/main.go').is_file()

unit = configparser.ConfigParser(interpolation=None)
unit.optionxform = str
unit.read(root / 'packaging/systemd/aesirguard-audit.service')
assert unit['Unit']['Description'].startswith('AesirGuard Audit')
assert unit['Unit']['Documentation'] == 'https://github.com/kstone-sa/aesirguard-audit'
expected = {
    'Type': 'simple', 'User': 'aesirguard-audit', 'Group': 'aesirguard-audit',
    'RuntimeDirectory': 'aesirguard-audit', 'RuntimeDirectoryMode': '0700',
    'ExecStart': '/usr/bin/ag-audit --config /etc/aesirguard-audit/config.json',
    'Restart': 'on-failure', 'RestartSec': '5s', 'UMask': '0077',
    'NoNewPrivileges': 'true', 'PrivateTmp': 'true', 'ProtectSystem': 'strict',
    'ProtectHome': 'true', 'ReadOnlyPaths': '/var/log/audit',
    'ReadWritePaths': '/var/lib/aesirguard-audit /var/log/aesirguard-audit',
    'RestrictAddressFamilies': 'AF_UNIX', 'LockPersonality': 'true',
    'MemoryDenyWriteExecute': 'true', 'SystemCallArchitectures': 'native',
}
assert dict(unit['Service']) == expected, 'systemd deployment/hardening contract changed'
assert (root / 'packaging/systemd/aesirguard-audit.sysusers.conf').read_text() == 'u aesirguard-audit - "AesirGuard Audit collector" /var/lib/aesirguard-audit\n'
assert (root / 'packaging/systemd/aesirguard-audit.tmpfiles.conf').read_text() == 'd /var/lib/aesirguard-audit 0700 aesirguard-audit aesirguard-audit -\nd /var/log/aesirguard-audit 0750 aesirguard-audit aesirguard-audit -\n'
config = json.loads((root / 'configs/aesirguard-audit.example.json').read_text())
assert config['version'] == 1
assert config['input']['lock_file'] == '/run/aesirguard-audit/audit.lock'
assert config['checkpoint']['file'] == '/var/lib/aesirguard-audit/audit.checkpoint'

def anchors(path):
    return {re.sub(r'[^\w\- ]', '', line.lstrip('#').strip().lower()).replace(' ', '-')
            for line in path.read_text().splitlines() if line.startswith('#')}

links = 0
for path in files:
    if path.suffix != '.md':
        continue
    for target in re.findall(r'\[[^\]]+\]\(([^\s)]+)\)', path.read_text()):
        url = urlparse(target)
        if url.scheme or target.startswith('//'):
            # Future repository URLs are deliberately staged; check their local file targets.
            prefix = '/kstone-sa/aesirguard-audit/'
            if url.netloc == 'raw.githubusercontent.com' and url.path.startswith(prefix + 'main/'):
                resolved = root / url.path.split('/main/', 1)[1]
            elif url.netloc == 'github.com' and url.path.startswith(prefix + 'blob/main/'):
                resolved = root / url.path.split('/blob/main/', 1)[1]
            else:
                continue
        else:
            resolved = (path.parent / unquote(url.path)).resolve() if url.path else path
        assert resolved.exists(), f'broken doc link: {path.relative_to(root)} -> {target}'
        if url.fragment and resolved.suffix == '.md':
            assert unquote(url.fragment) in anchors(resolved), f'broken anchor: {target}'
        links += 1
print(f'Branding, single schema, Go policy, systemd hardening/configuration and {links} local doc links valid; {count} classified legacy lines')
