#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 4 ]; then
  echo "usage: $0 OUTPUT_DIRECTORY VERSION COMMIT SOURCE_DATE_EPOCH" >&2
  exit 2
fi
python3 scripts/verify-release.py "$@"
