#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: bash scripts/reproduce.sh 8[,64,256,1024] [--build-artifacts] [--output-root runs]" >&2
  exit 2
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
sizes="$1"
shift
cd "$repo_root"
exec node scripts/reproduce.js --sizes "$sizes" "$@"
