#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PG_ROOT="${PRIMORDIAL_BOOTSTRAP_PG_ROOT:-${ROOT}/runtime/postgres}"
PG_DATA="${PG_ROOT}/data"

if [[ ! -d "$PG_DATA" ]]; then
  echo "No bootstrap Postgres data directory found at ${PG_DATA}."
  exit 0
fi

pg_ctl -D "$PG_DATA" -m fast -w stop
