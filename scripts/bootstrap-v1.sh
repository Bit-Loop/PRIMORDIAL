#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${PRIMORDIAL_VENV_DIR:-.venv}"
PG_ROOT="${PRIMORDIAL_BOOTSTRAP_PG_ROOT:-${ROOT}/runtime/postgres}"
PG_DATA="${PG_ROOT}/data"
PG_SOCKET="${PG_ROOT}/socket"
PG_LOG="${PG_ROOT}/postgres.log"
PG_PORT="${PRIMORDIAL_BOOTSTRAP_PG_PORT:-55432}"
PG_USER="${PRIMORDIAL_BOOTSTRAP_PG_USER:-primordial}"
PG_DB="${PRIMORDIAL_BOOTSTRAP_PG_DB:-primordial}"
ENV_FILE="${PRIMORDIAL_BOOTSTRAP_ENV_FILE:-runtime/primordial.env}"

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
}

wait_for_postgres() {
  for _ in $(seq 1 60); do
    if pg_isready -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d postgres >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Postgres did not become ready on 127.0.0.1:${PG_PORT}." >&2
  echo "Log: ${PG_LOG}" >&2
  exit 2
}

require_bin "$PYTHON_BIN"
require_bin initdb
require_bin pg_ctl
require_bin createdb
require_bin psql
require_bin pg_isready
require_bin npm

if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/python" -m pip install -e .
npm ci

mkdir -p "$PG_ROOT" "$PG_SOCKET" runtime

if [[ ! -d "$PG_DATA" ]]; then
  initdb -D "$PG_DATA" -A trust -U "$PG_USER"
fi

if ! pg_ctl -D "$PG_DATA" status >/dev/null 2>&1; then
  pg_ctl \
    -D "$PG_DATA" \
    -l "$PG_LOG" \
    -o "-p ${PG_PORT} -k ${PG_SOCKET} -h 127.0.0.1" \
    -w \
    start
fi

wait_for_postgres

createdb -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" "$PG_DB" 2>/dev/null || true

if ! psql "postgresql://${PG_USER}@127.0.0.1:${PG_PORT}/${PG_DB}" \
  -v ON_ERROR_STOP=1 \
  -c 'CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;' >/dev/null; then
  echo "Postgres is running, but pgvector is not available in this installation." >&2
  echo "Install pgvector for your Postgres version, then rerun this script." >&2
  exit 2
fi

cat > "$ENV_FILE" <<EOF
export PRIMORDIAL_DATABASE_URL='postgresql://${PG_USER}@127.0.0.1:${PG_PORT}/${PG_DB}'
export PRIMORDIAL_TEST_DATABASE_URL='postgresql://${PG_USER}@127.0.0.1:${PG_PORT}/${PG_DB}'
export PRIMORDIAL_RUNTIME_DIR='${ROOT}/runtime'
export PATH='${ROOT}/${VENV_DIR}/bin':"\$PATH"
EOF

echo "Bootstrap complete."
echo "Load the environment with:"
echo "  source ${ENV_FILE}"
echo "Then run:"
echo "  python3 cli.py doctor"
echo "  scripts/v1-gate.sh"
