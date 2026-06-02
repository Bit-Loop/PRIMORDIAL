#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PRIMORDIAL_GATE_PORT:-18081}"
BASE_URL="http://127.0.0.1:${PORT}"
SERVER_PID=""

if [[ -z "${PRIMORDIAL_DATABASE_URL:-}" && -f runtime/primordial.env ]]; then
  # shellcheck disable=SC1091
  source runtime/primordial.env
fi

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ -z "${PRIMORDIAL_DATABASE_URL:-}" ]]; then
  echo "PRIMORDIAL_DATABASE_URL is required for the V1 gate." >&2
  exit 2
fi

tracked_runtime="$(git ls-files runtime)"
if [[ -n "${tracked_runtime}" ]]; then
  echo "runtime/ files are still tracked:" >&2
  echo "${tracked_runtime}" >&2
  exit 2
fi

PRIMORDIAL_TEST_DATABASE_URL="${PRIMORDIAL_TEST_DATABASE_URL:-$PRIMORDIAL_DATABASE_URL}" \
  PRIMORDIAL_DATABASE_URL= \
  python3 -m unittest discover -q
python3 -m unittest tests.test_ctf_lab_phases tests.test_ctf_harness_environment -q
python3 -m primordial.core.quality.hardcode
git ls-files '*.py' | xargs python3 -m py_compile
npm run build

python3 cli.py web --host 127.0.0.1 --port "${PORT}" &
SERVER_PID="$!"

for _ in $(seq 1 60); do
  if curl -fsS "${BASE_URL}/api/health" >/dev/null; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "Web server exited before becoming healthy." >&2
    wait "${SERVER_PID}" || true
    exit 2
  fi
  sleep 1
done

curl -fsS "${BASE_URL}/" >/dev/null
curl -fsS "${BASE_URL}/api/health" >/dev/null
curl -fsS "${BASE_URL}/api/control-plane" >/dev/null
curl -fsS "${BASE_URL}/api/self-test" >/dev/null

python3 cli.py doctor --json >/dev/null

echo "V1 gate passed without running model inference, benchmarks, credential validation, or exploit behavior."
