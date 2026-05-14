# Agent Chat API

Standalone Python HTTP API that wraps local Codex and Claude Code chat CLIs.

This is intentionally separate from PRIMORDIAL runtime code. It uses only the Python standard library, launches providers with exact `subprocess` argv lists, and defaults to conservative execution:

- Claude: `claude -p` JSON mode with built-in tools disabled through `--tools ""`.
- Codex: `codex exec` non-interactive mode with `--sandbox read-only` and `--ephemeral`.
- Request `cwd` values are constrained under `CHAT_API_WORKSPACE_ROOT`.
- Optional bearer auth is enabled by setting `CHAT_API_KEY`.
- Every response includes a `request_id` for log correlation.
- `include_raw: true` redacts provider session identifiers and token-like fields before returning raw output.
- Streaming uses Server-Sent Events for both the simple API and the OpenAI-compatible endpoint.
- Persistent conversations are opt-in through `conversation_id`.
- Live requests are protected by an in-memory fixed-window rate limiter.
- Requests default to Codex first, then fall back to the next configured provider when Codex is out of usage, unavailable, or returns a narrow refusal-style response.
- Provider fallback/refusal events are written to a redacted JSONL audit log without user prompts.

The provider integration shape was based on:

- OpenAI Codex non-interactive mode docs: `codex exec`, JSON events, and `--output-last-message`.
- OpenAI Codex GitHub README: local Codex CLI installation and CLI role.
- Claude Code CLI docs: `claude -p`, JSON output, `--tools`, and permission mode flags.
- Anthropic `claude-agent-sdk-python` README: async query shape and the warning that tool permissions and tool availability are separate concerns.

## Run

```bash
cd /home/bitloop/Desktop/PRIMORDIAL/agent_chat_api
python3 app.py --host 127.0.0.1 --port 8787 --workspace-root "$PWD"
```

Optional environment:

```bash
export CHAT_API_KEY='change-me'
export CHAT_API_DEFAULT_PROVIDER=codex
export CHAT_API_FALLBACK_PROVIDERS=codex,claude
export CHAT_API_PROVIDER_FALLBACK_ENABLED=true
export CHAT_API_AUDIT_LOG=/home/bitloop/Desktop/PRIMORDIAL/agent_chat_api/runtime/provider-audit.jsonl
export CHAT_API_TIMEOUT_SECONDS=300
export CHAT_API_MAX_PROMPT_CHARS=200000
export CHAT_API_WORKSPACE_ROOT=/home/bitloop/Desktop/PRIMORDIAL/agent_chat_api
export CHAT_API_RATE_LIMIT_ENABLED=true
export CHAT_API_RATE_LIMIT_WINDOW_SECONDS=60
export CHAT_API_RATE_LIMIT_REQUESTS=30
```

## Tests

Run the full deterministic test suite from this subfolder:

```bash
cd /home/bitloop/Desktop/PRIMORDIAL/agent_chat_api
python3 -B run_test_suite.py
```

The runner discovers `tests/test*.py`, does not call live Codex or Claude models, and writes Markdown results to:

- `test-results/test-results-<timestamp>.md`
- `test-results/latest.md`

## Health

```bash
curl -s http://127.0.0.1:8787/health | python3 -m json.tool
```

## Simple API

```bash
curl -s http://127.0.0.1:8787/api/chat \
  -H 'Content-Type: application/json' \
  -d '{
    "provider": "claude",
    "prompt": "Summarize what this API does.",
    "dry_run": true
  }' | python3 -m json.tool
```

Use `dry_run: true` to inspect the provider command without spending model tokens.

If `provider` is omitted, the wrapper tries Codex first. If Codex has no remaining usage, cannot start, times out, or returns a narrow refusal phrase such as "sorry, I cannot...", the wrapper audits that event and tries the next configured provider. Explicit `provider` or provider-prefixed `model` requests do not fall back unless `"fallback": true` is passed.

For streaming, add `"stream": true`. The response is `text/event-stream` with these event names:

- `meta`: request/provider metadata and command preview.
- `provider_event`: redacted provider-native event payload.
- `delta`: text delta.
- `done`: final text and timing metadata.
- `error`: provider startup/runtime error.

```bash
curl -N http://127.0.0.1:8787/api/chat \
  -H 'Content-Type: application/json' \
  -d '{
    "provider": "claude",
    "prompt": "Reply with a short status line.",
    "stream": true
  }'
```

## OpenAI-Compatible Chat Shape

```bash
curl -s http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "codex:gpt-5.5",
    "messages": [
      {"role": "user", "content": "Explain this repository in one paragraph."}
    ],
    "dry_run": true
  }' | python3 -m json.tool
```

Provider prefixes are supported in `model`:

- `claude:sonnet`
- `claude:opus`
- `codex:gpt-5.5`

You can also pass `"provider": "claude"` or `"provider": "codex"` separately.

Set `"stream": true` on this endpoint for OpenAI-style SSE chunks ending in `data: [DONE]`.

## Request Fields

- `provider`: `claude` or `codex`; defaults to `CHAT_API_DEFAULT_PROVIDER`.
- `prompt`: raw prompt text.
- `messages`: chat messages with `role` and `content`; used when `prompt` is omitted or combined with it.
- `model`: optional provider model. Prefix with `claude:` or `codex:` to select provider.
- `cwd`: optional working directory, constrained under `CHAT_API_WORKSPACE_ROOT`.
- `timeout_seconds`: capped by `CHAT_API_MAX_TIMEOUT_SECONDS`.
- `dry_run`: return the constructed command without invoking the model.
- `stream`: return Server-Sent Events instead of a JSON response.
- `fallback`: allow provider fallback for this request. Defaults to `true` only when no explicit provider/model prefix is supplied.
- `include_raw`: include redacted provider stdout/stderr in `/api/chat` responses.
- `safe_guard`: prepend a narrow safety instruction. Defaults to `true`.
- `conversation_id`: opt into persistent provider sessions for this conversation key.
- `persist`: set to `false` to force an ephemeral call even when `conversation_id` is present.

Provider-specific fields:

- Claude: `allow_tools`, `claude_tools`, `claude_permission_mode`.
- Codex: `codex_sandbox`, `codex_ephemeral`.

Dangerous Codex sandbox mode is refused unless `CHAT_API_ALLOW_DANGEROUS_SANDBOXES=1`.

## Persistent Conversations

Persistence is opt-in. Supplying `conversation_id` stores the provider session mapping in `runtime/sessions.json`. Later requests with the same `conversation_id` resume that provider session as long as provider, cwd, and Codex sandbox match.

```bash
curl -s http://127.0.0.1:8787/api/chat \
  -H 'Content-Type: application/json' \
  -d '{
    "provider": "claude",
    "conversation_id": "notes-review",
    "prompt": "Remember that this conversation is about the wrapper API."
  }' | python3 -m json.tool
```

## Rate Limits

The limiter applies only to live requests. `dry_run`, `/health`, and `/providers` are exempt.

- `CHAT_API_RATE_LIMIT_ENABLED`: default `true`.
- `CHAT_API_RATE_LIMIT_WINDOW_SECONDS`: default `60`.
- `CHAT_API_RATE_LIMIT_REQUESTS`: default `30`.

Buckets use the bearer token hash when `CHAT_API_KEY` is active, otherwise the client IP.

## Provider Fallback Audit

Rare provider fallback events are appended to `CHAT_API_AUDIT_LOG` as JSONL. Entries include timestamp, provider, request id, reason, status code, and a short redacted provider-output snippet. They do not include the user prompt.

Fallback reasons include quota/rate exhaustion, provider startup/timeout failures, empty responses, and narrow refusal-style text. If every configured provider fails or refuses, the wrapper returns a deterministic `wrapper` response explaining that no synthetic model answer was generated and includes the fallback attempts in the API response.

## User Service

Install the repo-local user service template:

```bash
mkdir -p ~/.config/systemd/user
cp /home/bitloop/Desktop/PRIMORDIAL/agent_chat_api/systemd/agent-chat-api.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now agent-chat-api.service
systemctl --user status agent-chat-api.service
```

Optional environment overrides can be placed at:

```text
/home/bitloop/Desktop/PRIMORDIAL/agent_chat_api/runtime/agent-chat-api.env
```

## Notes

This is a CLI wrapper, not a replacement for the official provider APIs. It inherits the auth, rate limits, local configuration, and behavior of the installed `codex` and `claude` binaries. Claude exposes a hard tool restriction flag through `--tools ""`; Codex does not expose an equivalent no-tools flag in this wrapper, so Codex uses read-only sandboxing plus the guard prompt.
