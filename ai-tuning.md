# AI Tuning

Date: 2026-05-09

## Live LM Studio Tuning

The LM Studio tuner was run against all installed LM Studio LLMs at a small context:

```bash
context_length=1024
max_tokens=128
temperature=0.0
cpu_reserve_mb=4096
vram_soft_reserve_mb=128
timeout_seconds=120
```

The runtime CLI path was not used for the live run because this local environment does not have `PRIMORDIAL_DATABASE_URL` configured. The provider-level tuner was used directly with the same load/unload and metrics logic, plus a local `/proc/meminfo` and `nvidia-smi` sampler.

Models checked before tuning:

- `gpt-oss-cybersecurity-20b-merged-heretic-i1`
- `gpt-oss-cybersecurity-merged-20b-heretic-ara`
- `lily-cybersecurity-7b-v0.2`
- `qwen3.5-27b-claude-4.6-opus-reasoning-distilled`
- `qwen3.5-35b-a3b-uncensored-hauhaucs-aggressive`
- `qwen3.5-9b-claude-4.6-opus-reasoning-distilled`
- `qwen3.5-9b-uncensored-hauhaucs-aggressive`

Result: `ok`

Rows recorded: `105`

Warnings: none

Detailed artifact:

```text
artifacts/model_eval/lmstudio_tuning_live_20260509T000055Z/lmstudio_tuning_20260509T001430Z.json
```

Reusable profile:

```text
runtime/model_eval/lmstudio_performance_profile.json
```

Post-run LM Studio model state: no loaded models were reported by `/api/v1/models`.

## Best Configs

| Model | Tok/s | Best load config |
| --- | ---: | --- |
| `lily-cybersecurity-7b-v0.2` | 124.2831 | `eval_batch_size=1024`, `flash_attention=true`, `offload_kv_cache_to_gpu=true` |
| `qwen3.5-9b-claude-4.6-opus-reasoning-distilled` | 94.4410 | `eval_batch_size=512`, `flash_attention=true`, `offload_kv_cache_to_gpu=true` |
| `qwen3.5-9b-uncensored-hauhaucs-aggressive` | 90.2749 | `eval_batch_size=1024`, `flash_attention=true`, `offload_kv_cache_to_gpu=true` |
| `gpt-oss-cybersecurity-20b-merged-heretic-i1` | 49.6811 | `eval_batch_size=512`, `flash_attention=true`, `offload_kv_cache_to_gpu=true`, `num_experts=4` |
| `gpt-oss-cybersecurity-merged-20b-heretic-ara` | 49.5443 | `eval_batch_size=1024`, `flash_attention=true`, `offload_kv_cache_to_gpu=true`, `num_experts=4` |
| `qwen3.5-35b-a3b-uncensored-hauhaucs-aggressive` | 45.1363 | `eval_batch_size=1024`, `flash_attention=true`, `offload_kv_cache_to_gpu=true`, `num_experts=4` |
| `qwen3.5-27b-claude-4.6-opus-reasoning-distilled` | 7.3860 | `eval_batch_size=512`, `flash_attention=false`, `offload_kv_cache_to_gpu=true` |

## Role Findings

Role findings were added to the saved benchmark metadata:

- `runtime/model_eval/lmstudio_performance_profile.json` now includes `role_findings`.
- `artifacts/model_eval/lmstudio_tuning_live_20260509T000055Z/lmstudio_tuning_20260509T001430Z.json` now includes performance-based `role_findings`.
- `artifacts/model_eval/lmstudio_role_eval_20260509T001954Z/model_eval_20260509T002846Z.json` now includes deterministic role-eval `role_findings`.
- Model-eval aggregate rows now include `recommendation_id` and `role_fit_summary`.

A direct deterministic role evaluation was run through the benchmark suite at `context_size=1024`, `temperature=0.0`, using the tuned LM Studio profile. It prompted the models with the existing safe Primordial role cases rather than relying only on model names or self-report.

Role-eval artifacts:

```text
artifacts/model_eval/lmstudio_role_eval_20260509T001954Z/model_eval_20260509T002846Z.csv
artifacts/model_eval/lmstudio_role_eval_20260509T001954Z/model_eval_20260509T002846Z.json
```

Strict result: no LM Studio model met the benchmark's recommendation gate at this small `1024/128` run. Treat the following as relative guidance, not durable role routing.

| Role | Relative best | Why | Caution |
| --- | --- | --- | --- |
| `local_fast` | `lily-cybersecurity-7b-v0.2` | Highest aggregate score in role eval, highest measured eval throughput at `126.4019` tok/s, lowest average latency at `0.9748s`. | Pass rate was only `0.1176`, so this is a practical hot-path pick, not a high-confidence recommendation. |
| `local_compact` | `lily-cybersecurity-7b-v0.2` | Tied best compact role score with `gpt-oss-cybersecurity-20b-merged-heretic-i1`, but was much faster and had the better aggregate score. | Use for quick summarization/compression only until larger-context quality is tested. |
| `local_deep` | `lily-cybersecurity-7b-v0.2` for this small benchmark; `qwen3.5-35b-a3b-uncensored-hauhaucs-aggressive` remains the performance-profile deep candidate. | The deterministic role cases favored Lily at 1024/128; the tuning profile favored Qwen 35B-A3B for deeper/larger-model metadata. | The Qwen 35B and 27B reasoning models did not produce useful scored output at this token budget; retest them with larger output limits/context before assigning deep reasoning. |
| `local_code` | `lily-cybersecurity-7b-v0.2`, with `gpt-oss-cybersecurity-20b-merged-heretic-i1` as the next code/security candidate. | Lily had the best relative role score; GPT-OSS I1 was the next strongest code/security metadata fit with usable speed around `44.3477` tok/s. | Code fit is still score-driven rather than proven by pass-rate. Do not auto-route code work yet. |

Practical current default: use `lily-cybersecurity-7b-v0.2` as the small-context LM Studio workhorse for hot-path/compact probing. Keep `gpt-oss-cybersecurity-20b-merged-heretic-i1` as the next cyber/code candidate. Keep `qwen3.5-35b-a3b-uncensored-hauhaucs-aggressive` as a deep-candidate to retest at higher output budgets, not as the current default.

## Benchmark Head Runtime Guard

The benchmark suite now treats this AI tuning profile as the benchmark head for rough runtime estimates.

Default cutoff:

```text
max_model_runtime_seconds=1800
max_model_runtime=30 minutes
```

Behavior:

- Before loading a model, the suite estimates the selected model scope from tuning `tokens_per_second`, context sizes, temperature count, and benchmark case count.
- If the estimate exceeds 30 minutes, the model is not loaded locally.
- The result is recorded in-band with `stage=planning`, `error=skipped_estimated_timeout`, and `load_state=skipped_estimated_timeout`.
- The result includes `benchmark_plan`, `estimated_runtime_seconds`, `max_runtime_seconds`, and `offload_recommendation`.
- The offload recommendation targets `claude` and `gpt` for model scopes that exceed the local runtime cutoff.
- The full eval metadata includes `eval_config.runtime_estimates` and `eval_config.max_model_runtime_seconds`.

CLI override:

```bash
python ./cli.py models evaluate --providers lmstudio --exhaustive --max-model-minutes 45
```

The saved benchmark artifacts were updated with top-level `benchmark_head` metadata:

- `runtime/model_eval/lmstudio_performance_profile.json`
- `artifacts/model_eval/lmstudio_tuning_live_20260509T000055Z/lmstudio_tuning_20260509T001430Z.json`
- `artifacts/model_eval/lmstudio_role_eval_20260509T001954Z/model_eval_20260509T002846Z.json`

## Tests

Full model-eval test file:

```bash
python -m pytest -q tests/test_model_eval.py
```

Result:

```text
21 passed, 1 failed
```

The failure is the existing environment dependency issue:

```text
RuntimeError: psycopg v3 is required for Primordial runtime storage.
Install project dependencies with `pip install -e .`.
```

Focused non-storage suite:

```bash
python -m pytest -q tests/test_model_eval.py -k 'not runtime_model_evaluation_uses_cpu_by_default_and_returns_payload'
```

Result:

```text
21 passed, 1 deselected
```

## Usage

The benchmark suite now loads the saved LM Studio profile by default when `lmstudio` is selected:

```bash
python ./cli.py models evaluate --providers lmstudio --context-size 1024
```

To explicitly use this profile:

```bash
python ./cli.py models evaluate --providers lmstudio --context-size 1024 --lmstudio-profile runtime/model_eval/lmstudio_performance_profile.json
```

To disable the profile:

```bash
python ./cli.py models evaluate --providers lmstudio --context-size 1024 --no-lmstudio-profile
```
