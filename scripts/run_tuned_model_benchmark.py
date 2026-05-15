#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from primordial.core.providers.lmstudio import LMStudioClient  # noqa: E402
from primordial.core.providers.model_eval import ModelEvaluationService  # noqa: E402
from primordial.core.providers.ollama import OllamaClient, OllamaResponse  # noqa: E402


def parse_csv_ints(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def parse_csv_floats(value: str) -> list[float]:
    return [float(item.strip()) for item in value.split(",") if item.strip()]


def json_safe(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return json_safe(asdict(value))
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    return str(value)


def shell(args: list[str], timeout: int = 15) -> dict[str, object]:
    try:
        proc = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return {"returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "timeout"}


def nvidia_metrics() -> dict[str, object]:
    result = shell(
        [
            "nvidia-smi",
            "--query-gpu=utilization.gpu,utilization.memory,memory.used,memory.free,memory.total,temperature.gpu",
            "--format=csv,noheader,nounits",
        ],
        timeout=10,
    )
    if result["returncode"] != 0 or not result["stdout"]:
        return {"available": False, "error": result.get("stderr") or result.get("stdout") or "nvidia-smi unavailable"}
    parts = [part.strip() for part in str(result["stdout"]).splitlines()[0].split(",")]
    try:
        util, mem_util, used, free, total, temp = [float(part) for part in parts[:6]]
    except Exception:
        return {"available": False, "raw": result["stdout"]}
    return {
        "available": True,
        "percent": util,
        "memory_utilization_percent": mem_util,
        "memory_used_mb": used,
        "memory_free_mb": free,
        "memory_total_mb": total,
        "memory_percent": round((used / total) * 100.0, 4) if total else None,
        "temperature_c": temp,
    }


try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional host telemetry
    psutil = None


def host_metrics() -> dict[str, object]:
    cpu = None
    memory: dict[str, object] = {}
    if psutil:
        vm = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=0.02)
        memory = {
            "percent": vm.percent,
            "total_mb": round(vm.total / (1024 * 1024), 2),
            "available_mb": round(vm.available / (1024 * 1024), 2),
        }
    return {"cpu": {"percent": cpu}, "memory": memory, "gpu": nvidia_metrics()}


def is_timeout(message: str) -> bool:
    lowered = message.lower()
    return "timed out" in lowered or "timeout" in lowered


def is_offload_or_load_failure(message: str) -> bool:
    lowered = message.lower()
    return any(
        term in lowered
        for term in (
            "http 500",
            "internal server error",
            "out of memory",
            "cuda",
            "vram",
            "memory",
            "alloc",
            "failed to load",
            "llama",
        )
    )


def fallback_candidates(selected: int | None) -> list[int | None]:
    values: list[int | None] = [selected]
    if selected is None:
        pass
    elif selected >= 999:
        values.extend([64, 48, 32, 24, 16, 8, 0])
    elif selected > 48:
        values.extend([48, 32, 24, 16, 8, 0])
    elif selected > 32:
        values.extend([32, 24, 16, 8, 0])
    elif selected > 24:
        values.extend([24, 16, 8, 0])
    elif selected > 16:
        values.extend([16, 8, 0])
    elif selected > 8:
        values.extend([8, 4, 0])
    elif selected > 4:
        values.extend([4, 2, 0])
    elif selected > 0:
        values.extend([2, 0])
    else:
        values.append(0)
    out: list[int | None] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


class EventSink:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, event: dict[str, object]) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(json_safe(event), sort_keys=True) + "\n")

    def counts(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        if not self.path.exists():
            return counts
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            provider = str(event.get("provider") or "unknown")
            status = str(event.get("status") or event.get("event") or "unknown")
            counts.setdefault(provider, {}).setdefault(status, 0)
            counts[provider][status] += 1
        return counts


class TunedOllama(OllamaClient):
    def __init__(
        self,
        *,
        policy: dict[str, int],
        events: EventSink,
        num_predict: int,
        timeout_seconds: int,
    ) -> None:
        super().__init__(timeout_seconds=timeout_seconds)
        self.policy = policy
        self.events = events
        self.num_predict = num_predict
        self.disabled: dict[str, str] = {}
        self.context_failures: dict[tuple[str, int], str] = {}
        self.context_policy: dict[tuple[str, int], int | None] = {}
        self.last_model: str | None = None
        self.call_index = 0
        self.used_num_gpu_counts: dict[str, dict[str, int]] = {}

    def stop(self, model: str) -> None:
        shell(["ollama", "stop", model], timeout=35)

    def generate(
        self,
        *,
        model: str,
        prompt: str,
        system: str,
        temperature: float = 0.0,
        num_ctx: int = 8192,
        num_gpu: int | None = None,
        keep_alive: str | None = None,
        timeout_seconds: int | None = None,
    ) -> OllamaResponse:
        del num_gpu
        timeout = int(timeout_seconds or self.timeout_seconds)
        self.call_index += 1
        if model in self.disabled:
            raise RuntimeError(f"model disabled after prior timeout: {self.disabled[model]}")
        context_key = (model, int(num_ctx))
        if context_key in self.context_failures:
            raise RuntimeError(self.context_failures[context_key])
        if self.last_model and self.last_model != model:
            self.stop(self.last_model)
        self.last_model = model

        selected = self.context_policy.get(context_key, self.policy.get(model))
        candidates = fallback_candidates(selected)
        last_error = ""
        for attempt, candidate_gpu in enumerate(candidates, start=1):
            event = {
                "provider": "ollama",
                "call_index": self.call_index,
                "model": model,
                "context_length": num_ctx,
                "temperature": temperature,
                "selected_num_gpu": selected,
                "used_num_gpu": candidate_gpu,
                "attempt": attempt,
            }
            payload: dict[str, object] = {
                "model": model,
                "prompt": prompt,
                "system": system,
                "stream": False,
                "keep_alive": keep_alive or "30m",
                "options": {
                    "temperature": temperature,
                    "num_ctx": num_ctx,
                    "num_predict": self.num_predict,
                },
            }
            if candidate_gpu is not None:
                payload["options"]["num_gpu"] = candidate_gpu  # type: ignore[index]
            started = time.perf_counter()
            try:
                data = self._post_generate_with_body(payload, timeout_seconds=timeout)
                response = self._response_from_data(model=model, data=data, wall_seconds=time.perf_counter() - started)
            except Exception as exc:
                wall = time.perf_counter() - started
                last_error = str(exc)
                event.update({"status": "error", "wall_seconds": round(wall, 3), "error": last_error})
                self.events.append(event)
                if is_timeout(last_error):
                    reason = f"timeout at num_gpu={candidate_gpu} ctx={num_ctx} temp={temperature}: {last_error}"
                    self.disabled[model] = reason
                    self.stop(model)
                    print(
                        f"[ollama timeout-disable] {model} ctx={num_ctx} temp={temperature} num_gpu={candidate_gpu}",
                        flush=True,
                    )
                    raise RuntimeError(reason) from exc
                if is_offload_or_load_failure(last_error) and attempt < len(candidates):
                    print(
                        f"[ollama fallback] {model} ctx={num_ctx} num_gpu={candidate_gpu} failed: {last_error[:140]}",
                        flush=True,
                    )
                    self.stop(model)
                    continue
                if is_offload_or_load_failure(last_error):
                    reason = f"context failed after offload fallback ctx={num_ctx}: {last_error}"
                    self.context_failures[context_key] = reason
                    print(f"[ollama context-failed] {model} ctx={num_ctx} reason={last_error[:140]}", flush=True)
                    raise RuntimeError(reason) from exc
                print(
                    f"[ollama error] {self.call_index} {model} ctx={num_ctx} temp={temperature} num_gpu={candidate_gpu} error={last_error[:140]}",
                    flush=True,
                )
                raise

            wall = time.perf_counter() - started
            eval_tps = self._eval_tokens_per_second(data)
            event.update(
                {
                    "status": "ok",
                    "wall_seconds": round(wall, 3),
                    "prompt_eval_count": response.prompt_tokens,
                    "eval_count": response.completion_tokens,
                    "eval_tokens_per_second": round(eval_tps, 4) if eval_tps else None,
                    "total_duration_ns": data.get("total_duration"),
                }
            )
            self.events.append(event)
            self.context_policy[context_key] = candidate_gpu
            key = str(candidate_gpu)
            self.used_num_gpu_counts.setdefault(model, {}).setdefault(key, 0)
            self.used_num_gpu_counts[model][key] += 1
            print(
                f"[ollama ok] {self.call_index} {model} ctx={num_ctx} temp={temperature} num_gpu={candidate_gpu} wall={wall:.1f}s tps={round(eval_tps, 2) if eval_tps else ''}",
                flush=True,
            )
            return response
        raise RuntimeError(last_error or "no Ollama offload candidate succeeded")

    def _post_generate_with_body(self, payload: dict[str, object], *, timeout_seconds: int) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}/api/generate",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = f"HTTP {exc.code} {exc.reason}"
            body_text = exc.read().decode("utf-8", errors="replace").strip()
            if body_text:
                detail = f"{detail}: {body_text}"
            raise RuntimeError(f"Ollama request failed at {self.base_url}: {detail}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Ollama is not reachable at {self.base_url}: {exc}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Ollama returned a non-object JSON payload")
        return data

    def _response_from_data(self, *, model: str, data: dict[str, object], wall_seconds: float) -> OllamaResponse:
        text = str(data.get("response") or "").strip()
        if not text:
            raise RuntimeError("Ollama returned an empty response")
        elapsed = data.get("total_duration")
        elapsed_seconds = float(elapsed) / 1_000_000_000 if isinstance(elapsed, (int, float)) else round(wall_seconds, 3)
        prompt_tokens = int(data["prompt_eval_count"]) if isinstance(data.get("prompt_eval_count"), int) else None
        completion_tokens = int(data["eval_count"]) if isinstance(data.get("eval_count"), int) else None
        return OllamaResponse(
            model=str(data.get("model", model)),
            text=text,
            elapsed_seconds=elapsed_seconds,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    def _eval_tokens_per_second(self, data: dict[str, object]) -> float | None:
        eval_count = data.get("eval_count")
        eval_duration = data.get("eval_duration")
        if not isinstance(eval_count, int) or not isinstance(eval_duration, (int, float)) or not eval_duration:
            return None
        return float(eval_count) / (float(eval_duration) / 1_000_000_000)


class ProgressLMStudio:
    def __init__(self, base: LMStudioClient, *, events: EventSink, timeout_seconds: int) -> None:
        self.base = base
        self.events = events
        self.timeout_seconds = timeout_seconds
        self.disabled: dict[str, str] = {}
        self.call_index = 0

    def list_models(self):
        return self.base.list_models()

    def load_model(self, *, model: str, context_length: int, timeout_seconds: int | None = None):
        print(f"[lmstudio load] {model} ctx={context_length}", flush=True)
        result = self.base.load_model(
            model=model,
            context_length=context_length,
            timeout_seconds=timeout_seconds or self.timeout_seconds,
        )
        self.events.append(
            {
                "provider": "lmstudio",
                "event": "load",
                "model": model,
                "context_length": context_length,
                "ok": result.ok,
                "error": result.error,
                "elapsed_seconds": result.elapsed_seconds,
            }
        )
        if not result.ok and result.error and is_timeout(result.error):
            self.disabled[model] = result.error
        return result

    def unload_model(self, *, model: str, timeout_seconds: int | None = None):
        result = self.base.unload_model(model=model, timeout_seconds=min(timeout_seconds or 60, 120))
        self.events.append(
            {
                "provider": "lmstudio",
                "event": "unload",
                "model": model,
                "ok": result.ok,
                "error": result.error,
                "elapsed_seconds": result.elapsed_seconds,
            }
        )
        print(f"[lmstudio unload] {model} ok={result.ok}", flush=True)
        return result

    def chat(
        self,
        *,
        model: str,
        system: str,
        prompt: str,
        temperature: float = 0.0,
        num_ctx: int | None = None,
        timeout_seconds: int | None = None,
    ):
        if model in self.disabled:
            raise RuntimeError(f"model disabled after prior timeout/load failure: {self.disabled[model]}")
        self.call_index += 1
        started = time.perf_counter()
        try:
            response = self.base.chat(
                model=model,
                system=system,
                prompt=prompt,
                temperature=temperature,
                num_ctx=num_ctx,
                timeout_seconds=timeout_seconds or self.timeout_seconds,
            )
        except Exception as exc:
            wall = time.perf_counter() - started
            message = str(exc)
            if is_timeout(message):
                self.disabled[model] = message
            self.events.append(
                {
                    "provider": "lmstudio",
                    "event": "chat",
                    "status": "error",
                    "model": model,
                    "context_length": num_ctx,
                    "temperature": temperature,
                    "wall_seconds": round(wall, 3),
                    "error": message,
                }
            )
            print(
                f"[lmstudio error] {self.call_index} {model} ctx={num_ctx} temp={temperature} wall={wall:.1f}s error={message[:120]}",
                flush=True,
            )
            raise
        wall = time.perf_counter() - started
        self.events.append(
            {
                "provider": "lmstudio",
                "event": "chat",
                "status": "ok",
                "model": model,
                "context_length": num_ctx,
                "temperature": temperature,
                "wall_seconds": round(wall, 3),
                "tokens_per_second": response.tokens_per_second,
                "completion_tokens": response.completion_tokens,
            }
        )
        print(
            f"[lmstudio ok] {self.call_index} {model} ctx={num_ctx} temp={temperature} wall={wall:.1f}s tps={round(response.tokens_per_second, 2) if response.tokens_per_second else ''}",
            flush=True,
        )
        return response


def write_report(
    *,
    root_report: Path,
    stamp: str,
    summary: object,
    artifacts: dict[str, str],
    elapsed_wall: float,
    policy_payload: dict[str, Any],
    tuning_json: Path,
    policy_path: Path,
    events: EventSink,
    tuned_ollama: TunedOllama,
    providers: list[str],
    contexts: list[int],
    temperatures: list[float],
    timeout_seconds: int,
    num_predict: int,
) -> None:
    payload = summary.as_payload()  # type: ignore[attr-defined]
    aggregate = payload.get("aggregate_rows", [])
    results = payload.get("results", [])
    errors = [item for item in results if item.get("error")]
    provider_counts: dict[str, int] = {}
    for item in results:
        provider = str(item.get("provider") or "unknown")
        provider_counts[provider] = provider_counts.get(provider, 0) + 1

    hw = host_metrics()
    gpu = hw.get("gpu", {}) if isinstance(hw.get("gpu"), dict) else {}
    mem = hw.get("memory", {}) if isinstance(hw.get("memory"), dict) else {}
    lines = [
        "# Tuned Local AI Model Benchmark - 500s Timeout",
        "",
        f"Created: {stamp} UTC",
        f"Wall time: {elapsed_wall / 60:.2f} minutes",
        "",
        "## CPU/GPU Offload Answer",
        "",
        "Yes. Ollama/llama.cpp-style inference can split a model across CPU and GPU by offloading a selected number of transformer layers to GPU with `num_gpu`; non-offloaded layers remain CPU-resident. The best value depends on model size, quantization, context/KV cache size, free VRAM, backend support, and concurrent GPU load. LM Studio is included in the benchmark, but Primordial currently leaves LM Studio layer residency to LM Studio runtime settings rather than setting per-request GPU layers.",
        "",
        "## Hardware Snapshot",
        "",
        f"- GPU total/free at report write: {gpu.get('memory_total_mb', '')}/{gpu.get('memory_free_mb', '')} MB",
        f"- System RAM available at report write: {mem.get('available_mb', '')} MB",
        "",
        "## Benchmark Configuration",
        "",
        f"- Providers: {', '.join(providers)}",
        f"- Timeout: {timeout_seconds}s per generation",
        f"- Context sizes: {', '.join(str(item) for item in contexts)}",
        f"- Temperatures: {', '.join(str(item) for item in temperatures)}",
        f"- Max generated tokens per call: {num_predict}",
        f"- Case count: {len(ModelEvaluationService().default_cases())}",
        f"- Planned models: {len(payload.get('models', []))}",
        f"- Result rows: {len(results)}",
        f"- Provider row counts: `{json.dumps(provider_counts, sort_keys=True)}`",
        "",
        "## Ollama Offload Policy",
        "",
        "| Model | num_gpu | Probe tok/s | Probe residency |",
        "| --- | ---: | ---: | --- |",
    ]
    for model, item in sorted(policy_payload["policy"].items()):
        processor = str(item.get("processor") or "").splitlines()[-1].strip()
        lines.append(f"| `{model}` | {item.get('num_gpu')} | {item.get('tokens_per_second', '')} | `{processor}` |")

    lines.extend(["", "## Recommendations", ""])
    recs = payload.get("recommendations", {})
    if recs:
        lines.extend(f"- `{role}`: `{model}`" for role, model in sorted(recs.items()))
    else:
        lines.append("- No model met the current recommendation thresholds.")

    lines.extend(
        [
            "",
            "## Aggregate Results",
            "",
            "| Provider | Model | Score | Pass Rate | Hallucination | Avg tok/s | Avg latency | Best ctx | Notes |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for row in sorted(aggregate, key=lambda item: float(item.get("aggregate_score") or 0), reverse=True):
        lines.append(
            f"| {row.get('provider', '')} | `{row.get('model', '')}` | {row.get('aggregate_score', '')} | {row.get('pass_rate', '')} | {row.get('hallucination_rate', '')} | {row.get('avg_tokens_sec', '')} | {row.get('avg_latency_sec', '')} | {row.get('best_context_length', '')} | {row.get('notes', '')} |"
        )

    lines.extend(
        [
            "",
            "## Error And Timeout Summary",
            "",
            f"- Rows with errors: {len(errors)}",
            f"- Event counts: `{json.dumps(events.counts(), sort_keys=True)}`",
            f"- Ollama num_gpu use counts: `{json.dumps(tuned_ollama.used_num_gpu_counts, sort_keys=True)}`",
            f"- Ollama context fallback policy: `{json.dumps({f'{model}@{ctx}': gpu for (model, ctx), gpu in tuned_ollama.context_policy.items()}, sort_keys=True)}`",
        ]
    )
    if errors:
        grouped: dict[str, int] = {}
        for item in errors:
            key = f"{item.get('provider')}::{item.get('model')}::{str(item.get('error'))[:100]}"
            grouped[key] = grouped.get(key, 0) + 1
        for key, count in sorted(grouped.items(), key=lambda pair: (-pair[1], pair[0]))[:25]:
            lines.append(f"- {count}x {key}")

    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            f"- Tuning JSON: `{tuning_json}`",
            f"- Tuning policy: `{policy_path}`",
            f"- Benchmark JSON: `{artifacts.get('json_path', '')}`",
            f"- Benchmark CSV: `{artifacts.get('csv_path', '')}`",
            f"- Offload events: `{events.path}`",
        ]
    )
    root_report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Primordial tuned local model benchmark.")
    parser.add_argument("--tuning-dir", type=Path, default=Path("artifacts/model_eval/offload_tuning_20260508T175122Z"))
    parser.add_argument("--timeout", type=int, default=500)
    parser.add_argument("--num-predict", type=int, default=256)
    parser.add_argument("--contexts", default="2048,4096,8192,16384,32768")
    parser.add_argument("--temperatures", default="0.0,0.1")
    parser.add_argument("--providers", default="ollama,lmstudio")
    args = parser.parse_args()

    root = Path.cwd()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    policy_path = args.tuning_dir / "ollama_offload_policy.json"
    tuning_json = args.tuning_dir / "ollama_offload_tuning.json"
    policy_payload = json.loads(policy_path.read_text(encoding="utf-8"))
    policy = {model: int(item["num_gpu"]) for model, item in policy_payload["policy"].items()}
    contexts = parse_csv_ints(args.contexts)
    temperatures = parse_csv_floats(args.temperatures)
    providers = [item.strip() for item in args.providers.split(",") if item.strip()]
    output_dir = root / "artifacts" / "model_eval" / f"tuned_full_500s_{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    events = EventSink(output_dir / "offload_events.jsonl")
    root_report = root / f"MODEL_BENCHMARK_TUNED_500S_{stamp}.md"

    print(f"tuned benchmark artifacts: {output_dir}", flush=True)
    print(f"root report target: {root_report}", flush=True)
    print(
        f"providers={providers} contexts={contexts} temps={temperatures} timeout={args.timeout}s num_predict={args.num_predict}",
        flush=True,
    )
    print(f"ollama policy={policy}", flush=True)

    tuned_ollama = TunedOllama(
        policy=policy,
        events=events,
        num_predict=args.num_predict,
        timeout_seconds=args.timeout,
    )
    lmstudio = ProgressLMStudio(
        LMStudioClient(timeout_seconds=args.timeout),
        events=events,
        timeout_seconds=args.timeout,
    )
    evaluator = ModelEvaluationService(
        ollama=tuned_ollama,
        lmstudio=lmstudio,
        host_metrics_sampler=host_metrics,
    )
    started = time.perf_counter()
    try:
        summary = evaluator.evaluate(
            providers=providers,
            exhaustive=True,
            context_sizes=contexts,
            max_context=max(contexts),
            temperatures=temperatures,
            timeout_seconds=args.timeout,
            include_outputs=False,
            num_gpu=None,
        )
    finally:
        if tuned_ollama.last_model:
            tuned_ollama.stop(tuned_ollama.last_model)
    elapsed_wall = time.perf_counter() - started
    summary.eval_config.update(
        {
            "timeout_seconds": args.timeout,
            "num_predict": args.num_predict,
            "providers": providers,
            "context_sizes": contexts,
            "temperatures": temperatures,
            "offload_tuning_policy_path": str(policy_path),
            "offload_tuning_json_path": str(tuning_json),
            "offload_events_path": str(events.path),
            "ollama_num_gpu_policy": policy,
            "ollama_used_num_gpu_counts": tuned_ollama.used_num_gpu_counts,
            "ollama_context_policy": {f"{model}@{ctx}": gpu for (model, ctx), gpu in tuned_ollama.context_policy.items()},
            "lmstudio_note": "LM Studio layer residency is provider-managed by current Primordial client.",
            "timeout_behavior": "Ollama models are disabled after a 500s timeout; failed contexts are cached after offload fallbacks are exhausted.",
        }
    )
    artifacts = evaluator.write_artifacts(summary, output_dir=output_dir)
    write_report(
        root_report=root_report,
        stamp=stamp,
        summary=summary,
        artifacts=artifacts,
        elapsed_wall=elapsed_wall,
        policy_payload=policy_payload,
        tuning_json=tuning_json,
        policy_path=policy_path,
        events=events,
        tuned_ollama=tuned_ollama,
        providers=providers,
        contexts=contexts,
        temperatures=temperatures,
        timeout_seconds=args.timeout,
        num_predict=args.num_predict,
    )
    print(f"[benchmark complete] wall_minutes={elapsed_wall / 60:.2f}", flush=True)
    print(f"JSON={artifacts.get('json_path')}", flush=True)
    print(f"CSV={artifacts.get('csv_path')}", flush=True)
    print(f"REPORT={root_report}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
