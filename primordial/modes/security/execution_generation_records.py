from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveGenerationRecordMixin:
    def _target_active_generation(self, target) -> str | None:
        if target is None or target.metadata.get("active_ip_generation") is None:
            return None
        return str(target.metadata.get("active_ip_generation"))

    def _records_for_generation(self, records: list[object], active_generation: str | None) -> list[object]:
        if active_generation is None:
            return records
        selected = []
        for record in records:
            metadata = getattr(record, "metadata", {})
            if isinstance(metadata, dict) and str(metadata.get("active_ip_generation", "")) == active_generation:
                selected.append(record)
        return selected

    def _task_records_for_generation(self, tasks: list[Task], active_generation: str | None) -> list[Task]:
        if active_generation is None:
            return tasks
        return [
            task
            for task in tasks
            if task.metadata.get("active_ip_generation") is None
            or str(task.metadata.get("active_ip_generation", "")) == active_generation
        ]

    def _task_generation_records(self, task: Task, target, records: list[object]) -> list[object]:
        generation = str(task.metadata.get("active_ip_generation", "")).strip() or self._target_active_generation(target)
        return self._records_for_generation(records, generation)

    def _write_artifact(self, task: Task, target_id: str, prefix: str, payload: dict[str, object]) -> ArtifactRecord:
        task_dir = self.config.artifacts_dir / (task.id or "task")
        task_dir.mkdir(parents=True, exist_ok=True)
        path = task_dir / f"{prefix}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        content = path.read_bytes()
        return ArtifactRecord(
            task_id=task.id,
            target_id=target_id,
            kind=ArtifactKind.TOOL_OUTPUT,
            path=str(path),
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            metadata={"prefix": prefix},
        )

    def _target_scope_assets(self, target) -> list[object]:
        assets = self.store.list_scope_assets(target.id)
        active_ip = str(target.metadata.get("active_ip") or "").strip()
        if not active_ip:
            return assets
        active = []
        hostnames = []
        webapps = []
        others = []
        for asset in assets:
            if asset.asset == active_ip:
                active.append(asset)
            elif asset.asset_type == "hostname":
                hostnames.append(asset)
            elif asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                webapps.append(asset)
            elif asset.asset_type != "ip":
                others.append(asset)
        # Network primitives should use the operator-confirmed IP first while retaining
        # hostnames for Host-header and domain inference.
        return active + hostnames + webapps + others
