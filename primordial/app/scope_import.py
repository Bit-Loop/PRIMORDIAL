from __future__ import annotations


def normalize_scope_assets(raw_assets: object, handle: str, infer_asset_type) -> list[dict[str, object]]:
    if not isinstance(raw_assets, list):
        raise ValueError(f"assets for {handle} must be a list")
    normalized_assets = []
    for asset_payload in raw_assets or [handle]:
        if isinstance(asset_payload, dict):
            raw_asset = str(asset_payload["asset"])
            normalized_assets.append(
                {
                    "asset": raw_asset,
                    "asset_type": str(asset_payload.get("asset_type", infer_asset_type(raw_asset))),
                    "metadata": dict(asset_payload.get("metadata", {})),
                }
            )
        else:
            raw_asset = str(asset_payload)
            normalized_assets.append(
                {
                    "asset": raw_asset,
                    "asset_type": infer_asset_type(raw_asset),
                    "metadata": {},
                }
            )
    return normalized_assets
