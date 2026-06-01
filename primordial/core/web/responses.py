from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class WebResponse:
    status: int
    body: bytes
    content_type: str
    headers: dict[str, str] = field(default_factory=dict)
