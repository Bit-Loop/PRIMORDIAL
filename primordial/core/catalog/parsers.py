from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class ParserContract:
    id: str
    input_kind: str
    output_kind: str
    description: str = ""
