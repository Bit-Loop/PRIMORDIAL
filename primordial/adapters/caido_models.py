from __future__ import annotations

from dataclasses import dataclass

from primordial.adapters.caido_redaction import redact_request_path


@dataclass(frozen=True, slots=True)
class CaidoConnection:
    graphql_url: str
    api_token: str
    migrated_from: str = ""


@dataclass(frozen=True, slots=True)
class ParsedRawRequest:
    method: str
    host: str
    port: int
    is_tls: bool
    sni: str | None
    path: str
    raw: str
    raw_base64: str
    raw_sha256: str
    headers: dict[str, str]

    @property
    def connection_info(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "isTLS": self.is_tls,
            "SNI": self.sni or self.host,
        }

    def as_payload(self) -> dict[str, object]:
        return {
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "is_tls": self.is_tls,
            "sni": self.sni,
            "path": redact_request_path(self.path),
            "raw_sha256": self.raw_sha256,
            "headers": sorted(self.headers),
            "connection": self.connection_info,
        }
