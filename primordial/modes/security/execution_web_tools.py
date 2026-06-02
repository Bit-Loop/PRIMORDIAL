from __future__ import annotations

from primordial.modes.security.execution_common import _SurfaceParser
from primordial.modes.security.execution_common import *


class PrimitiveWebToolMixin:
    def _content_discovery_bases(self, target_id: str) -> list[str]:
        bases: list[str] = []
        seen: set[str] = set()
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            effective_url = evidence.metadata.get("effective_url")
            status_code = evidence.metadata.get("status_code")
            if not isinstance(effective_url, str) or not effective_url.startswith(("http://", "https://")):
                continue
            if isinstance(status_code, int) and status_code >= 500:
                continue
            parsed = parse.urlsplit(effective_url)
            if not parsed.scheme or not parsed.netloc:
                continue
            base = f"{parsed.scheme}://{parsed.netloc}/"
            if base in seen:
                continue
            seen.add(base)
            bases.append(base)
        return bases[:4]

    def _content_discovery_words(self, metadata: dict[str, object]) -> list[str]:
        limit = int(metadata.get("content_word_limit", 420) or 420)
        limit = max(50, min(limit, 2000))
        wordlist_path = str(metadata.get("content_wordlist", self.config.content_discovery_wordlist))
        words: list[str] = []
        try:
            with open(wordlist_path, encoding="utf-8", errors="ignore") as wordlist:
                raw_lines = wordlist.read().splitlines()
        except OSError:
            raw_lines = [
                "admin",
                "api",
                "app",
                "backup",
                "config",
                "dev",
                "files",
                "login",
                "portal",
                "private",
                "test",
                "upload",
            ]
        for raw in raw_lines:
            word = raw.strip().strip("/")
            if not word or word.startswith("#") or len(word) > 80:
                continue
            if word not in words:
                words.append(word)
            if len(words) >= limit:
                break
        return words

    def _run_web_content_discovery(self, bases: list[str], words: list[str]) -> list[dict[str, object]]:
        candidates: list[tuple[str, str]] = []
        for base in bases:
            for word in words:
                for extension in CONTENT_DISCOVERY_EXTENSIONS:
                    if extension and word.lower().endswith(extension):
                        continue
                    candidates.append((base, f"/{word}{extension}"))
        discovered: list[dict[str, object]] = []
        seen_urls: set[str] = set()
        with ThreadPoolExecutor(max_workers=18) as executor:
            future_map = {
                executor.submit(self._probe_content_candidate, base, path): (base, path)
                for base, path in candidates
            }
            for future in as_completed(future_map):
                probe = future.result()
                if not probe:
                    continue
                url = str(probe["url"])
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                discovered.append(probe)
                if len(discovered) >= 200:
                    break
        return sorted(discovered, key=lambda item: (int(item["status_code"]), str(item["url"])))

    def _probe_content_candidate(self, base_url: str, path: str) -> dict[str, object] | None:
        url = parse.urljoin(base_url, path.lstrip("/"))
        req = request.Request(url, headers={"User-Agent": "Primordial/0.1", "Accept": "*/*"}, method="GET")
        try:
            with request.urlopen(
                req,
                timeout=3,
                context=ssl._create_unverified_context() if url.startswith("https://") else None,
            ) as response:
                body = response.read(4096)
                status = int(response.status)
                headers = {key.lower(): value for key, value in response.headers.items()}
                final_url = response.geturl()
        except error.HTTPError as exc:
            body = exc.read(4096)
            status = int(exc.code)
            headers = {key.lower(): value for key, value in exc.headers.items()}
            final_url = exc.geturl()
        except (error.URLError, OSError, ssl.SSLError, ValueError):
            return None
        if status not in CONTENT_DISCOVERY_INTERESTING_STATUS:
            return None
        return {
            "url": self._sanitize_surface_url(final_url),
            "url_redacted": True,
            "path": path,
            "status_code": status,
            "content_type": headers.get("content-type", ""),
            "content_length": headers.get("content-length") or len(body),
            "server": headers.get("server", ""),
            "title": self._title_from_body(headers.get("content-type", ""), body),
        }

    def _title_from_body(self, content_type: str, body: bytes) -> str:
        if "html" not in content_type.lower() or not body:
            return ""
        decoded = self._decode_response_body(body, {})
        parser = _SurfaceParser()
        try:
            parser.feed(decoded)
        except (ValueError, AssertionError):
            return ""
        return parser.title

    def _summarize_content_discovery(
        self,
        discovered: list[dict[str, object]],
        bases: list[str],
        word_count: int,
    ) -> str:
        if not discovered:
            return f"Bounded web content discovery checked {len(bases)} base URL(s) with {word_count} words and found no interesting paths."
        n = self.config.max_evidence_items
        path_summary = ", ".join(f"{item['path']}({item['status_code']})" for item in discovered[:n])
        suffix = "" if len(discovered) <= n else f" and {len(discovered) - n} more"
        return f"Bounded web content discovery found {len(discovered)} interesting path(s): {path_summary}{suffix}."

    def _build_content_discovery_note(
        self,
        discovered: list[dict[str, object]],
        bases: list[str],
        word_count: int,
    ) -> str:
        lines = [
            f"Base URLs: {', '.join(bases)}",
            f"Words checked: {word_count}",
            f"Interesting paths: {len(discovered)}",
        ]
        for item in discovered[:self.config.max_evidence_items]:
            title = f" title={item['title']!r}" if item.get("title") else ""
            lines.append(f"- {item['status_code']} {item['url']} {item.get('content_type', '')}{title}")
        if not discovered:
            lines.append("No interesting paths were observed in the bounded wordlist run.")
        lines.append("This is content inventory only; no authentication or exploit attempt was performed.")
        return "\n".join(lines)

    def _target_domain_guess(self, target, assets) -> str:
        if isinstance(target.metadata.get("domain"), str) and target.metadata["domain"]:
            return str(target.metadata["domain"])
        if "." in target.handle and not self._looks_like_ip(target.handle):
            return target.handle.strip(".")
        for asset in assets:
            candidate = ""
            if asset.asset_type == "hostname":
                candidate = asset.asset
            elif asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                candidate = parse.urlsplit(asset.asset).hostname or ""
            if "." in candidate and not self._looks_like_ip(candidate):
                return candidate.strip(".")
        return ""

    def _looks_like_ip(self, value: str) -> bool:
        try:
            socket.inet_aton(value)
        except OSError:
            return False
        return value.count(".") == 3
