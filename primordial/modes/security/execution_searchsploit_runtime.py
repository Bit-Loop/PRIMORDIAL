from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveSearchsploitRuntimeMixin:
    def _run_searchsploit_research(self, queries: list[str]) -> dict[str, object]:
        policy = self._active_intent_policy()
        if policy is not None and not (policy.public_poc_research and policy.searchsploit_allowed):
            return {
                "matches": [],
                "suppressed_matches": [],
                "examined_examples": [],
                "command_results": [
                    {
                        "tool": "searchsploit",
                        "argv": ["searchsploit", "-j", "<query>"],
                        "executed": False,
                        "returncode": None,
                        "stdout": "",
                        "stderr": "disabled: active operator intent does not allow public PoC research",
                        "timeout": False,
                    }
                ],
            }
        command_results: list[dict[str, object]] = []
        matches_by_id: dict[str, dict[str, object]] = {}
        suppressed_by_id: dict[str, dict[str, object]] = {}
        searched: set[str] = set()
        for query in queries:
            rows = self._searchsploit_rows_for_query(query, command_results, searched)
            if not rows:
                for refined_query in self._refine_empty_searchsploit_query(query):
                    if len(searched) >= 14:
                        break
                    rows.extend(self._searchsploit_rows_for_query(refined_query, command_results, searched, refined_from=query))
                    if rows:
                        break
            for match in rows:
                match_id = str(match.get("edb_id") or match.get("path") or match.get("title"))
                if self._is_suppressed_exploit_match(match):
                    suppressed_by_id.setdefault(match_id, match)
                else:
                    matches_by_id.setdefault(match_id, match)
        matches = sorted(
            matches_by_id.values(),
            key=lambda item: (-int(item.get("score", 0)), str(item.get("title", ""))),
        )[:self.config.max_evidence_items]
        suppressed = sorted(suppressed_by_id.values(), key=lambda item: str(item.get("title", "")))[:self.config.max_evidence_items]
        examples = []
        if policy is None or policy.read_poc_examples:
            examples = self._examine_searchsploit_examples(matches[:4], command_results)
        return {
            "matches": matches,
            "suppressed_matches": suppressed,
            "examined_examples": examples,
            "command_results": command_results,
        }

    def _searchsploit_rows_for_query(
        self,
        query: str,
        command_results: list[dict[str, object]],
        searched: set[str],
        *,
        refined_from: str | None = None,
    ) -> list[dict[str, object]]:
        normalized = self._normalize_searchsploit_query(query)
        if not normalized or normalized.lower() in searched:
            return []
        searched.add(normalized.lower())
        result = self._run_host_command(
            tool="searchsploit",
            argv=["searchsploit", "-j", normalized],
            timeout_seconds=18,
        )
        result["query"] = normalized
        if refined_from:
            result["refined_from"] = refined_from
        command_results.append(result)
        return self._parse_searchsploit_json(str(result.get("stdout", "")), normalized)

    def _refine_empty_searchsploit_query(self, query: str) -> list[str]:
        normalized = self._normalize_searchsploit_query(query)
        if not normalized:
            return []
        refinements: list[str] = []

        def add(value: str) -> None:
            candidate = self._normalize_searchsploit_query(value)
            if candidate and candidate.lower() != normalized.lower() and candidate.lower() not in {item.lower() for item in refinements}:
                refinements.append(candidate)

        version_match = re.search(r"\b([0-9]+(?:\.[0-9]+)+)\b", normalized)
        if version_match:
            major = version_match.group(1).split(".")[0]
            add(normalized.replace(version_match.group(1), major))
        if normalized.lower().startswith("microsoft "):
            add(normalized[10:])
        if " iis " in f" {normalized.lower()} ":
            add(normalized.replace("Microsoft IIS", "IIS"))
        if "active directory" in normalized.lower():
            add("LDAP")
        return refinements[:3]

    def _parse_searchsploit_json(self, stdout: str, query: str) -> list[dict[str, object]]:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        rows = []
        for section in ("RESULTS_EXPLOIT", "RESULTS_PAPER"):
            raw_rows = payload.get(section, [])
            if not isinstance(raw_rows, list):
                continue
            for row in raw_rows:
                if not isinstance(row, dict):
                    continue
                title = str(row.get("Title") or row.get("title") or "").strip()
                path = str(row.get("Path") or row.get("path") or "").strip()
                edb_id = str(row.get("EDB-ID") or row.get("EDB_ID") or row.get("id") or "").strip()
                rows.append(
                    {
                        "query": query,
                        "section": section,
                        "edb_id": edb_id,
                        "title": title,
                        "path": path,
                        "date": row.get("Date") or row.get("date") or "",
                        "author": row.get("Author") or row.get("author") or "",
                        "type": row.get("Type") or row.get("type") or "",
                        "platform": row.get("Platform") or row.get("platform") or "",
                        "score": self._score_searchsploit_match(query, title, path),
                    }
                )
        return rows

    def _score_searchsploit_match(self, query: str, title: str, path: str) -> int:
        lowered = f"{title} {path}".lower()
        score = 0
        for token in query.lower().split():
            if token and token in lowered:
                score += 2
        if re.search(r"\b[0-9]+(?:\.[0-9]+)+\b", query) and re.search(r"\b[0-9]+(?:\.[0-9]+)+\b", lowered):
            score += 4
        if any(term in lowered for term in EXPLOIT_RESEARCH_RCE_TERMS):
            score += 8
        if "remote" in lowered:
            score += 5
        if "/remote/" in lowered:
            score += 5
        if any(term in lowered for term in EXPLOIT_RESEARCH_LOCAL_TERMS):
            score -= 5
        if "authenticated" in lowered:
            score -= 1
        if self._contains_suppressed_exploit_term(lowered):
            score -= 10
        return score

    def _is_suppressed_exploit_match(self, match: dict[str, object]) -> bool:
        haystack = " ".join(str(match.get(key, "")) for key in ("title", "path", "type")).lower()
        return self._contains_suppressed_exploit_term(haystack)

    def _contains_suppressed_exploit_term(self, haystack: str) -> bool:
        return any(term in haystack for term in EXPLOIT_RESEARCH_SUPPRESSED_TERMS)

    def _examine_searchsploit_examples(
        self,
        matches: list[dict[str, object]],
        command_results: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        examples: list[dict[str, object]] = []
        for match in matches:
            edb_id = str(match.get("edb_id", "")).strip()
            if not edb_id:
                continue
            result = self._run_host_command_with_env(
                tool="searchsploit",
                argv=["searchsploit", "-x", edb_id],
                timeout_seconds=15,
                env={"PAGER": "cat"},
            )
            result["query"] = f"examine:{edb_id}"
            command_results.append(result)
            if not result.get("executed") or result.get("timeout"):
                continue
            text = str(result.get("stdout", "")).strip()
            if not text:
                continue
            examples.append(
                {
                    "edb_id": edb_id,
                    "title": match.get("title", ""),
                    "path": match.get("path", ""),
                    "excerpt": text[:6000],
                    "truncated": len(text) > 6000,
                }
            )
        return examples

    def _run_host_command_with_env(
        self,
        *,
        tool: str,
        argv: list[str],
        timeout_seconds: int,
        env: dict[str, str],
    ) -> dict[str, object]:
        if shutil.which(argv[0]) is None:
            return {
                "tool": tool,
                "argv": argv,
                "executed": False,
                "returncode": None,
                "stdout": "",
                "stderr": "tool not found",
                "timeout": False,
            }
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                env={**dict(os.environ), **env},
            )
            return {
                "tool": tool,
                "argv": argv,
                "executed": True,
                "returncode": completed.returncode,
                "stdout": self._truncate_command_output(completed.stdout),
                "stderr": self._truncate_command_output(completed.stderr),
                "timeout": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "tool": tool,
                "argv": argv,
                "executed": True,
                "returncode": None,
                "stdout": self._truncate_command_output(exc.stdout or ""),
                "stderr": self._truncate_command_output(exc.stderr or "command timed out"),
                "timeout": True,
            }
