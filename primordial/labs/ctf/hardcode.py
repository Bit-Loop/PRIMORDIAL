from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Iterable, Mapping, Sequence
import hashlib
import re


FLAG_PATTERN = re.compile(r"\b(?:flag|ctf)\{[^}\s]{4,}\}", re.IGNORECASE)
TARGET_IP_PATTERN = re.compile(r"\b(?:10|172|192)\.(?:\d{1,3}\.){2}\d{1,3}\b")
CHALLENGE_CONDITIONAL_PATTERN = re.compile(
    r"\b(?:if|elif)\s+[^:\n]*"
    r"(?:target(?:\.name|_name|\.id|_id)|challenge(?:\.name|_name|\.id|_id)|lab(?:\.name|_name|\.id|_id))"
    r"[^:\n]*==\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
CREDENTIAL_LITERAL_PATTERN = re.compile(
    r"\b(?:password|passwd|pwd|username|user)\s*=\s*[\"'][^\"'\s]{4,}[\"']",
    re.IGNORECASE,
)
CHALLENGE_PATH_LITERAL_PATTERN = re.compile(
    r"\b(?:path|url|endpoint|route)\s*=\s*[\"']/(?:[A-Za-z0-9._~%-]+/)+[A-Za-z0-9._~%-]*[\"']",
    re.IGNORECASE,
)
CHALLENGE_BANNER_LITERAL_PATTERN = re.compile(
    r"\b(?:if|elif)\s+[\"'][^\"']{4,}[\"']\s+in\s+(?:banner|hostname|host_name|target_name|challenge_name)\b",
    re.IGNORECASE,
)
STATIC_SERVICE_PORT_PATTERN = re.compile(
    r"\b(?:target_port|service_port|port)\s*=\s*(?:[1-9][0-9]{3,4})\b",
    re.IGNORECASE,
)
CHALLENGE_FILENAME_LITERAL_PATTERN = re.compile(
    r"\b(?:file|filename|payload_file|artifact|path)\s*=\s*[\"'][A-Za-z0-9]+(?:[-_][A-Za-z0-9]+){2,}\."
    r"(?:bak|conf|db|json|key|php|sql|txt|zip)[\"']",
    re.IGNORECASE,
)
STRING_LITERAL_PATTERN = re.compile(r"([\"'])(.*?)\1")
COMMAND_CHAIN_TOOL_PATTERN = re.compile(r"\b(?:curl|ffuf|gobuster|hydra|nmap|sqlmap|wfuzz)\b", re.IGNORECASE)
COMMAND_BIGRAM_REVIEW_THRESHOLD = 0.70
COMMAND_BIGRAM_MINIMUM = 8
TEXT_SPAN_REVIEW_THRESHOLD = 0.92
TEXT_SPAN_MINIMUM = 40
CODE_SIMHASH_REVIEW_DISTANCE = 3
CODE_SIMHASH_MINIMUM_TOKENS = 8
REVIEW_RULES = frozenset(
    {
        "command_sequence_similarity",
        "text_span_similarity",
        "code_simhash_similarity",
    }
)
RULE_ORDER = {
    "raw_flag": 0,
    "target_ip_literal": 1,
    "challenge_specific_conditional": 2,
    "credential_literal": 3,
    "scripted_command_chain": 4,
    "challenge_path_literal": 5,
    "challenge_banner_literal": 6,
    "static_service_port": 7,
    "challenge_filename_literal": 8,
    "box_name_literal": 9,
    "hidden_solution_snippet": 10,
    "command_sequence_similarity": 11,
    "text_span_similarity": 12,
    "code_simhash_similarity": 13,
}
LINE_REGEX_RULES = (
    (FLAG_PATTERN, "raw_flag", "raw flag-like material is not allowed"),
    (TARGET_IP_PATTERN, "target_ip_literal", "target IP literals must not be baked into behavior"),
    (CHALLENGE_CONDITIONAL_PATTERN, "challenge_specific_conditional", "challenge-specific conditionals are not generalized solve logic"),
    (CREDENTIAL_LITERAL_PATTERN, "credential_literal", "credential literals must not be baked into generated solver behavior"),
    (CHALLENGE_PATH_LITERAL_PATTERN, "challenge_path_literal", "challenge-specific path literals must not be baked into generated solver behavior"),
    (CHALLENGE_BANNER_LITERAL_PATTERN, "challenge_banner_literal", "challenge-specific banner literals must not drive generated solver behavior"),
    (STATIC_SERVICE_PORT_PATTERN, "static_service_port", "static service port assumptions must come from observed evidence"),
    (CHALLENGE_FILENAME_LITERAL_PATTERN, "challenge_filename_literal", "challenge-specific filename literals must not be baked into generated solver behavior"),
)


@dataclass(frozen=True, slots=True)
class HardcodeFinding:
    rule_id: str
    path: str
    line: int
    message: str
    severity: str = ""

    def __post_init__(self) -> None:
        if not self.severity:
            object.__setattr__(self, "severity", _severity_for_rule(self.rule_id))


@dataclass(frozen=True, slots=True)
class HardcodeScanResult:
    status: str
    findings: tuple[HardcodeFinding, ...]


class HardcodeScanner:
    @staticmethod
    def scan(
        files: Mapping[str, str],
        *,
        hidden_solution_snippets: Iterable[str] = (),
        box_names: Iterable[str] = (),
        reference_command_sequences: Iterable[Sequence[str]] = (),
        reference_text_spans: Iterable[str] = (),
        reference_code_spans: Iterable[str] = (),
    ) -> HardcodeScanResult:
        findings: list[HardcodeFinding] = []
        snippets = tuple(snippet.strip() for snippet in hidden_solution_snippets if len(snippet.strip()) >= 12)
        box_name_literals = tuple(_normalize_box_name(name) for name in box_names if _normalize_box_name(name))
        command_sequences = tuple(
            tuple(command.strip() for command in sequence if command.strip()) for sequence in reference_command_sequences
        )
        text_spans = tuple(span.strip() for span in reference_text_spans if len(_normalize_text_span(span)) >= TEXT_SPAN_MINIMUM)
        code_spans = tuple(
            span for span in reference_code_spans if len(_normalize_code_tokens(span)) >= CODE_SIMHASH_MINIMUM_TOKENS
        )
        for path, content in files.items():
            text = str(content)
            findings.extend(
                _scan_text(
                    str(path),
                    text,
                    hidden_solution_snippets=snippets,
                    box_names=box_name_literals,
                    reference_command_sequences=command_sequences,
                    reference_text_spans=text_spans,
                    reference_code_spans=code_spans,
                )
            )
        findings = _deduplicate_findings(findings)
        findings.sort(key=lambda finding: (RULE_ORDER[finding.rule_id], finding.path, finding.line))
        status = "fail" if findings else "pass"
        return HardcodeScanResult(status=status, findings=tuple(findings))


def _scan_text(
    path: str,
    content: str,
    *,
    hidden_solution_snippets: tuple[str, ...],
    box_names: tuple[str, ...],
    reference_command_sequences: tuple[tuple[str, ...], ...],
    reference_text_spans: tuple[str, ...],
    reference_code_spans: tuple[str, ...],
) -> tuple[HardcodeFinding, ...]:
    findings: list[HardcodeFinding] = []
    findings.extend(_line_findings(path, content, hidden_solution_snippets=hidden_solution_snippets, box_names=box_names))
    findings.extend(_multiline_hidden_snippet_findings(path, content, hidden_solution_snippets))
    findings.extend(_command_similarity_findings(path, content, reference_command_sequences))
    findings.extend(_text_span_similarity_findings(path, content, reference_text_spans))
    findings.extend(_code_similarity_findings(path, content, reference_code_spans))
    return tuple(findings)


def _line_findings(
    path: str,
    content: str,
    *,
    hidden_solution_snippets: tuple[str, ...],
    box_names: tuple[str, ...],
) -> tuple[HardcodeFinding, ...]:
    findings: list[HardcodeFinding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        findings.extend(_regex_line_findings(path, line, line_number))
        if _looks_like_scripted_command_chain(line):
            findings.append(_finding("scripted_command_chain", path, line_number, "scripted command chains look like target-specific solve traces"))
        if _contains_box_name_literal(line, box_names):
            findings.append(_finding("box_name_literal", path, line_number, "box names must not be baked into generated solver behavior"))
        if any(snippet in line for snippet in hidden_solution_snippets):
            findings.append(_finding("hidden_solution_snippet", path, line_number, "hidden solution snippets must not appear in generated solver behavior"))
    return tuple(findings)


def _regex_line_findings(path: str, line: str, line_number: int) -> tuple[HardcodeFinding, ...]:
    return tuple(
        _finding(rule_id, path, line_number, message)
        for pattern, rule_id, message in LINE_REGEX_RULES
        if pattern.search(line)
    )


def _multiline_hidden_snippet_findings(
    path: str,
    content: str,
    hidden_solution_snippets: tuple[str, ...],
) -> tuple[HardcodeFinding, ...]:
    findings: list[HardcodeFinding] = []
    for snippet in (item for item in hidden_solution_snippets if "\n" in item):
        offset = content.find(snippet)
        if offset != -1:
            findings.append(
                _finding(
                    "hidden_solution_snippet",
                    path,
                    content[:offset].count("\n") + 1,
                    "hidden solution snippets must not appear in generated solver behavior",
                )
            )
    return tuple(findings)


def _command_similarity_findings(
    path: str,
    content: str,
    reference_command_sequences: tuple[tuple[str, ...], ...],
) -> tuple[HardcodeFinding, ...]:
    findings: list[HardcodeFinding] = []
    generated_commands = tuple(line.strip() for line in content.splitlines() if line.strip())
    for sequence in reference_command_sequences:
        if len(sequence) >= 4 and (
            _contains_command_sequence(generated_commands, sequence)
            or _command_bigram_similarity(generated_commands, sequence) >= COMMAND_BIGRAM_REVIEW_THRESHOLD
        ):
            findings.append(
                _finding(
                    "command_sequence_similarity",
                    path,
                    _command_sequence_line(content, _first_overlapping_command(generated_commands, sequence)),
                    "command sequence bigram similarity requires review before accepting generated solver behavior",
                ),
            )
    return tuple(findings)


def _text_span_similarity_findings(
    path: str,
    content: str,
    reference_text_spans: tuple[str, ...],
) -> tuple[HardcodeFinding, ...]:
    findings: list[HardcodeFinding] = []
    normalized_content = _normalize_text_span(content)
    for span in reference_text_spans:
        normalized_span = _normalize_text_span(span)
        matched_text = _matching_text_span(normalized_content, normalized_span)
        if matched_text is not None:
            findings.append(
                _finding(
                    "text_span_similarity",
                    path,
                    _text_span_line(content, matched_text),
                    "normalized text span similarity requires review before accepting generated solver behavior",
                )
            )
    return tuple(findings)


def _code_similarity_findings(
    path: str,
    content: str,
    reference_code_spans: tuple[str, ...],
) -> tuple[HardcodeFinding, ...]:
    findings: list[HardcodeFinding] = []
    content_code_tokens = _normalize_code_tokens(content)
    if len(content_code_tokens) >= CODE_SIMHASH_MINIMUM_TOKENS:
        for reference_code in reference_code_spans:
            reference_code_tokens = _normalize_code_tokens(reference_code)
            matched_tokens = _matching_code_simhash_tokens(content_code_tokens, reference_code_tokens)
            if matched_tokens is not None:
                findings.append(
                    _finding(
                        "code_simhash_similarity",
                        path,
                        _code_span_line(content, matched_tokens),
                        "code SimHash similarity requires review before accepting generated solver behavior",
                    )
                )
    return tuple(findings)


def _finding(rule_id: str, path: str, line: int, message: str) -> HardcodeFinding:
    return HardcodeFinding(rule_id=rule_id, path=path, line=line, message=message)


def _looks_like_scripted_command_chain(line: str) -> bool:
    separators = line.count("&&") + line.count(";") + len(re.findall(r"\s\|\s", line))
    return separators >= 2 and COMMAND_CHAIN_TOOL_PATTERN.search(line) is not None


def _contains_box_name_literal(line: str, box_names: tuple[str, ...]) -> bool:
    if not box_names:
        return False
    for match in STRING_LITERAL_PATTERN.finditer(line):
        normalized_literal = _normalize_box_name(match.group(2))
        if any(name and name in normalized_literal for name in box_names):
            return True
    return False


def _normalize_box_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _severity_for_rule(rule_id: str) -> str:
    return "review" if rule_id in REVIEW_RULES else "hard_fail"


def _deduplicate_findings(findings: list[HardcodeFinding]) -> list[HardcodeFinding]:
    deduplicated: list[HardcodeFinding] = []
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line)
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated


def _contains_command_sequence(generated_commands: tuple[str, ...], reference_sequence: tuple[str, ...]) -> bool:
    window_size = len(reference_sequence)
    return any(generated_commands[index : index + window_size] == reference_sequence for index in range(len(generated_commands)))


def _command_bigram_similarity(generated_commands: tuple[str, ...], reference_sequence: tuple[str, ...]) -> float:
    generated_bigrams = _command_bigrams(generated_commands)
    reference_bigrams = _command_bigrams(reference_sequence)
    if len(generated_bigrams) < COMMAND_BIGRAM_MINIMUM or len(reference_bigrams) < COMMAND_BIGRAM_MINIMUM:
        return 0.0
    return len(generated_bigrams & reference_bigrams) / len(generated_bigrams | reference_bigrams)


def _command_bigrams(commands: tuple[str, ...]) -> set[tuple[str, str]]:
    return set(zip(commands, commands[1:]))


def _normalize_text_span(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def _text_span_similarity(content: str, reference_span: str) -> float:
    if len(content) < TEXT_SPAN_MINIMUM or len(reference_span) < TEXT_SPAN_MINIMUM:
        return 0.0
    return SequenceMatcher(a=content, b=reference_span).ratio()


def _matching_text_span(content: str, reference_span: str) -> str | None:
    if _text_span_similarity(content, reference_span) >= TEXT_SPAN_REVIEW_THRESHOLD:
        return reference_span
    content_tokens = content.split()
    reference_tokens = reference_span.split()
    if not reference_tokens or len(content_tokens) < len(reference_tokens):
        return None
    window_size = len(reference_tokens)
    for index in range(len(content_tokens) - window_size + 1):
        window = " ".join(content_tokens[index : index + window_size])
        if _text_span_similarity(window, reference_span) >= TEXT_SPAN_REVIEW_THRESHOLD:
            return window
    return None


def _text_span_line(content: str, reference_span: str) -> int:
    reference_tokens = _normalize_text_span(reference_span).split()
    if not reference_tokens:
        return 1
    for line_number, line in enumerate(content.splitlines(), start=1):
        line_tokens = _normalize_text_span(line).split()
        if _contains_token_window(line_tokens, reference_tokens):
            return line_number
    first_token = reference_tokens[0]
    for line_number, line in enumerate(content.splitlines(), start=1):
        if first_token in _normalize_text_span(line).split():
            return line_number
    return 1


def _contains_token_window(line_tokens: list[str], reference_tokens: list[str]) -> bool:
    window_size = len(reference_tokens)
    if len(line_tokens) < window_size:
        return False
    return any(line_tokens[index : index + window_size] == reference_tokens for index in range(len(line_tokens) - window_size + 1))


def _normalize_code_tokens(code: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[a-z_][a-z0-9_]*|[0-9]+", code.lower()))


def _simhash_tokens(tokens: tuple[str, ...]) -> int:
    weights = [0] * 64
    for token in tokens:
        value = int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if value & (1 << bit) else -1
    result = 0
    for bit, weight in enumerate(weights):
        if weight >= 0:
            result |= 1 << bit
    return result


def _simhash_distance(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def _matching_code_simhash_tokens(
    content_tokens: tuple[str, ...], reference_tokens: tuple[str, ...]
) -> tuple[str, ...] | None:
    if len(content_tokens) < CODE_SIMHASH_MINIMUM_TOKENS or len(reference_tokens) < CODE_SIMHASH_MINIMUM_TOKENS:
        return None
    reference_simhash = _simhash_tokens(reference_tokens)
    if _simhash_distance(_simhash_tokens(content_tokens), reference_simhash) <= CODE_SIMHASH_REVIEW_DISTANCE:
        return reference_tokens
    window_size = len(reference_tokens)
    if len(content_tokens) < window_size:
        return None
    for index in range(len(content_tokens) - window_size + 1):
        window = content_tokens[index : index + window_size]
        if _simhash_distance(_simhash_tokens(window), reference_simhash) <= CODE_SIMHASH_REVIEW_DISTANCE:
            return window
    return None


def _code_span_line(content: str, reference_tokens: tuple[str, ...]) -> int:
    if not reference_tokens:
        return 1
    for line_number, line in enumerate(content.splitlines(), start=1):
        line_tokens = _normalize_code_tokens(line)
        if line_tokens and reference_tokens[: len(line_tokens)] == line_tokens:
            return line_number
    first_token = reference_tokens[0]
    for line_number, line in enumerate(content.splitlines(), start=1):
        if first_token in _normalize_code_tokens(line):
            return line_number
    return 1


def _first_overlapping_command(generated_commands: tuple[str, ...], reference_sequence: tuple[str, ...]) -> str:
    reference_bigrams = _command_bigrams(reference_sequence)
    for left, right in zip(generated_commands, generated_commands[1:]):
        if (left, right) in reference_bigrams:
            return left
    return reference_sequence[0]


def _command_sequence_line(content: str, first_command: str) -> int:
    for line_number, line in enumerate(content.splitlines(), start=1):
        if line.strip() == first_command:
            return line_number
    return 1
