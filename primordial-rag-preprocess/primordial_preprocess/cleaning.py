from __future__ import annotations

from collections import Counter
import re


def normalize_whitespace(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()


def remove_page_number_only_lines(text: str) -> str:
    lines = [line for line in text.splitlines() if not re.fullmatch(r"\s*(page\s*)?\d+\s*", line, flags=re.I)]
    return "\n".join(lines)


def remove_repeated_headers_footers(pages: list[str]) -> list[str]:
    if len(pages) < 4:
        return pages
    first_lines = [page.splitlines()[0].strip() for page in pages if page.splitlines()]
    last_lines = [page.splitlines()[-1].strip() for page in pages if page.splitlines()]
    repeated = {
        line
        for line, count in (Counter(first_lines) + Counter(last_lines)).items()
        if line and count >= max(3, len(pages) // 2) and len(line) < 160
    }
    cleaned: list[str] = []
    for page in pages:
        lines = page.splitlines()
        if lines and lines[0].strip() in repeated:
            lines = lines[1:]
        if lines and lines[-1].strip() in repeated:
            lines = lines[:-1]
        cleaned.append("\n".join(lines))
    return cleaned


def clean_text(text: str) -> str:
    return normalize_whitespace(remove_page_number_only_lines(text))
