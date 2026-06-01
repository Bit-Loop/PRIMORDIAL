from __future__ import annotations

import json
from urllib import parse

from primordial.adapters.caido_constants import REQUEST_SUMMARY_FIELDS


def build_target_httpql(terms: list[str], *, max_terms: int = 8) -> str:
    clauses: list[str] = []
    seen: set[str] = set()
    for raw_term in terms:
        term = raw_term.strip()
        if not term or term in seen:
            continue
        seen.add(term)
        parsed = parse.urlsplit(term if "://" in term else f"//{term}")
        host = parsed.hostname or term
        if not host:
            continue
        escaped_host = httpql_string(host)
        if parsed.path and parsed.path not in {"", "/"}:
            clauses.append(f'(req.host.eq:"{escaped_host}" AND req.path.cont:"{httpql_string(parsed.path)}")')
        else:
            clauses.append(f'req.host.eq:"{escaped_host}"')
        if len(clauses) >= max_terms:
            break
    return " OR ".join(clauses)


def httpql_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def graphql_string_literal(value: str) -> str:
    return json.dumps(value)


def request_search_attempts(*, httpql: str, limit: int, offset: int) -> list[dict[str, object]]:
    attempts: list[dict[str, object]] = []
    field_shapes = [
        ("requestsByOffset", {"limit": limit, "offset": offset}, ["limit: $limit", "offset: $offset"]),
        ("requests", {"limit": limit}, ["first: $limit"]),
    ]
    for field_name, base_variables, base_args in field_shapes:
        for filter_strategy, filter_var_defs, filter_variables, filter_arg in _filter_shapes(httpql):
            for include_order in (True, False):
                variables = dict(base_variables)
                variables.update(filter_variables)
                arg_lines = list(base_args)
                if filter_arg:
                    arg_lines.append(filter_arg)
                if include_order:
                    arg_lines.append("order: { by: CREATED_AT, ordering: DESC }")
                variable_defs = "$limit: Int!"
                if field_name == "requestsByOffset":
                    variable_defs += ", $offset: Int!"
                if filter_var_defs:
                    variable_defs = filter_var_defs + variable_defs
                args = "\n                    ".join(arg_lines)
                attempts.append(_attempt(field_name, filter_strategy, variable_defs, args, variables, include_order))
    return attempts


def compact_search_attempts(attempts: list[dict[str, object]]) -> list[dict[str, object]]:
    compacted = []
    seen_errors: set[tuple[str, str, str]] = set()
    for item in attempts:
        error_text = str(item.get("error") or "")
        key = (str(item.get("query_field") or ""), str(item.get("filter_strategy") or ""), error_text)
        if error_text and key in seen_errors:
            continue
        if error_text:
            seen_errors.add(key)
        compacted.append(
            {
                "query_field": item.get("query_field") or "",
                "filter_strategy": item.get("filter_strategy") or "",
                "ok": bool(item.get("ok")),
                "error": error_text,
                "auth_error": bool(item.get("auth_error")),
            }
        )
    return compacted[-8:]


def _filter_shapes(httpql: str) -> list[tuple[str, str, dict[str, object], str]]:
    if not httpql:
        return [("unfiltered", "", {}, "")]
    httpql_literal = graphql_string_literal(httpql)
    return [
        ("variable:HTTPQLInput.code", "$filter: HTTPQLInput!, ", {"filter": {"code": httpql}}, "filter: $filter"),
        ("inline:HTTPQLInput.code", "", {}, f"filter: {{ code: {httpql_literal} }}"),
        ("variable:HTTPQLInput.query", "$filter: HTTPQLInput!, ", {"filter": {"query": httpql}}, "filter: $filter"),
        ("inline:HTTPQLInput.query", "", {}, f"filter: {{ query: {httpql_literal} }}"),
        ("variable:String", "$filter: String!, ", {"filter": httpql}, "filter: $filter"),
        ("inline:String", "", {}, f"filter: {httpql_literal}"),
    ]


def _attempt(
    field_name: str,
    filter_strategy: str,
    variable_defs: str,
    args: str,
    variables: dict[str, object],
    include_order: bool,
) -> dict[str, object]:
    order_label = "+order" if include_order else ""
    query = f"""
query PrimordialCaidoRequestSearch({variable_defs}) {{
  {field_name}(
    {args}
  ) {{
    count {{ value }}
    nodes {{ {REQUEST_SUMMARY_FIELDS} }}
  }}
}}
"""
    return {
        "field_name": field_name,
        "filter_strategy": f"{filter_strategy}{order_label}",
        "query": query,
        "variables": variables,
    }
