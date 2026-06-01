from __future__ import annotations


def empty_schema(*, error: str = "") -> dict[str, object]:
    return {
        "ok": False,
        "error": error,
        "capabilities": {
            "requests_by_offset": False,
            "requests": False,
            "request_detail": False,
            "create_replay_session": False,
            "start_replay_task": False,
            "replay_entry": False,
        },
        "query_fields": [],
        "mutation_fields": [],
        "request_args": {},
    }


def field_arg_types(fields: list[dict[str, object]], selected_names: set[str]) -> dict[str, dict[str, str]]:
    selected: dict[str, dict[str, str]] = {}
    for field in fields:
        name = str(field.get("name") or "")
        if name not in selected_names:
            continue
        args: dict[str, str] = {}
        for arg in field.get("args", []) if isinstance(field.get("args"), list) else []:
            if not isinstance(arg, dict):
                continue
            arg_name = str(arg.get("name") or "")
            if arg_name:
                args[arg_name] = graphql_type_name(arg.get("type"))
        selected[name] = args
    return selected


def graphql_type_name(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    kind = str(value.get("kind") or "")
    name = str(value.get("name") or "")
    if kind == "NON_NULL":
        inner = graphql_type_name(value.get("ofType"))
        return f"{inner}!" if inner else "!"
    if kind == "LIST":
        inner = graphql_type_name(value.get("ofType"))
        return f"[{inner}]" if inner else "[]"
    return name or kind


def schema_payload(
    *,
    ok: bool,
    error: object,
    query_fields: set[str],
    mutation_fields: set[str],
    request_args: dict[str, dict[str, str]],
) -> dict[str, object]:
    return {
        "ok": ok,
        "error": error,
        "capabilities": {
            "requests_by_offset": "requestsByOffset" in query_fields,
            "requests": "requests" in query_fields,
            "request_detail": "request" in query_fields,
            "create_replay_session": "createReplaySession" in mutation_fields,
            "start_replay_task": "startReplayTask" in mutation_fields,
            "replay_entry": "replayEntry" in query_fields,
        },
        "query_fields": sorted(query_fields),
        "mutation_fields": sorted(mutation_fields),
        "request_args": request_args,
    }
