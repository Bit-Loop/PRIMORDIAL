from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from agent_chat_api.config import Settings
    from agent_chat_api.server import run_server
else:
    from .config import Settings
    from .server import run_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Standalone Codex/Claude chat API wrapper")
    parser.add_argument("--host", help="Bind host, default from CHAT_API_HOST or 127.0.0.1")
    parser.add_argument("--port", type=int, help="Bind port, default from CHAT_API_PORT or 8787")
    parser.add_argument("--workspace-root", help="Constrain request cwd values to this directory")
    parser.add_argument("--default-provider", choices=["claude", "codex"], help="Provider used when a request omits provider")
    args = parser.parse_args(argv)

    settings = Settings.from_env()
    if args.host:
        settings = Settings(**{**settings.__dict__, "host": args.host})
    if args.port:
        settings = Settings(**{**settings.__dict__, "port": args.port})
    if args.workspace_root:
        settings = Settings(**{**settings.__dict__, "workspace_root": Path(args.workspace_root).expanduser().resolve()})
    if args.default_provider:
        settings = Settings(**{**settings.__dict__, "default_provider": args.default_provider})

    run_server(settings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
