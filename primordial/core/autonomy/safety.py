from __future__ import annotations

import ast


class ScriptSafetyValidator:
    FORBIDDEN_IMPORTS = {"subprocess", "socket"}
    FORBIDDEN_CALLS = {("os", "system"), ("builtins", "eval"), ("builtins", "exec"), ("importlib", "import_module")}
    FORBIDDEN_IMPORT_ALIASES = {
        ("importlib", "import_module"),
        ("os", "system"),
        ("subprocess", "Popen"),
        ("subprocess", "run"),
        ("socket", "socket"),
    }
    STAR_IMPORT_ALIAS_MODULES = {"importlib", "os", "subprocess", "socket"}

    def validate(self, source: str) -> tuple[bool, list[str]]:
        issues: list[str] = []
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return False, [f"syntax error: {exc}"]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in self.FORBIDDEN_IMPORTS:
                        issues.append(f"forbidden import: {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".")[0]
                if module in self.FORBIDDEN_IMPORTS:
                    issues.append(f"forbidden import: {node.module}")
                for alias in node.names:
                    if (module, alias.name) in self.FORBIDDEN_IMPORT_ALIASES or (
                        alias.name == "*" and module in self.STAR_IMPORT_ALIAS_MODULES
                    ):
                        issues.append(f"forbidden import alias: {node.module}.{alias.name}")
            elif isinstance(node, ast.Call):
                name = self._call_name(node.func)
                if name in {"eval", "exec", "__import__"}:
                    issues.append(f"forbidden call: {name}")
                if name in {"os.system", "subprocess.run", "subprocess.Popen", "socket.socket", "importlib.import_module"}:
                    issues.append(f"forbidden call: {name}")
            elif isinstance(node, ast.With):
                if any(self._call_name(item.context_expr.func) == "open" for item in node.items if isinstance(item.context_expr, ast.Call)):
                    issues.append("broad filesystem writes are not allowed in generated helpers")
        return not issues, issues

    def _call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""
