# Structured Autonomy

The autonomy scaffold adds typed support for tool inventory, missing-tool resolution, failure diagnosis, script safety validation, and methodology proposals.

Tool inventory checks:

- approved executables via `shutil.which`
- approved Python packages via `importlib.metadata`
- trusted scripts by configured paths

Tooling gaps resolve to safe substitutions when available. The first concrete substitution is `netexec` to `smbclient` for SMB share enumeration.

Generated helpers are engagement-local only. `ScriptSafetyValidator` rejects subprocess use, `os.system`, `eval`, `exec`, dynamic imports, broad filesystem writes, and unapproved socket/network behavior.

`MethodologyCompiler` creates proposal-local artifacts under `proposals/methodology/...`. Baseline catalogs are not mutated by compiler output.
