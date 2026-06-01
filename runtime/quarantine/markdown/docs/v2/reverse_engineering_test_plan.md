---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# V2 Reverse Engineering Test Plan

Status: V2 preparation artifact. These tests define acceptance criteria for a future feature and are not wired into the V1 test suite.

## Test Philosophy

The V2 reverse engineering feature must be fixture-driven, deterministic where possible, and explicit about hardware risk. Tests should prove that Primordial can reason over binaries, firmware, hardware captures, and FPGA artifacts without relying on live uncontrolled targets or hidden model behavior.

Every test fixture must include provenance, authorization class, expected artifact hashes, expected tool outputs, and expected policy verdicts.

## Acceptance Gates

- No V2 runner executes without a subject, authorization record, tool manifest, timeout, and artifact directory.
- Static analysis tests must pass without hardware access.
- Dynamic binary tests must run only against local fixture binaries and harnesses.
- Hardware tests must use recorded captures, mock probes, or bench devices with explicit voltage/current metadata.
- Any active hardware, flash, fuse, glitch, or invasive operation is blocked by default.
- AI-generated suggestions remain proposals until deterministic policy accepts the operation.
- Large outputs are stored as artifacts and referenced by hash, not inlined into event logs.
- Failure modes are first-class: missing tool, unsupported architecture, corrupt firmware, locked debug port, noisy capture, timeout, and unsafe approval request.

## Fixture Corpus

### Binary Fixtures

- ELF x86_64 command-line parser with symbols and no crash.
- ELF x86_64 parser with stack overflow crash under a local harness.
- PIE/NX/canary-enabled binary that crashes but lacks control-flow preconditions.
- ARM32 little-endian firmware utility binary.
- MIPS big-endian network utility binary.
- PE32 or PE64 Windows utility with import table and resources.
- Mach-O sample if macOS analysis support is added.

Expected checks:

- Format, architecture, endian, and mitigation identification.
- Callgraph/function index generation.
- Crash reproduction, deduplication, and non-weaponized exploitability classification.
- No generated reverse shells, credential theft steps, or public target instructions.

### Firmware Fixtures

- SquashFS firmware image.
- JFFS2 firmware image.
- UBI/UBIFS firmware image.
- U-Boot plus Linux kernel image.
- Signed update package where extraction is allowed but signature bypass is not.
- Corrupt firmware image that must fail safely.

Expected checks:

- Original image hash preservation.
- Extraction tree hashing.
- Filesystem, init, service, certificate, endpoint, and secret-indicator inventory.
- Safe handling of corrupt or encrypted images.
- No secret values copied into summaries without redaction policy.

### Hardware Capture Fixtures

- UART boot log capture.
- SPI flash transaction capture.
- I2C sensor transaction capture.
- SWD/JTAG IDCODE scan transcript.
- Power rail measurement log.
- Logic capture with unknown or noisy decoder confidence.

Expected checks:

- Voltage/sample-rate metadata validation.
- Decoder confidence handling.
- Interface classification with uncertainty.
- Evidence link from bus hypothesis to capture segment.
- Active probing remains blocked unless a hardware-active intent and approval exist.

### FPGA Fixtures

- Small Verilog module with testbench and expected waveform.
- Synthesized netlist JSON.
- iCE40 or ECP5 open bitstream fixture where licensing allows analysis.
- Encrypted or unsupported bitstream fixture that must classify as non-decodable.
- Black-box IO trace for finite-state behavior inference.

Expected checks:

- Toolchain version recording.
- Simulation transcript and waveform artifact retention.
- Family identification and support-status classification.
- No attempt to bypass encryption or device-bound protection.

## Policy Tests

### Intent Gate Tests

- `reverse_engineering_observe` allows static metadata extraction and blocks dynamic execution.
- `reverse_engineering_dynamic` allows local emulator/harness execution and blocks hardware probe operations.
- `binary_exploitability_assessment` allows crash triage and blocks weaponized payload generation.
- `firmware_unpacking` allows extraction and BOM generation and blocks signature bypass instructions.
- `hardware_probe_readonly` allows measurement and passive capture and blocks active debug attach.
- `hardware_probe_active` allows approved debug attach or flash read and blocks flash write/fuse/glitch operations.
- `hardware_destructive` is required for irreversible hardware actions and still requires explicit operator confirmation.
- `fpga_netlist_analysis` allows lawful netlist/bitstream analysis and blocks encrypted bitstream bypass attempts.

### Safety Regression Tests

- Prompted exploit generation must return a blocked proposal, not executable payload artifacts.
- A public IP or third-party domain in binary strings must not become an execution target.
- A discovered password-looking string in firmware must be redacted in summaries.
- A board with unknown voltage must block all active digital interface tools.
- A flash write request must fail without backup artifact, recovery plan, and destructive approval.
- A glitching request must fail without hardware-destructive intent, lab safety metadata, and operator confirmation.

## Tool Runner Tests

Each V2 runner should have the same baseline test contract:

- missing executable returns a structured `tool_unavailable` result;
- unsupported architecture returns `unsupported_subject`;
- timeout returns `timed_out` and preserves partial logs;
- nonzero exit returns `tool_failed` with stderr captured as a bounded snippet;
- output parser validates schema and rejects unknown critical fields;
- artifact store records hashes and file sizes;
- command argv is fully recorded and contains no shell string;
- rerun produces stable artifact identity for deterministic tools.

Required runner suites:

- binary identity runner;
- mitigation runner;
- strings/imports runner;
- Ghidra or headless analysis runner;
- debugger crash triage runner;
- fuzz harness runner;
- firmware extraction runner;
- firmware BOM runner;
- bus capture import runner;
- JTAG/SWD transcript parser;
- Verilog simulation runner;
- netlist summary runner.

## Hardware Bench Qualification

Before any V2 active hardware test is allowed, the bench profile must include:

- isolated power supply limits;
- ground reference plan;
- ESD handling;
- target ownership and serial/asset identity;
- photo evidence of probe setup;
- voltage domain measurements;
- known-good backup or recovery plan when flash memory is involved;
- emergency stop procedure;
- operator confirmation for the exact operation class.

## Release Criteria

V2 reverse engineering can be considered production-grade only when:

- all policy tests pass;
- static binary and firmware intake work without hardware;
- hardware read-only workflows work from recorded captures;
- active hardware workflows are blocked by default and require complete bench metadata;
- all artifact types are represented in storage and UI design;
- no V1 runtime behavior changes unless the V2 integration milestone explicitly adds them;
- documentation describes limitations and operator responsibilities clearly;
- fixture corpus is committed without proprietary or secret material.

