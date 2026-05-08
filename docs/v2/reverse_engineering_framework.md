# V2 Reverse Engineering Framework

Status: V2 preparation artifact. This document is not loaded by Primordial V1 and does not add runtime execution paths.

## Purpose

V2 should support authorized binary exploitation research, software reverse engineering, hardware reverse engineering, embedded firmware analysis, and FPGA-oriented reverse engineering as first-class disciplines. The feature is a control-plane framework, not a collection of ad hoc scripts. It should preserve Primordial's source-of-truth model: scope, evidence, approvals, operator intent, artifacts, and tool provenance decide what can happen.

Baseline V2 behavior is analysis-first. It may classify binaries, firmware, buses, boards, interfaces, netlists, crashes, mitigations, and exploitability preconditions. It must not silently generate weaponized exploit payloads, bypass access controls on third-party systems, brute force secrets, extract credentials, produce reverse shells, or operate outside explicit ownership and authorization evidence.

## Design Boundaries

- V1 runtime integration is intentionally deferred.
- No current `primordial/` execution, routing, web, storage, or orchestration code should import these V2 artifacts.
- V2 execution must remain `shell=False`, argv-only, timeout-bounded, workspace-isolated, and provenance-recorded.
- Live hardware actions require explicit operator confirmation, attached authorization, device identity, voltage/current limits, and a rollback or recovery plan.
- Destructive operations such as flash erase/write, fuse modification, glitching, invasive probing, decapsulation, or debug-lock manipulation require a separate high-risk hardware approval.
- Binary exploitation support means crash triage, exploitability assessment, mitigation review, harness construction, and safe in-house proof validation. Weaponized payload generation is out of baseline scope.

## Work Domains

### Binary Exploitation Research

Primary questions:

- What architecture, ABI, format, compiler signals, hardening, and dependency surface does the target binary expose?
- Is a crash reproducible under a bounded harness?
- Which primitive class is suggested: null dereference, bounds error, UAF, type confusion, integer overflow, format string, command injection, deserialization flaw, or logic bug?
- Which exploitability preconditions are still missing?
- Which mitigations block or constrain exploitation?

Required artifacts:

- Binary identity: hash, format, architecture, bitness, endian, compiler hints, linked libraries.
- Mitigation profile: NX, PIE, RELRO, stack canary, CFI, sandboxing, seccomp, entitlements.
- Crash record: input hash, signal/exception, fault address, register snapshot, stack trace, coverage signature.
- Triage verdict: reproducible, unique, likely duplicate, non-security crash, needs harness repair.
- Exploitability preconditions: control of instruction pointer, controlled write, info leak, heap groomability, ASLR bypass, target version proof.

### Software Reverse Engineering

Primary questions:

- What does the program do, and which trust boundaries matter?
- Which parsing, deserialization, crypto, update, authentication, IPC, plugin, driver, and network paths are reachable?
- Which code paths need manual review, symbolic exploration, dynamic tracing, or fuzz harnessing?
- Which dependencies or protocol grammars should be modeled?

Required artifacts:

- Function index, callgraph, import/export table, string clusters, protocol grammar notes.
- Decompiled snippets as small references, not bulk copyrighted source dumps.
- Trust-boundary map with evidence references.
- Dynamic trace summaries with tool versions, inputs, and environment constraints.

### Embedded And Firmware Reverse Engineering

Primary questions:

- What image format, boot chain, filesystem, compression, signing, update, and storage layout exists?
- Which chips, boards, buses, debug interfaces, voltage domains, and test pads are present?
- What can be safely read without writing to the device?
- Which emulation or rehosting path is realistic?

Required artifacts:

- Firmware bill of materials: hashes, partitions, filesystems, init scripts, services, credentials indicators, certificates, endpoints.
- Hardware observation log: photos, chip markings, connectors, voltage measurements, probe settings, continuity results.
- Bus capture metadata: interface, voltage, sample rate, decoder, timestamps, signal confidence.
- Debug-interface verdict: observed, confirmed, disabled, locked, unknown.

### Hardware And FPGA Reverse Engineering

Primary questions:

- What logic devices, FPGAs, CPLDs, memories, clocks, regulators, sensors, and transceivers exist?
- Is the bitstream accessible, encrypted, compressed, signed, or device-bound?
- Can the behavior be modeled with simulation, netlist analysis, or black-box IO characterization?
- What safety constraints protect the device under test?

Required artifacts:

- Board-level inventory, power tree, clock tree, IO voltage map, and connector map.
- Netlist or HDL artifacts only when lawfully obtained from owned or authorized material.
- Simulation transcript, waveform capture, constraints summary, synthesis/simulation tool versions.
- FPGA-family profile with supported open tooling and known limitations.

## Control Plane Model

V2 should introduce a dedicated reverse-engineering session profile while keeping Operator Intent authoritative.

Required durable records:

- `subject`: file, firmware image, board, chip, bus, FPGA, crash, trace, or harness.
- `authorization`: owner, engagement, asset tag, custody note, and allowed operation classes.
- `environment`: host OS, container image, emulator, debugger, probe, voltage/current limits, toolchain versions.
- `artifact`: generated or imported outputs with hash, source tool, command argv, timestamp, retention class, and sensitivity.
- `finding`: claim backed by evidence references and confidence.
- `hazard`: safety, legal, destructive, export-control, privacy, warranty, or device-damage risk.

Intent gates:

- `reverse_engineering_observe`: static analysis, metadata extraction, read-only classification.
- `reverse_engineering_dynamic`: emulator or local harness execution against owned artifacts.
- `binary_exploitability_assessment`: crash triage and exploitability-precondition analysis without payload weaponization.
- `firmware_unpacking`: firmware extraction, filesystem recovery, and credential-indicator review.
- `hardware_probe_readonly`: non-invasive measurement, bus sniffing, and debug-interface discovery.
- `hardware_probe_active`: active probing, debug attach, flash read, or controlled register/memory access.
- `hardware_destructive`: flash erase/write, fuse changes, glitching, invasive work, decap, or other irreversible actions.
- `fpga_netlist_analysis`: bitstream/netlist analysis for owned or authorized devices only.

Default V2 posture:

- Static analysis is preferred before dynamic execution.
- Emulation is preferred before physical hardware interaction.
- Read-only hardware interaction is preferred before active debug attach.
- Active hardware work is blocked until device identity, voltage limits, connection plan, and recovery plan exist.
- Any generated harness must run against local owned artifacts, not public targets.

## Workflow Families

### Binary Intake

Inputs: binary file, debug symbols if available, provenance statement, scope record.

Steps:

1. Hash and identify file format, architecture, endian, imports, sections, compiler hints, and packer indicators.
2. Extract strings, exports, imports, resources, symbols, and dependency metadata.
3. Record mitigation profile and risk-relevant binary properties.
4. Produce an initial review map: parsers, file IO, network IO, IPC, crypto, auth, update, plugin, and memory-unsafe surfaces.

### Crash Triage

Inputs: binary identity, harness, crashing input, run constraints.

Steps:

1. Reproduce under a bounded local environment.
2. Capture signal, fault address, registers, backtrace, allocator state, sanitizer output, and input hash.
3. Deduplicate using stack signature, coverage signature, and fault class.
4. Classify exploitability preconditions without producing a weaponized payload.

### Firmware Intake

Inputs: image dump, update package, memory read, or vendor package.

Steps:

1. Hash the original image and preserve it read-only.
2. Identify compression, container, partition table, filesystem, bootloader, kernel, init system, and architecture.
3. Extract filesystems into a controlled artifact directory.
4. Produce a firmware BOM: services, exposed ports, scripts, hardcoded endpoints, certificates, secrets indicators, and update flow.

### Board Intake

Inputs: board photos, ownership record, target device profile.

Steps:

1. Inventory visible chips, markings, connectors, test pads, regulators, crystals, memories, antennas, and debug headers.
2. Establish voltage domains with a meter before connecting any digital instrument.
3. Map probable UART, JTAG, SWD, SPI, I2C, I3C, CAN, LIN, USB, PCIe, MIPI, and memory interfaces.
4. Record probe settings, sample rates, grounding, isolation, and current limits.

### FPGA And Logic Analysis

Inputs: bitstream, configuration flash dump, HDL/netlist, board inventory, or captured IO traces.

Steps:

1. Identify device family, package, configuration memory, encryption/signing indicators, and toolchain clues.
2. Preserve raw bitstream or flash contents and derive read-only normalized artifacts.
3. If lawfully available, convert to netlist or intermediate representation and run structural review.
4. Validate hypotheses through simulation, waveform comparison, or black-box IO characterization.

## Artifact And Evidence Standards

Every V2 tool run should produce a compact machine-readable result plus optional large artifacts. Large binaries, dumps, captures, and traces should remain file artifacts with hashes, not copied into logs.

Required fields for V2 evidence:

- `subject_id`
- `operation_id`
- `tool`
- `tool_version`
- `argv`
- `working_directory`
- `started_at`
- `finished_at`
- `timeout_seconds`
- `exit_status`
- `input_artifact_refs`
- `output_artifact_refs`
- `environment_ref`
- `operator_intent_id`
- `authorization_ref`
- `sensitivity`
- `confidence`

Sensitivity classes:

- `public_metadata`: hashes, formats, tool versions, high-level summaries.
- `controlled_binary`: proprietary binaries, firmware, board photos, captures, or dumps.
- `secrets_possible`: firmware filesystems, strings output, memory dumps, traces with credentials indicators.
- `device_damage_risk`: active hardware actions, voltage probing, flash writes, glitching, fuse changes.
- `export_control_review`: cryptographic hardware, radio firmware, military/aerospace/critical infrastructure contexts, or restricted IP.

## AI Control Plane Requirements

AI may help with triage, summarization, hypothesis generation, and tool selection. It must not become the authority for execution.

Allowed AI outputs:

- Suggested next analysis steps with evidence references.
- Function or component summaries.
- Harness review and safety review.
- Crash classification and missing-precondition analysis.
- Bus/protocol identification hypotheses.
- FPGA/netlist component labeling hypotheses.

Blocked baseline AI outputs:

- Weaponized exploit payloads.
- Reverse shells, credential theft, persistence, or evasion instructions.
- Instructions to bypass third-party access controls or DRM.
- Automatic flash writes, fuse changes, glitching campaigns, or destructive hardware operations.
- Bulk reconstruction of proprietary source code beyond limited evidence excerpts.

## V2 Implementation Milestones

1. Static artifact and subject model.
2. Read-only tool catalog loader for V2 manifests.
3. Local artifact store for binaries, firmware, captures, traces, and board media.
4. Static binary and firmware intake runners.
5. Dynamic local harness and debugger runners.
6. Hardware read-only observation workflow.
7. Hardware active-probe workflow with explicit high-risk approvals.
8. FPGA/netlist analysis workflow.
9. UI surfaces for subject inventory, evidence graph, waveforms, callgraphs, crash groups, and hardware maps.
10. Policy test suite and fixture corpus.

## Official Reference Anchors

These sources were used to ground the tool taxonomy:

- Ghidra official repository: https://github.com/NationalSecurityAgency/ghidra
- angr documentation: https://docs.angr.io/en/latest/
- AFL++ documentation: https://aflplus.plus/
- Renode documentation/about: https://renode.io/about/
- OpenOCD documentation: https://openocd.org/doc/html/About.html
- pyOCD documentation: https://pyocd.io/
- sigrok supported hardware: https://sigrok.org/wiki/Supported_hardware
- Yosys documentation: https://yosyshq.readthedocs.io/projects/yosys/

