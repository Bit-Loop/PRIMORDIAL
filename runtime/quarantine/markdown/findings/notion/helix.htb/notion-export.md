---
origin: generated_export
ingest_allowed: false
operational_retrieval_allowed: false
---

# helix.htb Notion Export

Target: `helix.htb`
Profile: `hack_the_box`
Generated: 2026-05-16T17:03:02.698635+00:00

## AI Agent Guidance

# helix.htb Agent Guidance

## AI Agent Guidance

- Stay evidence-backed. Do not promote a finding without linked evidence.
- Prefer narrow, scoped verification tasks over broad spray-and-pray actions.
- Never run DoS or stress-style checks.
- Record assumptions, blockers, and missing prerequisites explicitly.

## Operator Notes

- Add target-specific methodology guidance here.

## Findings

- `medium` Public exploit references require manual triage: Searchsploit returned 29 retained non-DoS candidate reference(s). These are unverified research leads only; no PoC was executed.
- `low` Open TCP services observed: Service discovery observed 4 open TCP service(s) across 2 host candidate(s).
- `medium` Reachable HTTP surface observed: Recovered HTTP probe and content discovery evidence shows reachable HTTP responses and many wildcard-like path hits that still require bounded verification.
- `medium` Public exploit references require manual triage: Recovered Searchsploit and PoC applicability evidence retained public references for gated review only. No PoC was executed and no exploit code was generated.
- `low` Open TCP services observed: Recovered service evidence shows SSH and HTTP on the current Helix IP, plus hostname observations. This is inventory, not proof that no other ports exist.

## Open Interests

- `open` PoC applicability candidates ready for gated review: 14 retained public PoC candidate(s) have enough evidence for a deeper gated review. Execution still requires explicit policy approval and bounded stop conditions.
- `open` PoC research candidates for gated synthesis: Searchsploit returned non-DoS public exploit references. These are research candidates only; they require version validation, adaptation review, and policy approval before any execution.
- `open` High-signal exposed service review: Remote access, file-sharing, or database services were observed. This is service inventory only; exploitation requires explicit bounded verification tasks.
- `open` Web wildcard/catch-all verification gate: Recovered web content discovery shows many 200 responses. Keep web-layer expansion gated until wildcard behavior is verified.
- `open` PoC applicability candidates ready for gated review: Recovered PoC applicability evidence classified 14 retained public candidates as ready for deeper gated review; execution still requires explicit policy approval and bounded stop conditions.
- `open` Observed auth/session surface inventory: Recovered content-discovery notes mention auth-adjacent surfaces. Treat as follow-up inventory only until a real verification primitive reviews exact paths.

## Recent Notes

- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 0 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 0. No exploit claim is promoted at this stage.

## Evidence References

- `evidence_4caa6aeeef3c` DNS enumeration: helix.htb: DNS enumeration queried helix.htb via 10.129.64.253; parsed 0 record(s). AXFR did not succeed.
- `evidence_b3ff3d45169c` TCP service discovery: helix.htb: TCP connect checks completed against 2 host(s) and 38 port(s); no open services were observed in the bounded port set.
- `evidence_4a6541a6713b` PoC applicability validation: helix.htb: Classified 29 retained public PoC candidate(s): 14 ready for gated review, 15 blocked or research-only. No PoC was executed and no exploit code was generated.
- `evidence_19aae821c612` Exploit research: helix.htb: Searchsploit research found 29 non-DoS candidate(s), suppressed 10 DoS/crash-oriented result(s), and retained 4 example excerpt(s): Ingress-NGINX 4.11.0 - Remote Code Execution (RCE), OpenSSH < 6.6 SFTP (x64) - Command Execution, OpenSSH < 6.6 SFTP - Command Execution, SSH (x2) - Remote Command Execution, PHP-FPM + Nginx - Remote Code Execution.
- `evidence_1656c5228a85` TCP service discovery: helix.htb: TCP service discovery observed 4 open service(s): 10.129.55.37:22/ssh, 10.129.55.37:80/http, helix.htb:22/ssh, helix.htb:80/http.
- `evidence_b40d5fe8acdd` Recon: http://10.129.54.140/: HTTP probe returned 200 for http://10.129.54.140/ with content-type text/html. title='Helix Industries | Industrial Automation & Critical Infrastructure'
- `evidence_df51199097d3` TCP service discovery: helix.htb: TCP service discovery observed 2 open service(s): 10.129.54.140:22/ssh, 10.129.54.140:80/http.
- `evidence_10d2d65c6f00` Web content discovery: helix.htb: Bounded web content discovery checked 1 base URL(s) with 420 words and found no interesting paths.
- `evidence_1eb1cd88ab65` Exploit research: helix.htb: Searchsploit research found 29 non-DoS candidate(s), suppressed 10 DoS/crash-oriented result(s), and retained 4 example excerpt(s): Ingress-NGINX 4.11.0 - Remote Code Execution (RCE), OpenSSH < 6.6 SFTP (x64) - Command Execution, OpenSSH < 6.6 SFTP - Command Execution, SSH (x2) - Remote Command Execution, PHP-FPM + Nginx - Remote Code Execution.
- `evidence_eb9e0db0a889` PoC applicability validation: helix.htb: Classified 29 retained public PoC candidate(s): 14 ready for gated review, 15 blocked or research-only. No PoC was executed and no exploit code was generated.
- `evidence_ccb584da7957` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_c4af167253a1` DNS enumeration: helix.htb: DNS enumeration queried helix.htb via 10.129.54.140; parsed 0 record(s). AXFR did not succeed.
- `evidence_12cb79babdf2` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_7504bc47697f` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_025add9642ae` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_5948965c3e41` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_d061d9eea6f7` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_cc04fd8d4a6f` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_d8f55ebfdaa8` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_212a1128893e` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_7acfa141f68f` Recon: http://helix.htb/: HTTP probe returned 200 for http://helix.htb/ with content-type text/html. title='Helix Industries | Industrial Automation & Critical Infrastructure'
- `evidence_0748f41bb64a` Recon: http://10.129.55.37/: HTTP probe returned 200 for http://10.129.55.37/ with content-type text/html. title='Helix Industries | Industrial Automation & Critical Infrastructure'
- `evidence_918fd314e269` Recon: http://helix.htb/: HTTP probe returned 200 for http://helix.htb/ with content-type text/html. title='Helix Industries | Industrial Automation & Critical Infrastructure'
- `evidence_4874ac495b54` TCP service discovery: helix.htb: TCP service discovery observed 4 open service(s): 10.129.55.37:22/ssh, 10.129.55.37:80/http, helix.htb:22/ssh, helix.htb:80/http.
- `evidence_fd15e133181d` Web content discovery: helix.htb: Bounded web content discovery found 200 interesting path(s): /00(200), /00.asp(200), /00.aspx(200), /00.config(200), /00.html(200), /00.txt(200), /01(200), /01.asp(200), /01.aspx(200), /01.config(200), /01.html(200), /01.txt(200), /02(200), /02.asp(200), /02.aspx(200), /02.config(200), /02.html(200), /02.txt(200), /03(200), /03.asp(200), /03.aspx(200), /03.config(200), /03.html(200), /03.txt(200), /1(200), /1.asp(200), /1.aspx(200), /1.config(200), /1.html(200), /1.txt(200), /10(200), /10.asp(200), /10.aspx(200), /10.config(200), /10.html(200), /10.txt(200), /100(200), /100.asp(200), /100.aspx(200), /100.config(200), /100.html(200), /100.txt(200), /1000(200), /1000.asp(200), /1000.aspx(200), /1000.config(200), /1000.html(200), /1000.txt(200), /123(200), /123.asp(200) and 150 more.
