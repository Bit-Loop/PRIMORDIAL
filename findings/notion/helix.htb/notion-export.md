# helix.htb Notion Export

Target: `helix.htb`
Profile: `hack_the_box`
Generated: 2026-05-14T22:04:14.110129+00:00

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
- `medium` Reachable HTTP surface observed: Recon reached 3 HTTP endpoint(s) for helix.htb. Observed status code(s): 200.
- `medium` Public exploit references require manual triage: Searchsploit returned 29 retained non-DoS candidate reference(s). These are unverified research leads only; no PoC was executed.
- `low` Open TCP services observed: Service discovery observed 2 open TCP service(s) across 2 host candidate(s).
- `medium` Reachable HTTP surface observed: Recon reached 1 HTTP endpoint(s) for helix.htb. Observed status code(s): 200.

## Open Interests

- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` PoC applicability candidates ready for gated review: 14 retained public PoC candidate(s) have enough evidence for a deeper gated review. Execution still requires explicit policy approval and bounded stop conditions.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` PoC research candidates for gated synthesis: Searchsploit returned non-DoS public exploit references. These are research candidates only; they require version validation, adaptation review, and policy approval before any execution.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Discovered web path follow-up candidates: Bounded content discovery found reachable or access-controlled web paths for follow-up analysis.
- `open` High-signal exposed service review: Remote access, file-sharing, or database services were observed. This is service inventory only; exploitation requires explicit bounded verification tasks.
- `open` Observed auth/session surface inventory: Recon observed auth-adjacent routes or forms. This is evidence-backed surface inventory, not a vulnerability claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.

## Recent Notes

- AI strategy review: ## Summary
Initial reconnaissance has identified multiple open services (SSH, HTTP) and a large number of potentially interesting web paths. The most promising leads are the identified services and the structured planner outputs, which suggest further targeted analysis is required. No immediate vulnerability can be claimed.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.htb: SSH (22) and HTTP (80). (evidence_4874ac495b54)
- Web content discovery identified 200 interes
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: ## Summary
Initial reconnaissance has identified multiple open services (SSH, HTTP) and a large number of potentially interesting web paths. The most promising leads are the identified services and the structured list of non-DoS exploit candidates. Further triage should focus on version enumeration and authentication-adjacent surface analysis.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.htb: SSH (22) and HTTP (80). (evidence_4874ac495b54)
- Web content discovery id
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: ## Summary
Initial reconnaissance has identified multiple open services (SSH, HTTP) and a large number of potentially interesting web paths. Exploit research has yielded several non-DoS candidates (e.g., RCE for NGINX, OpenSSH, PHP-FPM) that require version-specific triage and credential/scope validation. The primary focus should be on narrowing down the scope of the identified services and paths.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.htb: SSH (22) and HTTP (
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: ## Summary
Initial reconnaissance has identified multiple open services (SSH, HTTP) and a large number of potentially interesting web paths. The most promising leads involve the specific RCE candidates found via exploit research and the general web content discovery. Further triage should focus on version-specific enumeration and credential/scope prerequisite checks for the identified services and paths.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.htb: SSH (22) and
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: ## Summary
Initial reconnaissance has identified multiple open services (SSH, HTTP) and a large number of potentially interesting web paths. The most promising leads involve the specific RCE candidates found via exploit research and the general web content discovery. Further triage should focus on version-specific enumeration and credential/scope prerequisite gathering for the identified services.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.htb: SSH (22) and HTTP (
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: ## Summary
Initial reconnaissance has identified multiple open services (SSH, HTTP) and a large number of potential web paths. Exploit research yielded several non-DoS candidates (RCE, Command Execution) requiring version validation. The primary focus should be on service-specific enumeration and credential/scope prerequisite gathering for the identified web paths and services.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.htb: SSH (22) and HTTP (80). (evidence_4874a
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: ## Summary
Initial reconnaissance has identified multiple open services (SSH, HTTP) and a large number of potentially interesting web paths. The most promising leads are the identified public exploit references (Ingress-NGINX, OpenSSH, PHP-FPM) and the numerous 'Auth-adjacent' interests, which require targeted, scoped validation. Further focus should be placed on version enumeration and credential prerequisite gathering.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: ## Summary
Initial reconnaissance has identified multiple open services (SSH, HTTP) and a large number of potentially interesting web paths. The most promising leads are the specific exploit references (Ingress-NGINX, OpenSSH, PHP-FPM) and the numerous unreviewed 'Auth-adjacent' surfaces. Further triage must focus on version validation and path-specific content analysis.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.htb: SSH (22) and HTTP (80). (evidence_4874ac495b54
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- Remote premium review status: Agent chat provider: claude
Model: provider-default
Request ID: 7b8cbc47373742d29ebe60091b4c0a08
Structured output: True

{
  "confidence": 0.70,
  "invalid_existing_tasks": [
    {
      "task_id": "task_f93f1e451633",
      "reason": "All three proposed actions (web_path_access_check, service_version_detection, directory_listing_scan) lack registered primitive mappings. No actionable path exists under the current manifest set.",
      "recommendation": "Suspend pending operator registration of
- AI strategy review: ## Summary
Initial reconnaissance has identified multiple open services (SSH, HTTP) and a large number of potentially interesting web paths. The most promising leads are the identified services and the structured PoC candidates. Further triage must focus on versioning and authentication-adjacent paths.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.htb: SSH (22) and HTTP (80). (evidence_4874ac495b54)
- Web content discovery identified 200 interesting paths, including 
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: ## Summary
Initial reconnaissance identified multiple open services (SSH, HTTP) and a large number of potentially interesting web paths. The most promising next steps involve targeted analysis of the identified services and paths, prioritizing version-specific enumeration and credential/scope prerequisite checks before attempting exploit validation.

## Facts
- Four open TCP services were observed on 10.129.55.37 and helix.htb: SSH (22) and HTTP (80). (evidence_4874ac495b54)
- Bounded web conten
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 0 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- Remote premium review status: Agent chat provider: claude
Model: provider-default
Request ID: eedfd204cfe54d809e7dc31f5cfe837e
Structured output: True

{
  "confidence": 0.79,
  "invalid_existing_tasks": [
    {
      "task_id": "task_f93f1e451633",
      "reason": "All proposed primitive hints (web_path_access_check, service_version_detection, directory_listing_scan) are unregistered in the primitive registry.",
      "disposition": "blocked_missing_primitive"
    },
    {
      "task_id": "task_fc3370fd067c",
      "reason
- AI verification plan: ## Summary
Bounded verification plan to assess the applicability of top PoC exploit candidates on helix.htb without execution, focusing on SSH and web services using available primitives.

## Facts
- PoC applicability validation classified 14 candidates ready for gated review (evidence_73f3511f39f9).
- Exploit research identified non-DoS candidates including OpenSSH and Ingress-NGINX vulnerabilities (evidence_9e28ea382042).
- Auth-adjacent surfaces require verification before any exploit claim (
- Verification status: No production verification primitive is registered for automatic claim validation yet. The target remains in recon/analysis state until a real bounded verification adapter is implemented.
- AI verification plan: ## Summary
Operational verification of web content discovery findings to assess for auth-adjacent vulnerabilities on helix.htb.

## Facts
- Bounded web content discovery identified 200 interesting paths on helix.htb (evidence_9e28ea382042).
- HTTP services are reachable and responding with status code 200 (evidence_4874ac495b54).
- Open TCP services include SSH and HTTP on port 80 (evidence_4874ac495b54).
- Auth-adjacent surfaces have been observed but require manual or primitive-backed verifica

## Evidence References

- `evidence_24aaeaacc361` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_b8acd703a3e8` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_7b203a066575` DNS enumeration: helix.htb: DNS enumeration queried helix.htb via 10.129.55.37; parsed 0 record(s). AXFR did not succeed.
- `evidence_14addf4d2cf5` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_f0742c25ce72` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_73f3511f39f9` PoC applicability validation: helix.htb: Classified 29 retained public PoC candidate(s): 14 ready for gated review, 15 blocked or research-only. No PoC was executed and no exploit code was generated.
- `evidence_9e28ea382042` Exploit research: helix.htb: Searchsploit research found 29 non-DoS candidate(s), suppressed 10 DoS/crash-oriented result(s), and retained 4 example excerpt(s): Ingress-NGINX 4.11.0 - Remote Code Execution (RCE), OpenSSH < 6.6 SFTP (x64) - Command Execution, OpenSSH < 6.6 SFTP - Command Execution, SSH (x2) - Remote Command Execution, PHP-FPM + Nginx - Remote Code Execution.
- `evidence_fd15e133181d` Web content discovery: helix.htb: Bounded web content discovery found 200 interesting path(s): /00(200), /00.asp(200), /00.aspx(200), /00.config(200), /00.html(200), /00.txt(200), /01(200), /01.asp(200), /01.aspx(200), /01.config(200), /01.html(200), /01.txt(200), /02(200), /02.asp(200), /02.aspx(200), /02.config(200), /02.html(200), /02.txt(200), /03(200), /03.asp(200), /03.aspx(200), /03.config(200), /03.html(200), /03.txt(200), /1(200), /1.asp(200), /1.aspx(200), /1.config(200), /1.html(200), /1.txt(200), /10(200), /10.asp(200), /10.aspx(200), /10.config(200), /10.html(200), /10.txt(200), /100(200), /100.asp(200), /100.aspx(200), /100.config(200), /100.html(200), /100.txt(200), /1000(200), /1000.asp(200), /1000.aspx(200), /1000.config(200), /1000.html(200), /1000.txt(200), /123(200), /123.asp(200) and 150 more.
- `evidence_4874ac495b54` TCP service discovery: helix.htb: TCP service discovery observed 4 open service(s): 10.129.55.37:22/ssh, 10.129.55.37:80/http, helix.htb:22/ssh, helix.htb:80/http.
- `evidence_918fd314e269` Recon: http://helix.htb/: HTTP probe returned 200 for http://helix.htb/ with content-type text/html. title='Helix Industries | Industrial Automation & Critical Infrastructure'
- `evidence_0748f41bb64a` Recon: http://10.129.55.37/: HTTP probe returned 200 for http://10.129.55.37/ with content-type text/html. title='Helix Industries | Industrial Automation & Critical Infrastructure'
- `evidence_7acfa141f68f` Recon: http://helix.htb/: HTTP probe returned 200 for http://helix.htb/ with content-type text/html. title='Helix Industries | Industrial Automation & Critical Infrastructure'
- `evidence_212a1128893e` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_d8f55ebfdaa8` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_cc04fd8d4a6f` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_d061d9eea6f7` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_5948965c3e41` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_025add9642ae` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_7504bc47697f` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_12cb79babdf2` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_c4af167253a1` DNS enumeration: helix.htb: DNS enumeration queried helix.htb via 10.129.54.140; parsed 0 record(s). AXFR did not succeed.
- `evidence_ccb584da7957` Remote premium review: helix.htb: Remote premium review returned structured planner output.
- `evidence_eb9e0db0a889` PoC applicability validation: helix.htb: Classified 29 retained public PoC candidate(s): 14 ready for gated review, 15 blocked or research-only. No PoC was executed and no exploit code was generated.
- `evidence_1eb1cd88ab65` Exploit research: helix.htb: Searchsploit research found 29 non-DoS candidate(s), suppressed 10 DoS/crash-oriented result(s), and retained 4 example excerpt(s): Ingress-NGINX 4.11.0 - Remote Code Execution (RCE), OpenSSH < 6.6 SFTP (x64) - Command Execution, OpenSSH < 6.6 SFTP - Command Execution, SSH (x2) - Remote Command Execution, PHP-FPM + Nginx - Remote Code Execution.
- `evidence_10d2d65c6f00` Web content discovery: helix.htb: Bounded web content discovery checked 1 base URL(s) with 420 words and found no interesting paths.
