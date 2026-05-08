# Target Fixture Notion Export

Target: `target.htb`
Profile: `hack_the_box`
Generated: 2026-05-08T17:13:04.711050+00:00

## AI Agent Guidance

# Target Fixture Agent Guidance

## AI Agent Guidance

- Stay evidence-backed. Do not promote a finding without linked evidence.
- Prefer narrow, scoped verification tasks over broad spray-and-pray actions.
- Never run DoS or stress-style checks.
- Record assumptions, blockers, and missing prerequisites explicitly.

## Operator Notes

- Add target-specific methodology guidance here.

## Findings

- `medium` Reachable HTTP surface observed: Recon reached 2 HTTP endpoint(s) for target.htb. Observed status code(s): 200.

## Open Interests

- `verified` Suspicious auth flow: Candidate workflow issue
- `open` Observed auth/session surface inventory: Recon observed auth-adjacent routes or forms. This is evidence-backed surface inventory, not a vulnerability claim.

## Recent Notes

- TCP service inventory: Open services: 0
Closed or filtered checks: 38
Scan errors retained: 0
No open services were observed in the configured bounded port set.
This is service inventory only, not an exploitation or vulnerability claim.
- Recon summary: Reachable endpoints: 2
Observed auth-adjacent surfaces: /admin, /login, /session
Observed paths: /admin, /api/, /login, /login?next=/dashboard, /robots.txt, /session
Observed query parameters: next
- http://10.10.10.10/ -> 200 text/html; charset=utf-8
- https://10.10.10.10/ -> 200 text/html; charset=utf-8

## Evidence References

- `evidence_aa56c0006174` Old TCP service discovery: Observed services on 10.129.47.117.
- `evidence_0fd388c357bd` Recon result: Collected login endpoints and redirect behavior
- `evidence_c1422b0e084d` Initial recon result: First evidence batch
- `evidence_fb7645d1c009` TCP service discovery: Observed IIS headers and AD services.
- `evidence_1db8f3db8181` HTTP probe: IIS default page
- `evidence_e3928c950e91` TCP service discovery: target.htb: TCP connect checks completed against 1 host(s) and 38 port(s); no open services were observed in the bounded port set.
- `evidence_0a14437116af` Recon: https://10.10.10.10/: HTTP probe returned 200 for https://10.10.10.10/ with content-type text/html; charset=utf-8. title='Pirate Fixture'
- `evidence_63d26894f1ce` Recon: http://10.10.10.10/: HTTP probe returned 200 for http://10.10.10.10/ with content-type text/html; charset=utf-8. title='Pirate Fixture'
