# alpha.htb Notion Export

Target: `alpha.htb`
Profile: `hack_the_box`
Generated: 2026-05-08T17:13:04.722766+00:00

## AI Agent Guidance

# alpha.htb Agent Guidance

## AI Agent Guidance

- Stay evidence-backed. Do not promote a finding without linked evidence.
- Prefer narrow, scoped verification tasks over broad spray-and-pray actions.
- Never run DoS or stress-style checks.
- Record assumptions, blockers, and missing prerequisites explicitly.

## Operator Notes

- Add target-specific methodology guidance here.

## Findings

- `medium` Reachable HTTP surface observed: Recon reached 6 HTTP endpoint(s) for alpha.htb. Observed status code(s): 200.

## Open Interests

- `open` Observed auth/session surface inventory: Recon observed auth-adjacent routes or forms. This is evidence-backed surface inventory, not a vulnerability claim.

## Recent Notes

- Recon summary: Reachable endpoints: 6
Observed auth-adjacent surfaces: /admin, /login, /session
Observed paths: /admin, /api/, /login, /login?next=/dashboard, /robots.txt, /session
Observed query parameters: next
- http://alpha.htb/ -> 200 text/html; charset=utf-8
- https://alpha.htb/ -> 200 text/html; charset=utf-8
- http://10.10.10.10/ -> 200 text/html; charset=utf-8
- https://10.10.10.10/ -> 200 text/html; charset=utf-8
- http://10.10.10.10/ -> 200 text/html; charset=utf-8
- https://10.10.10.10/ -> 200 text

## Evidence References

- `evidence_8dd399b5dcbe` Recon: https://10.10.10.10/: HTTP probe returned 200 for https://10.10.10.10/ with content-type text/html; charset=utf-8. title='Pirate Fixture'
- `evidence_316821f89a6a` Recon: http://10.10.10.10/: HTTP probe returned 200 for http://10.10.10.10/ with content-type text/html; charset=utf-8. title='Pirate Fixture'
- `evidence_73a4a065e08c` Recon: https://10.10.10.10/: HTTP probe returned 200 for https://10.10.10.10/ with content-type text/html; charset=utf-8. title='Pirate Fixture'
- `evidence_4f292b8a00be` Recon: http://10.10.10.10/: HTTP probe returned 200 for http://10.10.10.10/ with content-type text/html; charset=utf-8. title='Pirate Fixture'
- `evidence_fa1164a31bc6` Recon: https://alpha.htb/: HTTP probe returned 200 for https://alpha.htb/ with content-type text/html; charset=utf-8. title='Pirate Fixture'
- `evidence_5613f97c808a` Recon: http://alpha.htb/: HTTP probe returned 200 for http://alpha.htb/ with content-type text/html; charset=utf-8. title='Pirate Fixture'
