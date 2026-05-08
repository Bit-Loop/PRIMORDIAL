# Pirate Fixture Notion Export

Target: `pirate.htb`
Profile: `hack_the_box`
Generated: 2026-05-08T17:13:04.739931+00:00

## AI Agent Guidance

# HTB Pirate Agent Guidance

## AI Agent Guidance

- Stay evidence-backed. Do not promote a finding without linked evidence.
- Prefer narrow, scoped verification tasks over broad spray-and-pray actions.
- Never run DoS or stress-style checks.
- Record assumptions, blockers, and missing prerequisites explicitly.

## Operator Notes

- Add target-specific methodology guidance here.

## Findings

- `medium` Reachable HTTP surface observed: Recon reached 1 HTTP endpoint(s) for pirate.htb. Observed status code(s): 200.
- `medium` Reachable HTTP surface observed: Recon reached 1 HTTP endpoint(s) for pirate.htb. Observed status code(s): 200.

## Open Interests

- `open` Observed auth/session surface inventory: Recon observed auth-adjacent routes or forms. This is evidence-backed surface inventory, not a vulnerability claim.
- `open` Observed auth/session surface inventory: Recon observed auth-adjacent routes or forms. This is evidence-backed surface inventory, not a vulnerability claim.

## Recent Notes

- Recon summary: Reachable endpoints: 1
Observed auth-adjacent surfaces: /admin, /login
Observed paths: /.well-known/security.txt, /admin, /api/, /fwlink/, /login, /robots.txt, /sitemap.xml
Observed query parameters: clcid, linkid
- http://10.129.244.95/ -> 200 text/html
- Recon summary: Reachable endpoints: 1
Observed auth-adjacent surfaces: /admin, /login
Observed paths: /.well-known/security.txt, /admin, /api/, /fwlink/, /login, /robots.txt, /sitemap.xml
Observed query parameters: clcid, linkid
- http://10.129.244.95/ -> 200 text/html
- Operator-confirmed active target IP: Active IP for `pirate.htb` is `10.129.244.95`. Prior recon evidence may still reference older IPs and should be treated as historical until refreshed recon tasks complete.

## Evidence References

- `evidence_43833ebfab90` Recon: http://10.129.244.95/: HTTP probe returned 200 for http://10.129.244.95/ with content-type text/html. title='IIS Windows Server'
- `evidence_63a8e2434073` Recon: http://10.129.244.95/: HTTP probe returned 200 for http://10.129.244.95/ with content-type text/html. title='IIS Windows Server'
- `evidence_531397569b55` Exploit research: pirate.htb: Searchsploit research found 1 non-DoS candidate.
