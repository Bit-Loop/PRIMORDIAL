# HTB Pirate Notion Export

Target: `pirate.htb`
Profile: `hack_the_box`
Generated: 2026-05-05T16:22:19.422893+00:00

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

- No verified findings recorded.

## Open Interests

- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` PoC research candidates for gated synthesis: Searchsploit returned non-DoS public exploit references. These are research candidates only; they require version validation, adaptation review, and policy approval before any execution.
- `open` DNS-derived host and service candidates: DNS enumeration produced records that may identify additional hostnames or service names for follow-up recon.
- `open` AD inventory follow-up candidates: Anonymous AD-facing enumeration produced structured inventory. Review shares, domain metadata, and discovered principals before any credentialed or exploitative step.
- `open` Auth-adjacent surface review backlog: Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.
- `open` High-signal exposed service review: Remote access, file-sharing, or database services were observed. This is service inventory only; exploitation requires explicit bounded verification tasks.
- `open` Observed auth/session surface inventory: Recon observed auth-adjacent routes or forms. This is evidence-backed surface inventory, not a vulnerability claim.

## Recent Notes

- Behavior verification note: Verifier reviewed 0 trace records. No unsupported durable claim promotion occurred in this branch.
- Compaction audit: Memory compaction merged recent task context into episodic and semantic layers while preserving evidence lineage.
- Operator-confirmed active target IP: Active IP for `pirate.htb` is `10.129.244.95`. Prior recon evidence may still reference older IPs and should be treated as historical until refreshed recon tasks complete.
- Behavior verification note: Verifier reviewed 0 trace records. No unsupported durable claim promotion occurred in this branch.
- Behavior verification note: Verifier reviewed 0 trace records. No unsupported durable claim promotion occurred in this branch.
- Compaction audit: Memory compaction merged recent task context into episodic and semantic layers while preserving evidence lineage.
- Operator-confirmed active target IP: Active IP for `pirate.htb` is `10.129.47.117`. Prior recon evidence may still reference older IPs and should be treated as historical until refreshed recon tasks complete.
- Compaction audit: Memory compaction merged recent task context into episodic and semantic layers while preserving evidence lineage.
- Operator-confirmed active target IP: Active IP for `pirate.htb` is `10.129.244.95`. Prior recon evidence may still reference older IPs and should be treated as historical until refreshed recon tasks complete.
- Behavior verification note: Verifier reviewed 0 trace records. No unsupported durable claim promotion occurred in this branch.
- AI strategy review: ### Facts

*   **Web Service:** The target `pirate.htb` (10.129.47.117) is running an IIS Windows Server, confirmed by multiple HTTP probes (200 OK) on both the root domain and IP address.
*   **Service Surface:** A comprehensive service discovery identified 28 open services, including critical protocols: DNS (53), HTTP (80, 5985), HTTPS (443), LDAP (389, 636), SMB (445), and RPC (135, 139).
*   **AD Inventory:** Anonymous AD enumeration successfully observed 6 LDAP naming context values, provid
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 2 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: **Facts**
*   **Target Identification:** The target is `pirate.htb` (10.129.47.117), hosting services including HTTP (80/443), LDAP (389/636), Kerberos (88), and SMB (445).
*   **Web Service:** The web server is running IIS on Windows Server, confirmed by HTTP probes returning 200 OK and the title 'IIS Windows Server' (evidence_a5945d78555c, evidence_ce9848b36f48, evidence_a5c3fabc8937).
*   **AD Status:** Anonymous AD enumeration was successful, revealing 6 LDAP naming context values (evidence_
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 2 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- AI strategy review: ### Facts

1.  **Target Environment:** The target is a Windows/IIS/Active Directory environment, confirmed by HTTP probes returning `title='IIS Windows Server'` (`evidence_a5945d78555c`, `evidence_ce9848b36f48`, `evidence_a5c3fabc8937`) and the presence of numerous AD-related services (LDAP, Kerberos, SMB, etc.) (`evidence_95129decb131`).
2.  **Service Exposure:** A wide range of services are exposed, including standard ports (53, 80, 443, 445) and specialized AD ports (389, 636, 135, 3268, 3269
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 2 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- Behavior verification note: Verifier reviewed 0 trace records. No unsupported durable claim promotion occurred in this branch.
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 2 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- Evidence analysis summary: Evidence-backed surface review found 6 normalized paths and 2 normalized query parameter names. Auth-adjacent evidence refs: 3. No exploit claim is promoted at this stage.
- Kerberos user discovery summary: Host: 10.129.47.117
Domain: pirate.htb
Commands: ldapsearch rc=1 timeout=False, rpcclient rc=1 timeout=False, netexec rc=1 timeout=False
Users discovered: 0
SPN candidates: 0
No password spraying, cracking, or exploit execution was performed.
- Exploit research summary: Queries: HTTP/1.1 200 OK Content-Length: 703 Content-Type: text/html Last-Modified: Sun,, Microsoft IIS, Microsoft Active Directory, Microsoft Windows SMB, ncacn_http/1.0, HTTP/1.1 404 Not Found Content-Length: 315 Content-Type: text/html; charset=us-a, Microsoft-IIS/10.0
Non-DoS candidates: 4
Suppressed DoS/crash candidates: 0
Example excerpts retained: 4
- EDB 32586 score=8: Microsoft Active Directory LDAP Server - 'Username' Enumeration [windows]
- EDB 22782 score=8: Microsoft Windows Server 
- Compaction audit: Memory compaction merged recent task context into episodic and semantic layers while preserving evidence lineage.
- Behavior verification note: Verifier reviewed 0 trace records. No unsupported durable claim promotion occurred in this branch.
- Behavior verification note: Verifier reviewed 0 trace records. No unsupported durable claim promotion occurred in this branch.
- Behavior verification note: Verifier reviewed 0 trace records. No unsupported durable claim promotion occurred in this branch.

## Evidence References

- `evidence_bf546d645ef4` Kerberos user discovery: pirate.htb: Kerberos user discovery against 10.129.47.117 found 0 user principal(s) and 0 SPN candidate(s).
- `evidence_e3efd682e2b4` Exploit research: pirate.htb: Searchsploit research found 4 non-DoS candidate(s), suppressed 0 DoS/crash-oriented result(s), and retained 4 example excerpt(s): Microsoft Active Directory LDAP Server - 'Username' Enumeration, Microsoft Windows Server 2000 - Active Directory Remote Stack Overflow, Microsoft Exchange Active Directory Topology 15.0.847.40 - 'Service MSExchangeADTopology' Unquoted Service Path, Microsoft Exchange Active Directory Topology 15.02.1118.007 - 'Service MSExchangeADTopology' Unquoted Service Path.
- `evidence_c56a08d25fdb` Web content discovery: pirate.htb: Bounded web content discovery checked 2 base URL(s) with 420 words and found no interesting paths.
- `evidence_00b8448a72c2` DNS enumeration: pirate.htb: DNS enumeration queried pirate.htb via 10.129.47.117; parsed 7 record(s). AXFR did not succeed.
- `evidence_e9f9ce15d408` AD enumeration: pirate.htb: Anonymous AD enumeration against 10.129.47.117 observed 6 LDAP naming context value(s), 0 SMB share candidate(s), and 0 RPC user candidate(s).
- `evidence_95129decb131` TCP service discovery: pirate.htb: TCP service discovery observed 28 open service(s): pirate.htb:53/dns, pirate.htb:80/http, pirate.htb:88/kerberos, pirate.htb:135/msrpc, pirate.htb:139/netbios-ssn, pirate.htb:389/ldap, pirate.htb:443/https, pirate.htb:445/smb, pirate.htb:464/kpasswd, pirate.htb:593/http-rpc-epmap, pirate.htb:636/ldaps, pirate.htb:3268/global-catalog, pirate.htb:3269/global-catalog-ssl, pirate.htb:5985/http, 10.129.47.117:53/dns, 10.129.47.117:80/http and 12 more.
- `evidence_a5945d78555c` Recon: http://10.129.47.117/: HTTP probe returned 200 for http://10.129.47.117/ with content-type text/html. title='IIS Windows Server'
- `evidence_ce9848b36f48` Recon: http://10.129.47.117/: HTTP probe returned 200 for http://10.129.47.117/ with content-type text/html. title='IIS Windows Server'
- `evidence_a5c3fabc8937` Recon: http://pirate.htb/: HTTP probe returned 200 for http://pirate.htb/ with content-type text/html. title='IIS Windows Server'
