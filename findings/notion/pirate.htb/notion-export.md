# HTB Pirate Notion Export

Target: `pirate.htb`
Profile: `hack_the_box`
Generated: 2026-05-07T19:44:39.510784+00:00

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

- `open` PoC applicability candidates ready for gated review: 1 retained public PoC candidate(s) have enough evidence for a deeper gated review. Execution still requires explicit policy approval and bounded stop conditions.
- `open` PoC research candidates for gated synthesis: Searchsploit returned non-DoS public exploit references. These are research candidates only; they require version validation, adaptation review, and policy approval before any execution.
- `open` AD inventory follow-up candidates: Anonymous AD-facing enumeration produced structured inventory. Review shares, domain metadata, and discovered principals before any credentialed or exploitative step.
- `open` DNS-derived host and service candidates: DNS enumeration produced records that may identify additional hostnames or service names for follow-up recon.
- `open` High-signal exposed service review: Remote access, file-sharing, or database services were observed. This is service inventory only; exploitation requires explicit bounded verification tasks.
- `open` Observed auth/session surface inventory: Recon observed auth-adjacent routes or forms. This is evidence-backed surface inventory, not a vulnerability claim.
- `open` AD inventory follow-up candidates: Anonymous AD-facing enumeration produced structured inventory. Review shares, domain metadata, and discovered principals before any credentialed or exploitative step.
- `open` PoC applicability candidates ready for gated review: 1 retained public PoC candidate(s) have enough evidence for a deeper gated review. Execution still requires explicit policy approval and bounded stop conditions.
- `open` PoC research candidates for gated synthesis: Searchsploit returned non-DoS public exploit references. These are research candidates only; they require version validation, adaptation review, and policy approval before any execution.
- `open` DNS-derived host and service candidates: DNS enumeration produced records that may identify additional hostnames or service names for follow-up recon.
- `open` High-signal exposed service review: Remote access, file-sharing, or database services were observed. This is service inventory only; exploitation requires explicit bounded verification tasks.
- `open` Observed auth/session surface inventory: Recon observed auth-adjacent routes or forms. This is evidence-backed surface inventory, not a vulnerability claim.
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
- Behavior verification note: Verifier reviewed 0 trace records. No unsupported durable claim promotion occurred in this branch.
- AI PoC applicability review: ## Summary
Public PoC (EDB 32586) for AD LDAP username enumeration is technically applicable in principle due to AD/LDAP services being present, but lacks version/configuration validation, requires authenticated or pre-authentication context, and has no evidence of exploitable misconfiguration or vulnerable banner. Current recon shows no user enumeration success and no exposed vulnerable endpoints.

## Facts
- Target pirate.htb (10.129.48.145) hosts Microsoft Active Directory LDAP on ports 389/6
- PoC applicability validation summary: Classified candidates: 1
Ready for gated review: 1
Blocked/research-only: 0
Observed services considered: 14
- ready_for_review: Microsoft Active Directory LDAP Server - 'Username' Enumeration :: AD/LDAP surface exists, but exact version/configuration still needs bounded verification
No PoC was executed, no exploit code was generated, and no vulnerability was marked verified.
- Kerberos user discovery summary: Host: 10.129.48.145
Domain: pirate.htb
Commands: ldapsearch rc=1 timeout=False, rpcclient rc=1 timeout=False, netexec rc=1 timeout=False
Users discovered: 0
SPN candidates: 0
No password spraying, cracking, or exploit execution was performed.
- AI exploit research triage: ## Summary
Target pirate.htb (10.129.48.145) shows an Active Directory-integrated IIS server with standard AD ports open (389, 636, 3268, 3269, 88, 464), but no exploitable surface confirmed. Public PoC for AD LDAP username enumeration (EDB-32586) matches query and service inventory, but exact version and authentication posture are unverified.

## Facts
- TCP service discovery confirmed open AD-related ports: 389/ldap, 636/ldaps, 3268/globalcatLDAP, 3269/globalcatLDAPssl, 88/kerberos, 464/kpassw
- Exploit research summary: Queries: Microsoft IIS 10.0, IIS 10.0, Windows SMB, Active Directory LDAP
Non-DoS candidates: 1
Suppressed DoS/crash candidates: 0
Example excerpts retained: 1
- EDB 32586 score=16: Microsoft Active Directory LDAP Server - 'Username' Enumeration [windows]
No PoC was executed. Any adaptation requires version validation, a bounded verification task, and policy approval.
DoS/crash-oriented candidates are intentionally suppressed because Primordial must never DDoS or degrade the target.
- Anonymous AD enumeration summary: Host: 10.129.48.145
Commands: ldapsearch rc=0 timeout=False, smbclient rc=0 timeout=False, rpcclient rc=1 timeout=False, netexec rc=1 timeout=False
LDAP RootDSE keys: defaultNamingContext, dnsHostName, namingContexts, result, rootDomainNamingContext, search, supportedSASLMechanisms
SMB shares parsed: 0
RPC users parsed: 0
RPC groups parsed: 0
This is anonymous inventory only; no credential use or exploit step was performed.
- Web content discovery summary: Base URLs: http://10.129.48.145/, http://10.129.244.95/, http://10.129.47.117/, http://pirate.htb/
Words checked: 420
Interesting paths: 0
No interesting paths were observed in the bounded wordlist run.
This is content inventory only; no authentication or exploit attempt was performed.
- DNS enumeration summary: DNS server: 10.129.48.145
Domain: pirate.htb
Commands: dig:soa rc=0 timeout=False, dig:ns rc=0 timeout=False, dig:axfr rc=0 timeout=False, dig:ldap_srv rc=0 timeout=False, dig:kerberos_srv rc=0 timeout=False, dig:dc01_a rc=0 timeout=False
AXFR success: False
Records parsed: 5
- DC01.pirate.htb A 10.129.48.145
- _kerberos._tcp.pirate.htb SRV 0 100 88 dc01.pirate.htb
- dc01.pirate.htb A 10.129.48.145
- pirate.htb NS dc01.pirate.htb
- pirate.htb SOA dc01.pirate.htb hostmaster.pirate.htb 155 900 600
- TCP service inventory: Open services: 14
Closed or filtered checks: 62
Scan errors retained: 0
- 10.129.48.145:53 -> domain banner='Simple DNS Plus'
- 10.129.48.145:80 -> http banner='Microsoft IIS httpd 10.0'
- 10.129.48.145:88 -> kerberos-sec banner='Microsoft Windows Kerberos server time: 2026-05-06 11:52:20Z'
- 10.129.48.145:135 -> msrpc banner='Microsoft Windows RPC'
- 10.129.48.145:139 -> netbios-ssn banner='Microsoft Windows netbios-ssn'
- 10.129.48.145:389 -> ldap banner='Microsoft Windows Active Directory LDA
- Recon summary: Reachable endpoints: 2
Observed auth-adjacent surfaces: /admin, /login
Observed paths: /.well-known/security.txt, /admin, /api/, /fwlink/, /login, /robots.txt, /sitemap.xml
Observed query parameters: clcid, linkid
- http://10.129.48.145/ -> 200 text/html
- http://10.129.48.145/ -> 200 text/html
- Operator-confirmed active target IP: Active IP for `pirate.htb` is `10.129.48.145`. Prior recon evidence may still reference older IPs and should be treated as historical until refreshed recon tasks complete.
- Operator-confirmed active target IP: Active IP for `pirate.htb` is `10.129.244.95`. Prior recon evidence may still reference older IPs and should be treated as historical until refreshed recon tasks complete.
- Operator-confirmed active target IP: Active IP for `pirate.htb` is `10.129.48.145`. Prior recon evidence may still reference older IPs and should be treated as historical until refreshed recon tasks complete.
- Kerberos user discovery summary: Host: 10.129.244.95
Domain: pirate.htb
Commands: ldapsearch rc=1 timeout=False, rpcclient rc=1 timeout=False, netexec rc=1 timeout=False
Users discovered: 0
SPN candidates: 0
No password spraying, cracking, or exploit execution was performed.
- Anonymous AD enumeration summary: Host: 10.129.244.95
Commands: ldapsearch rc=0 timeout=False, smbclient rc=0 timeout=False, rpcclient rc=1 timeout=False, netexec rc=1 timeout=False
LDAP RootDSE keys: defaultNamingContext, dnsHostName, namingContexts, result, rootDomainNamingContext, search, supportedSASLMechanisms
SMB shares parsed: 0
RPC users parsed: 0
RPC groups parsed: 0
This is anonymous inventory only; no credential use or exploit step was performed.
- Web content discovery summary: Base URLs: http://10.129.244.95/, http://10.129.47.117/, http://pirate.htb/
Words checked: 420
Interesting paths: 0
No interesting paths were observed in the bounded wordlist run.
This is content inventory only; no authentication or exploit attempt was performed.
- AI PoC applicability review: ## Summary
PoC applicability review for Microsoft Active Directory LDAP Username Enumeration (EDB-32586) on pirate.htb indicates partial surface alignment but insufficient version/configuration evidence to confirm applicability. No execution or verification is performed per instructions.

## Facts
- Target pirate.htb hosts Microsoft Active Directory LDAP service on ports 389, 636, 3268, and 3269 (evidence_1fdeeefec3c9, evidence_c0ac9f0d78ce).
- LDAP banners confirm 'Microsoft Windows Active Dire
- PoC applicability validation summary: Classified candidates: 1
Ready for gated review: 1
Blocked/research-only: 0
Observed services considered: 14
- ready_for_review: Microsoft Active Directory LDAP Server - 'Username' Enumeration :: AD/LDAP surface exists, but exact version/configuration still needs bounded verification
No PoC was executed, no exploit code was generated, and no vulnerability was marked verified.
- AI exploit research triage: ## Summary
Target pirate.htb shows IIS 10.0 on port 80/443 and multiple Windows services including AD LDAP, SMB, and Kerberos. One public PoC (EDB 32586) matches the 'Active Directory LDAP' query and targets username enumeration via malformed LDAP requests. However, no version-specific evidence confirms vulnerable LDAP service version or patch state, and no foothold (e.g., valid credentials or unauthenticated LDAP bind success) is present.

## Facts
- Evidence confirms IIS 10.0 on http://10.129.
- Exploit research summary: Queries: Microsoft IIS 10.0, IIS 10.0, Windows SMB, Active Directory LDAP
Non-DoS candidates: 1
Suppressed DoS/crash candidates: 0
Example excerpts retained: 1
- EDB 32586 score=16: Microsoft Active Directory LDAP Server - 'Username' Enumeration [windows]
No PoC was executed. Any adaptation requires version validation, a bounded verification task, and policy approval.
DoS/crash-oriented candidates are intentionally suppressed because Primordial must never DDoS or degrade the target.
- DNS enumeration summary: DNS server: 10.129.244.95
Domain: pirate.htb
Commands: dig:soa rc=0 timeout=False, dig:ns rc=0 timeout=False, dig:axfr rc=0 timeout=False, dig:ldap_srv rc=0 timeout=False, dig:kerberos_srv rc=0 timeout=False, dig:dc01_a rc=0 timeout=False
AXFR success: False
Records parsed: 7
- DC01.pirate.htb A 10.129.244.95
- DC01.pirate.htb A 192.168.100.1
- _kerberos._tcp.pirate.htb SRV 0 100 88 dc01.pirate.htb
- dc01.pirate.htb A 10.129.244.95
- dc01.pirate.htb A 192.168.100.1
- pirate.htb NS dc01.pirate.ht
- TCP service inventory: Open services: 14
Closed or filtered checks: 62
Scan errors retained: 0
- 10.129.244.95:53 -> domain banner='Simple DNS Plus'
- 10.129.244.95:80 -> http banner='Microsoft IIS httpd 10.0'
- 10.129.244.95:88 -> kerberos-sec banner='Microsoft Windows Kerberos server time: 2026-05-05 23:45:15Z'
- 10.129.244.95:135 -> msrpc banner='Microsoft Windows RPC'
- 10.129.244.95:139 -> netbios-ssn banner='Microsoft Windows netbios-ssn'
- 10.129.244.95:389 -> ldap banner='Microsoft Windows Active Directory LDA

## Evidence References

- `evidence_8a080eb13bb0` PoC applicability validation: pirate.htb: Classified 1 retained public PoC candidate(s): 1 ready for gated review, 0 blocked or research-only. No PoC was executed and no exploit code was generated.
- `evidence_5179c46c4cee` Kerberos user discovery: pirate.htb: Kerberos user discovery against 10.129.48.145 found 0 user principal(s) and 0 SPN candidate(s).
- `evidence_00848c0a26e5` Exploit research: pirate.htb: Searchsploit research found 1 non-DoS candidate(s), suppressed 0 DoS/crash-oriented result(s), and retained 1 example excerpt(s): Microsoft Active Directory LDAP Server - 'Username' Enumeration.
- `evidence_bdb0a82055ac` AD enumeration: pirate.htb: Anonymous AD enumeration against 10.129.48.145 observed 6 LDAP naming context value(s), 0 SMB share candidate(s), and 0 RPC user candidate(s).
- `evidence_8e18ef9f486a` Web content discovery: pirate.htb: Bounded web content discovery checked 4 base URL(s) with 420 words and found no interesting paths.
- `evidence_bcc596da15ac` DNS enumeration: pirate.htb: DNS enumeration queried pirate.htb via 10.129.48.145; parsed 5 record(s). AXFR did not succeed.
- `evidence_5e0219700a87` TCP service discovery: pirate.htb: TCP service discovery observed 14 open service(s): 10.129.48.145:53/domain, 10.129.48.145:80/http, 10.129.48.145:88/kerberos-sec, 10.129.48.145:135/msrpc, 10.129.48.145:139/netbios-ssn, 10.129.48.145:389/ldap, 10.129.48.145:443/https, 10.129.48.145:445/microsoft-ds, 10.129.48.145:464/kpasswd5, 10.129.48.145:593/ncacn_http, 10.129.48.145:636/ldap, 10.129.48.145:3268/ldap, 10.129.48.145:3269/ldap, 10.129.48.145:5985/http.
- `evidence_da09beb83936` Recon: http://10.129.48.145/: HTTP probe returned 200 for http://10.129.48.145/ with content-type text/html. title='IIS Windows Server'
- `evidence_18902a9caa86` Recon: http://10.129.48.145/: HTTP probe returned 200 for http://10.129.48.145/ with content-type text/html. title='IIS Windows Server'
- `evidence_cbc6f6329f86` Kerberos user discovery: pirate.htb: Kerberos user discovery against 10.129.244.95 found 0 user principal(s) and 0 SPN candidate(s).
- `evidence_4f8bf27927a3` AD enumeration: pirate.htb: Anonymous AD enumeration against 10.129.244.95 observed 6 LDAP naming context value(s), 0 SMB share candidate(s), and 0 RPC user candidate(s).
- `evidence_eb53c44a4611` Web content discovery: pirate.htb: Bounded web content discovery checked 3 base URL(s) with 420 words and found no interesting paths.
- `evidence_b958cb55d6c4` PoC applicability validation: pirate.htb: Classified 1 retained public PoC candidate(s): 1 ready for gated review, 0 blocked or research-only. No PoC was executed and no exploit code was generated.
- `evidence_64c48bc46cb1` Exploit research: pirate.htb: Searchsploit research found 1 non-DoS candidate(s), suppressed 0 DoS/crash-oriented result(s), and retained 1 example excerpt(s): Microsoft Active Directory LDAP Server - 'Username' Enumeration.
- `evidence_449a52b5731e` DNS enumeration: pirate.htb: DNS enumeration queried pirate.htb via 10.129.244.95; parsed 7 record(s). AXFR did not succeed.
- `evidence_1fdeeefec3c9` TCP service discovery: pirate.htb: TCP service discovery observed 14 open service(s): 10.129.244.95:53/domain, 10.129.244.95:80/http, 10.129.244.95:88/kerberos-sec, 10.129.244.95:135/msrpc, 10.129.244.95:139/netbios-ssn, 10.129.244.95:389/ldap, 10.129.244.95:443/https, 10.129.244.95:445/microsoft-ds, 10.129.244.95:464/kpasswd5, 10.129.244.95:593/ncacn_http, 10.129.244.95:636/ldap, 10.129.244.95:3268/ldap, 10.129.244.95:3269/ldap, 10.129.244.95:5985/http.
- `evidence_c0ac9f0d78ce` Recon: http://10.129.244.95/: HTTP probe returned 200 for http://10.129.244.95/ with content-type text/html. title='IIS Windows Server'
- `evidence_4f1e686fe6fc` Recon: http://10.129.244.95/: HTTP probe returned 200 for http://10.129.244.95/ with content-type text/html. title='IIS Windows Server'
- `evidence_bf546d645ef4` Kerberos user discovery: pirate.htb: Kerberos user discovery against 10.129.47.117 found 0 user principal(s) and 0 SPN candidate(s).
- `evidence_e3efd682e2b4` Exploit research: pirate.htb: Searchsploit research found 4 non-DoS candidate(s), suppressed 0 DoS/crash-oriented result(s), and retained 4 example excerpt(s): Microsoft Active Directory LDAP Server - 'Username' Enumeration, Microsoft Windows Server 2000 - Active Directory Remote Stack Overflow, Microsoft Exchange Active Directory Topology 15.0.847.40 - 'Service MSExchangeADTopology' Unquoted Service Path, Microsoft Exchange Active Directory Topology 15.02.1118.007 - 'Service MSExchangeADTopology' Unquoted Service Path.
- `evidence_c56a08d25fdb` Web content discovery: pirate.htb: Bounded web content discovery checked 2 base URL(s) with 420 words and found no interesting paths.
- `evidence_00b8448a72c2` DNS enumeration: pirate.htb: DNS enumeration queried pirate.htb via 10.129.47.117; parsed 7 record(s). AXFR did not succeed.
- `evidence_e9f9ce15d408` AD enumeration: pirate.htb: Anonymous AD enumeration against 10.129.47.117 observed 6 LDAP naming context value(s), 0 SMB share candidate(s), and 0 RPC user candidate(s).
- `evidence_95129decb131` TCP service discovery: pirate.htb: TCP service discovery observed 28 open service(s): pirate.htb:53/dns, pirate.htb:80/http, pirate.htb:88/kerberos, pirate.htb:135/msrpc, pirate.htb:139/netbios-ssn, pirate.htb:389/ldap, pirate.htb:443/https, pirate.htb:445/smb, pirate.htb:464/kpasswd, pirate.htb:593/http-rpc-epmap, pirate.htb:636/ldaps, pirate.htb:3268/global-catalog, pirate.htb:3269/global-catalog-ssl, pirate.htb:5985/http, 10.129.47.117:53/dns, 10.129.47.117:80/http and 12 more.
- `evidence_a5945d78555c` Recon: http://10.129.47.117/: HTTP probe returned 200 for http://10.129.47.117/ with content-type text/html. title='IIS Windows Server'
