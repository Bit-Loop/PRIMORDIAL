# HTB Pirate Evidence Index

Generated: 2026-05-05T16:45:43.657442+00:00

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
- `evidence_ce9848b36f48` Recon: http://10.129.47.117/: HTTP probe returned 200 for http://10.129.47.117/ with content-type text/html. title='IIS Windows Server'
- `evidence_a5c3fabc8937` Recon: http://pirate.htb/: HTTP probe returned 200 for http://pirate.htb/ with content-type text/html. title='IIS Windows Server'
