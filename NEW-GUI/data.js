// Mock data for the Primordial control plane prototype
window.PD_DATA = {
  runtime: {
    autonomy: 'supervised',
    intent: 'recon-and-enum',
    health: 'OK',
    uptime: '04h 17m',
    cpu: 0.42,
    gpu: 0.78,
    mem: 0.31,
    diskWrites: 124,
    netIn: '12.4 MB/s',
    netOut: '3.1 MB/s',
    activeTasks: 4,
    queued: 11,
    approvals: 2,
  },
  models: [
    { route: 'local_fast',    model: 'gemma3:12b',          loaded: true,  hot: true,  ctx: 32768 },
    { route: 'local_deep',    model: 'deepseek-r1:8b',      loaded: true,  hot: true,  ctx: 16384 },
    { route: 'local_code',    model: 'qwen2.5-coder:7b',    loaded: false, hot: false, ctx: 32768 },
    { route: 'local_compact', model: 'phi4-mini',           loaded: true,  hot: false, ctx: 4096 },
    { route: 'remote_premium', model: 'disabled by policy', loaded: false, hot: false, ctx: 0 },
  ],
  tasks: [
    { id: 't_8c4a', kind: 'recon.tcp_scan',     route: 'local_fast', status: 'running', target: 'pirate.htb', model: 'gemma3:12b', title: 'TCP discovery sweep on 10.129.47.117', ms: 14200 },
    { id: 't_8c4b', kind: 'recon.dns_enum',     route: 'local_fast', status: 'done',    target: 'pirate.htb', model: 'gemma3:12b', title: 'DNS sub-zone enumeration', ms: 9100 },
    { id: 't_8c4c', kind: 'web.content_disco',  route: 'local_fast', status: 'running', target: 'pirate.htb', model: 'gemma3:12b', title: 'Content discovery /admin/*', ms: 22300 },
    { id: 't_8c4d', kind: 'kerb.user_disco',    route: 'local_deep', status: 'queued',  target: 'pirate.htb', model: 'deepseek-r1:8b', title: 'Kerberos user discovery', ms: 0 },
    { id: 't_8c4e', kind: 'finding.verify',     route: 'local_deep', status: 'await_approval', target: 'pirate.htb', model: 'deepseek-r1:8b', title: 'Verify Tomcat manager creds', ms: 0 },
    { id: 't_8c4f', kind: 'memory.compact',     route: 'local_compact', status: 'done', target: '*',         model: 'phi4-mini', title: 'Compact episodic memory', ms: 1100 },
    { id: 't_8c50', kind: 'web.poc_research',   route: 'local_code', status: 'await_approval', target: 'pirate.htb', model: 'qwen2.5-coder:7b', title: 'Research CVE-2024-50379 applicability', ms: 0 },
    { id: 't_8c51', kind: 'recon.kerb_attack',  route: 'local_deep', status: 'failed',  target: 'pirate.htb', model: 'deepseek-r1:8b', title: 'AS-REP roast attempt', ms: 4400 },
  ],
  approvals: [
    {
      id: 'ap_01', risk: 'high', task: 't_8c4e',
      title: 'Credentialed access verification',
      detail: 'Login to Tomcat manager at https://pirate.htb:8443/manager with discovered creds tomcat:s3cret_2024.',
      reason: 'Credentialed action against in-scope but unverified service. Non-DoS, single request, 1 retry.',
      target: 'pirate.htb', primitive: 'http-probe', limits: '1 req · 5s timeout',
    },
    {
      id: 'ap_02', risk: 'med', task: 't_8c50',
      title: 'PoC applicability validation',
      detail: 'Pull CVE-2024-50379 PoC source for read-only inspection (not execution).',
      reason: 'Research-only step. Code lane will diff PoC pattern against observed banner.',
      target: 'pirate.htb', primitive: 'searchsploit-research', limits: 'read-only · 30s',
    },
    {
      id: 'ap_03', risk: 'low', task: 't_8c52',
      title: 'Notion publish: target notes',
      detail: 'Publish recon notes for pirate.htb to parent page — 4 evidence refs, 2 interests.',
      reason: 'External publish requires confirmation per policy.',
      target: 'pirate.htb', primitive: 'notion-sync', limits: 'idempotent',
    },
  ],
  events: [
    { t: '14:02:11', lvl: 'info', msg: 'tick: workflow advanced 3 tasks, planner produced 2 new candidates' },
    { t: '14:02:09', lvl: 'ok',   msg: 'evidence: tcp_scan recorded 14 open ports for <b>10.129.47.117</b>' },
    { t: '14:02:01', lvl: 'warn', msg: 'verifier: loop suspected on <b>recon.kerb_attack</b> — backed off' },
    { t: '14:01:48', lvl: 'info', msg: 'memory.compact: promoted 6 → semantic, dropped 22 stale episodic' },
    { t: '14:01:31', lvl: 'err',  msg: 'failed: AS-REP roast — domain controller unreachable' },
    { t: '14:01:12', lvl: 'ok',   msg: 'finding: <b>partial</b> Tomcat default manager exposed' },
    { t: '14:00:52', lvl: 'dbg',  msg: 'route(local_fast) → gemma3:12b · 312 tok in / 1248 out · 1.4s' },
    { t: '14:00:33', lvl: 'info', msg: 'approval requested: ap_02 (PoC applicability validation)' },
    { t: '14:00:14', lvl: 'info', msg: 'caido: imported 2 replays from local Caido session' },
    { t: '13:59:48', lvl: 'ok',   msg: 'discord: alert delivered (likely-finding pirate.htb)' },
  ],
  scope: [
    { handle: 'pirate.htb', profile: 'hack_the_box', ip: '10.129.47.117', assets: 4, evidence: 22, findings: 1, status: 'active' },
    { handle: 'acme.bug',   profile: 'hackerone',    ip: '—',             assets: 12, evidence: 71, findings: 3, status: 'paused' },
    { handle: 'driftnet.io',profile: 'hackerone',    ip: '—',             assets: 9,  evidence: 8,  findings: 0, status: 'idle' },
  ],
  // Map data — Maltego-style asset graph for pirate.htb
  graph: {
    nodes: [
      { id: 'dom_pirate', kind: 'domain',  label: 'pirate.htb',         sub: 'in-scope · htb',       x: 240, y: 80,  geo: { lat: 51.5074, lon: -0.1278, city: 'London' } },
      { id: 'host_main',  kind: 'host',    label: '10.129.47.117',      sub: 'linux 5.15 · ttl 63',  x: 420, y: 180, geo: { lat: 51.5074, lon: -0.1278, city: 'HTB lab' } },
      { id: 'host_dc',    kind: 'host',    label: '10.129.47.118',      sub: 'windows · DC01',       x: 660, y: 90,  geo: { lat: 51.5074, lon: -0.1278, city: 'HTB lab' } },
      { id: 'svc_22',     kind: 'svc',     label: 'ssh:22',             sub: 'OpenSSH 9.2p1',        x: 580, y: 260 },
      { id: 'svc_80',     kind: 'svc',     label: 'http:80',            sub: 'nginx 1.24.0',         x: 420, y: 320 },
      { id: 'svc_8443',   kind: 'svc',     label: 'https:8443',         sub: 'Tomcat 9.0.83',        x: 300, y: 320 },
      { id: 'svc_445',    kind: 'svc',     label: 'smb:445',            sub: 'samba 4.17',           x: 780, y: 200 },
      { id: 'svc_88',     kind: 'svc',     label: 'kerberos:88',        sub: 'AD krb5',              x: 780, y: 60 },
      { id: 'user_jdoe',  kind: 'user',    label: 'j.doe',              sub: 'PIRATE\\j.doe',        x: 940, y: 130 },
      { id: 'user_svc',   kind: 'user',    label: 'svc_tomcat',         sub: 'service account',      x: 940, y: 220 },
      { id: 'cred_t1',    kind: 'cred',    label: 'tomcat:s3cret_2024', sub: 'manager basic-auth',   x: 140, y: 380 },
      { id: 'finding_1',  kind: 'finding', label: 'Tomcat /manager',    sub: 'partial · default cred', x: 240, y: 460 },
      { id: 'finding_2',  kind: 'finding', label: 'AS-REP roastable',   sub: 'pre-auth disabled',    x: 1080, y: 100 },
      { id: 'tool_caido', kind: 'tool',    label: 'caido:replay#412',   sub: 'POST /manager/login',  x: 460, y: 460 },
    ],
    edges: [
      { a: 'dom_pirate', b: 'host_main', label: 'A' },
      { a: 'dom_pirate', b: 'host_dc',   label: 'A' },
      { a: 'host_main',  b: 'svc_22',    label: 'open' },
      { a: 'host_main',  b: 'svc_80',    label: 'open' },
      { a: 'host_main',  b: 'svc_8443',  label: 'open' },
      { a: 'host_dc',    b: 'svc_445',   label: 'open' },
      { a: 'host_dc',    b: 'svc_88',    label: 'open' },
      { a: 'svc_88',     b: 'user_jdoe', label: 'enumerated' },
      { a: 'svc_88',     b: 'user_svc',  label: 'enumerated' },
      { a: 'user_jdoe',  b: 'finding_2', label: 'asreproast', kind: 'finding' },
      { a: 'svc_8443',   b: 'cred_t1',   label: 'default', kind: 'finding' },
      { a: 'cred_t1',    b: 'finding_1', label: 'enables', kind: 'finding' },
      { a: 'svc_8443',   b: 'tool_caido',label: 'evidence' },
      { a: 'tool_caido', b: 'finding_1', label: 'replay' },
    ],
  },
  // chats
  approvalChat: [
    { who: 'system', t: '14:00:33', text: 'Approval requested · PoC applicability validation (ap_02)' },
    { who: 'agent', t: '14:00:34', text: 'I want to fetch the PoC source for CVE-2024-50379 (Tomcat path traversal). Read-only, no execution. Diff against banner — Tomcat 9.0.83 is in the affected range.' },
    { who: 'me',    t: '14:00:51', text: 'show me what you observed first' },
    { who: 'agent', t: '14:00:52', text: 'Tomcat 9.0.83 banner from 10.129.47.117:8443 (evidence ev_2241). Default manager auth at /manager/html. CVE applies to <=9.0.85 with case-insensitive filesystem. Need to check FS — would do a benign canary GET.' },
  ],
  inquiryChat: [
    { who: 'me',    t: '13:54:02', text: 'summarize current state of pirate.htb in 3 bullets' },
    { who: 'agent', t: '13:54:04', text: '**1.** Recon: 14 ports open across two hosts (.117 web/ssh, .118 DC).\n**2.** Likely access: Tomcat manager exposed with default-pattern creds → partial finding.\n**3.** Lateral candidate: user enumeration on DC01 yielded 2 accounts; one (j.doe) is AS-REP roastable.' },
    { who: 'me',    t: '13:55:11', text: 'why did the AS-REP attempt fail?' },
    { who: 'agent', t: '13:55:13', text: 'Trace t_8c51 shows DC unreachable on 88/tcp at the moment of attempt — verifier flagged it as transient and backed off. Will retry under recon.kerb_attack with bounded retry budget.' },
  ],
  signals: [
    'workflow.tick.complete',
    'task.heartbeat:t_8c4c',
    'memory.promote:semantic',
    'verifier.loop_break:recon.kerb_attack',
    'policy.approval_pending:ap_02',
    'ollama.warm:gemma3:12b',
  ],

  // ===== PLAN — methodology, pinned assets, operator intent =====
  plan: {
    methodology: {
      id: 'htb_lab', label: 'HTB Lab',
      description: 'Explicit lab behavior for controlled HTB-style workflows.',
      phases: [
        { id: 'recon', label: 'Recon', status: 'active', tasks: 5, done: 3 },
        { id: 'analysis', label: 'Analysis', status: 'active', tasks: 2, done: 0 },
        { id: 'exploitation', label: 'Exploitation', status: 'locked', tasks: 0, done: 0 },
        { id: 'chaining', label: 'Chaining', status: 'locked', tasks: 0, done: 0 },
      ],
    },
    intent: {
      id: 'htb_lab', label: 'HTB Lab',
      flags: {
        public_poc_research: true,
        searchsploit_allowed: true,
        read_poc_examples: true,
        poc_applicability_validation: true,
        exploit_code_generation: false,
        poc_execution: false,
        kerberos_asrep_roast: true,
        kerberos_kerberoast: true,
        credential_validation: true,
        credential_guessing: false,
        credential_spraying: false,
        hash_cracking: false,
        lab_flag_collection: true,
        htb_lab_behavior: true,
      },
    },
    autonomy: 'supervised',
    autonomyModes: ['manual', 'assisted', 'supervised', 'supervised_auto', 'high_autonomy'],
    pinnedAssets: [
      { id: 'pin_01', kind: 'evidence', ref: 'evidence_95129decb131', label: 'TCP scan — 28 open services', target: 'pirate.htb', pinned: '14:01:22' },
      { id: 'pin_02', kind: 'evidence', ref: 'evidence_00b8448a72c2', label: 'DNS enum — 7 records, AXFR failed', target: 'pirate.htb', pinned: '14:00:48' },
      { id: 'pin_03', kind: 'interest', ref: 'int_poc_01', label: 'PoC candidates ready for gated review', target: 'pirate.htb', pinned: '13:58:11' },
      { id: 'pin_04', kind: 'artifact', ref: 'art_exploit_research', label: 'EDB-32586 LDAP username enum triage', target: 'pirate.htb', pinned: '13:55:02' },
      { id: 'pin_05', kind: 'guidance', ref: 'guidance_pirate', label: 'Agent guidance: evidence-backed only', target: 'pirate.htb', pinned: '13:48:00' },
    ],
    playbooks: [
      { id: 'pb_recon_ad', label: 'AD Enumeration', desc: 'Bounded AD-facing anonymous inventory commands', status: 'active', tasks: ['ldap_rootdse', 'smb_share_list', 'rpc_users', 'netexec_smb_null'] },
      { id: 'pb_htb_flag', label: 'HTB Flag Collection', desc: 'Explicit HTB lab flag collection over validated SMB', status: 'locked', tasks: ['htb_user_flag_smb', 'htb_root_flag_smb'] },
    ],
    skills: [
      { id: 'caido-httpql', title: 'Caido HTTPQL Traffic Review', summary: 'Search captured requests with narrow HTTPQL filters', tags: ['caido', 'httpql', 'traffic-search', 'evidence'] },
    ],
    criticalThinking: [
      { id: 'ct_01', prompt: 'Are we assuming the IIS default page means no custom app behind it?', target: 'pirate.htb', phase: 'recon', status: 'open' },
      { id: 'ct_02', prompt: 'AD ports open but anonymous enum yields 0 shares — is this a hardened DC or misconfigured?', target: 'pirate.htb', phase: 'analysis', status: 'open' },
      { id: 'ct_03', prompt: 'Why did AXFR fail? Is there a secondary DNS we haven\'t found?', target: 'pirate.htb', phase: 'recon', status: 'resolved' },
      { id: 'ct_04', prompt: 'Kerberos user discovery found 0 users — should we try different wordlists or SPN patterns?', target: 'pirate.htb', phase: 'recon', status: 'open' },
    ],
  },

  // ===== NOTES — Notion integration =====
  notes: {
    targets: [
      { id: 'pirate.htb', label: 'HTB Pirate', profile: 'hack_the_box', active: true },
      { id: 'principal.htb', label: 'HTB Principal', profile: 'hack_the_box', active: false },
    ],
    syncStatus: { ok: true, lastSync: '14:01:55', pendingJobs: 1, failedJobs: 0 },
    folders: [
      {
        id: 'pirate_root', label: 'pirate.htb Workspace', target: 'pirate.htb', kind: 'target-root', synced: true, url: '#',
        children: [
          { id: 'pirate_overview', label: 'Overview', kind: 'overview', synced: true, url: '#' },
          { id: 'pirate_notes', label: 'Notes', kind: 'notes', synced: true, url: '#' },
          { id: 'pirate_evidence', label: 'Evidence Links', kind: 'evidence-links', synced: true, url: '#' },
          { id: 'pirate_findings', label: 'Findings', kind: 'findings', synced: true, url: '#' },
          { id: 'pirate_hypotheses', label: 'Open Hypotheses', kind: 'open-hypotheses', synced: true, url: '#' },
          { id: 'pirate_actions', label: 'Next Actions', kind: 'next-actions', synced: true, url: '#' },
          { id: 'pirate_guidance', label: 'Agent Guidance', kind: 'agent-guidance', synced: true, url: '#' },
        ],
      },
    ],
    pages: {
      pirate_overview: {
        title: 'HTB Pirate Overview',
        body: 'Target: pirate.htb\nProfile: hack_the_box\nActive IP: 10.129.48.145\n\nDC01.pirate.htb — Windows Server with IIS 10.0, Active Directory, 14+ open services.\nPrimary attack surface: AD/LDAP, Kerberos, IIS/HTTP, SMB.',
      },
      pirate_notes: {
        title: 'HTB Pirate Notes',
        body: '• Operator-confirmed active target IP: 10.129.48.145\n• Prior IPs (10.129.47.117, 10.129.244.95) are historical — treat as stale.\n• AD anonymous enum shows 6 LDAP naming contexts, 0 SMB shares, 0 RPC users.\n• DNS: DC01.pirate.htb resolves to 10.129.48.145. AXFR failed.\n• Kerberos user discovery: 0 principals found across all IP iterations.\n• IIS default page at port 80 — no custom application detected yet.',
      },
      pirate_evidence: {
        title: 'HTB Pirate Evidence Links',
        body: '• evidence_95129decb131 — TCP service discovery: 28 open services\n• evidence_00b8448a72c2 — DNS enumeration: 7 records\n• evidence_e9f9ce15d408 — AD enumeration: 6 naming contexts\n• evidence_bf546d645ef4 — Kerberos: 0 users\n• evidence_c56a08d25fdb — Web content: no interesting paths\n• evidence_e3efd682e2b4 — Exploit research: 4 non-DoS candidates\n• evidence_8a080eb13bb0 — PoC validation: 1 ready for review',
      },
      pirate_findings: {
        title: 'HTB Pirate Findings',
        body: 'No verified findings recorded.\n\nCandidate (unverified):\n• EDB-32586: AD LDAP Username Enumeration — surface exists but version unconfirmed.',
      },
      pirate_hypotheses: {
        title: 'HTB Pirate Open Hypotheses',
        body: '• PoC applicability: EDB-32586 LDAP username enumeration may work against DC01\n• IIS default page may hide admin routes behind alternate ports or vhosts\n• AD with 0 enumerated shares could mean strict NULL session policy\n• Secondary DNS server may exist (AXFR refused)',
      },
      pirate_actions: {
        title: 'HTB Pirate Next Actions',
        body: '1. Approve PoC applicability validation (ap_02) for EDB-32586\n2. Approve credentialed access check (ap_01) for Tomcat manager\n3. Broader web content discovery with larger wordlist\n4. Try authenticated LDAP bind if creds obtained\n5. Check for alternate vhosts on ports 80/443',
      },
      pirate_guidance: {
        title: 'HTB Pirate Agent Guidance',
        body: '• Stay evidence-backed. Do not promote a finding without linked evidence.\n• Prefer narrow, scoped verification tasks over broad spray-and-pray.\n• Never run DoS or stress-style checks.\n• Record assumptions, blockers, and missing prerequisites explicitly.',
      },
    },
  },

  // ===== INTERESTS — attack surfaces, findings, PoCs =====
  interests: {
    surfaces: [
      { id: 'srf_01', target: 'pirate.htb', kind: 'AD/LDAP', ports: '389,636,3268,3269', severity: 'high', status: 'active', desc: 'Active Directory LDAP surface — anonymous enum succeeded, 6 naming contexts' },
      { id: 'srf_02', target: 'pirate.htb', kind: 'Kerberos', ports: '88,464', severity: 'high', status: 'active', desc: 'Kerberos authentication — AS-REP roast allowed by intent but 0 users found' },
      { id: 'srf_03', target: 'pirate.htb', kind: 'HTTP/IIS', ports: '80,443', severity: 'med', status: 'active', desc: 'IIS 10.0 default page — auth surfaces /admin, /login observed' },
      { id: 'srf_04', target: 'pirate.htb', kind: 'SMB', ports: '445,139', severity: 'med', status: 'active', desc: 'SMB3 — 0 shares via anonymous, needs credentialed recheck' },
      { id: 'srf_05', target: 'pirate.htb', kind: 'WinRM', ports: '5985', severity: 'low', status: 'locked', desc: 'WinRM HTTP — requires valid credentials for access' },
      { id: 'srf_06', target: 'pirate.htb', kind: 'DNS', ports: '53', severity: 'low', status: 'done', desc: 'Simple DNS Plus — zone transfer failed, 7 records enumerated' },
    ],
    findings: [
      { id: 'fnd_001', severity: 'info', title: 'IIS default page exposed', status: 'verified', evidence: ['evidence_a5945d78555c'], desc: 'IIS Windows Server default page at port 80. No custom application detected.' },
      { id: 'fnd_002', severity: 'info', title: 'AD anonymous LDAP bind allowed', status: 'verified', evidence: ['evidence_e9f9ce15d408'], desc: '6 naming contexts returned via anonymous LDAP query.' },
      { id: 'fnd_003', severity: 'low', title: 'Auth surfaces observed at /admin, /login', status: 'unverified', evidence: [], desc: 'Recon observed auth-adjacent routes. Not yet validated.' },
      { id: 'fnd_004', severity: 'med', title: 'AD LDAP username enumeration candidate', status: 'unverified', evidence: ['evidence_e3efd682e2b4', 'evidence_8a080eb13bb0'], desc: 'EDB-32586 may apply. Gated on operator approval.' },
    ],
    pocs: [
      {
        id: 'poc_01', edb: 'EDB-32586', title: 'Microsoft Active Directory LDAP Server — Username Enumeration',
        platform: 'windows', status: 'ready_for_review', gated: true,
        applicability: 'AD/LDAP surface exists on ports 389/636. Exact version unconfirmed.',
        evidence: ['evidence_e3efd682e2b4', 'evidence_8a080eb13bb0'],
        generated: false, downloadable: false,
      },
      {
        id: 'poc_02', edb: 'N/A', title: 'Windows Server 2000 — AD Remote Stack Overflow',
        platform: 'windows', status: 'rejected', gated: false,
        applicability: 'Target is not Windows Server 2000. Rejected by version mismatch.',
        evidence: ['evidence_e3efd682e2b4'],
        generated: false, downloadable: false,
      },
      {
        id: 'poc_03', edb: 'N/A', title: 'MSExchangeADTopology — Unquoted Service Path',
        platform: 'windows', status: 'rejected', gated: false,
        applicability: 'No Exchange service detected on target.',
        evidence: ['evidence_e3efd682e2b4'],
        generated: false, downloadable: false,
      },
    ],
    artifacts: [
      { id: 'art_01', kind: 'tool_output', task: 't_8c4a', title: 'nmap TCP scan output', target: 'pirate.htb', size: '14.2 KB', downloadable: true },
      { id: 'art_02', kind: 'tool_output', task: 't_8c4b', title: 'dig DNS enumeration output', target: 'pirate.htb', size: '3.1 KB', downloadable: true },
      { id: 'art_03', kind: 'model_review', task: 't_8c50', title: 'AI PoC applicability review', target: 'pirate.htb', size: '2.8 KB', downloadable: true },
      { id: 'art_04', kind: 'checkpoint', task: 't_8c4c', title: 'Web content disco checkpoint', target: 'pirate.htb', size: '8.4 KB', downloadable: true },
      { id: 'art_05', kind: 'export', task: 'notion_sync', title: 'Notion export mirror', target: 'pirate.htb', size: '6.1 KB', downloadable: true },
      { id: 'art_06', kind: 'caido_capture', task: 't_8c4f', title: 'Caido replay capture (2 requests)', target: 'pirate.htb', size: '1.4 KB', downloadable: true },
    ],
  },

  // ===== CAIDO — proxy integration =====
  caido: {
    connection: {
      configured: true,
      graphql_url: 'http://localhost:8080/graphql',
      api_token_configured: true,
      ok: true,
      health: { ok: true, status_code: 200, graphql_typename: 'Query' },
    },
    requests: [
      { id: 'req_001', method: 'GET', host: 'pirate.htb', path: '/', status: 200, length: 1247, time: '14:01:12', source: 'proxy', mime: 'text/html' },
      { id: 'req_002', method: 'GET', host: 'pirate.htb', path: '/admin', status: 302, length: 0, time: '14:01:14', source: 'proxy', mime: 'text/html' },
      { id: 'req_003', method: 'GET', host: 'pirate.htb', path: '/login', status: 200, length: 3412, time: '14:01:15', source: 'proxy', mime: 'text/html' },
      { id: 'req_004', method: 'POST', host: 'pirate.htb', path: '/login', status: 401, length: 89, time: '14:01:18', source: 'proxy', mime: 'application/json' },
      { id: 'req_005', method: 'GET', host: 'pirate.htb', path: '/api/v1/health', status: 200, length: 42, time: '14:01:22', source: 'replay', mime: 'application/json' },
      { id: 'req_006', method: 'GET', host: 'pirate.htb', path: '/robots.txt', status: 200, length: 26, time: '14:01:25', source: 'proxy', mime: 'text/plain' },
      { id: 'req_007', method: 'GET', host: 'pirate.htb', path: '/.well-known/security.txt', status: 404, length: 0, time: '14:01:27', source: 'proxy', mime: '' },
      { id: 'req_008', method: 'GET', host: 'pirate.htb', path: '/admin/manager/html', status: 401, length: 0, time: '14:02:09', source: 'replay', mime: 'text/html' },
      { id: 'req_009', method: 'GET', host: 'pirate.htb', path: '/admin/users', status: 200, length: 1248, time: '14:02:08', source: 'replay', mime: 'text/html' },
      { id: 'req_010', method: 'GET', host: '10.129.48.145', path: '/', status: 200, length: 1247, time: '14:00:42', source: 'proxy', mime: 'text/html' },
    ],
    replays: [
      { id: 'rpl_01', name: 'Tomcat manager probe', requests: 2, created: '14:00:14', target: 'pirate.htb', status: 'completed' },
      { id: 'rpl_02', name: 'Auth surface discovery', requests: 4, created: '14:01:12', target: 'pirate.htb', status: 'completed' },
    ],
    savedFilters: [
      { id: 'sf_01', label: 'Target host', httpql: 'req.host.eq:"pirate.htb"' },
      { id: 'sf_02', label: 'Error responses', httpql: 'req.host.eq:"pirate.htb" AND resp.code.gte:400' },
      { id: 'sf_03', label: 'Auth surfaces', httpql: 'req.host.eq:"pirate.htb" AND (req.path.cont:"login" OR req.path.cont:"admin" OR req.path.cont:"api")' },
      { id: 'sf_04', label: 'Token hunt', httpql: 'req.host.eq:"pirate.htb" AND (resp.raw.cont:"api_key" OR resp.raw.cont:"secret" OR resp.raw.cont:"token")' },
    ],
  },

  // ===== TRACES — AI/event tree of pass/fail per task kind =====
  // Mirrors real task kinds from runtime/checkpoints/* in the codebase
  traces: [
    {
      id: 'tr_root', kind: 'workflow.tick', status: 'run', time: '14:02:11',
      summary: 'orchestrator advanced 3 tasks · planner produced 2 candidates',
      route: 'local_fast', model: 'gemma3:12b',
      children: [
        {
          id: 'tr_recon', kind: 'recon.tcp_service_discovery', status: 'pass', time: '13:54:11',
          summary: 'service discovery completed · 14 reachable endpoints',
          route: 'local_fast', model: 'gemma3:12b', task: 't_8c4a',
          children: [
            { id: 'tr_dns', kind: 'recon.dns_enumeration', status: 'pass', time: '13:55:02', summary: 'DNS sub-zone enumeration completed', task: 't_8c4b', route: 'local_fast' },
            { id: 'tr_dns_loop', kind: 'verifier.behavior_review', status: 'partial', time: '13:55:14', summary: 'trace pattern repeated excessively: dns_enumeration · backed off', task: 't_v01', route: 'local_compact' },
          ],
        },
        {
          id: 'tr_web', kind: 'web.content_discovery', status: 'run', time: '14:01:48',
          summary: 'discovering /admin/* under https://pirate.htb:8443 · 312/4096 paths',
          route: 'local_fast', model: 'gemma3:12b', task: 't_8c4c',
          children: [
            { id: 'tr_finding1', kind: 'finding.candidate', status: 'partial', time: '14:01:12', summary: 'Tomcat default manager exposed · partial finding fnd_001', task: 't_f01' },
            { id: 'tr_caido', kind: 'caido.replay_capture', status: 'pass', time: '14:00:14', summary: 'imported 2 replays from local Caido session', task: 't_8c4f', route: 'local_compact' },
          ],
        },
        {
          id: 'tr_kerb', kind: 'recon.kerberos_user_discovery', status: 'pass', time: '13:58:42',
          summary: 'enumerated 2 accounts on DC01 · j.doe, svc_tomcat',
          task: 't_kr1', route: 'local_deep',
          children: [
            { id: 'tr_kerb_atk', kind: 'recon.kerberos_attack_check', status: 'fail', time: '14:01:31', summary: 'AS-REP roast attempt failed · DC unreachable on 88/tcp · 1 retry budget', task: 't_8c51', route: 'local_deep' },
            { id: 'tr_kerb_loop', kind: 'verifier.behavior_review', status: 'partial', time: '14:01:45', summary: 'trace pattern repeated excessively: kerberos_user_discovery · cooled', task: 't_v02', route: 'local_compact' },
          ],
        },
        {
          id: 'tr_poc', kind: 'poc.applicability_validation', status: 'gated', time: '14:00:33',
          summary: 'CVE-2024-50379 applicability check · GATED on operator approval (ap_02)',
          task: 't_8c50', route: 'local_code',
          children: [
            { id: 'tr_search', kind: 'searchsploit.research', status: 'queued', time: '—', summary: 'awaiting approval to fetch PoC source', task: 't_ss1', route: 'local_code' },
          ],
        },
        {
          id: 'tr_cred', kind: 'credentialed_access_check', status: 'gated', time: '14:00:08',
          summary: 'verify Tomcat manager creds · GATED on operator approval (ap_01)',
          task: 't_8c4e', route: 'local_deep',
        },
        {
          id: 'tr_compact', kind: 'memory.compactor', status: 'pass', time: '14:01:48',
          summary: 'memory compaction complete · promoted 6 → semantic, dropped 22 stale episodic',
          task: 't_8c4f', route: 'local_compact',
        },
        {
          id: 'tr_notion', kind: 'notion.sync', status: 'gated', time: '14:01:55',
          summary: 'publish target notes for pirate.htb · GATED (ap_03)',
          task: 't_8c52', route: 'local_compact',
        },
        {
          id: 'tr_search_old', kind: 'searchsploit.research', status: 'fail', time: '13:48:22',
          summary: 'no evidence-backed search terms available for exploit research',
          task: 't_ss0', route: 'local_code',
        },
      ],
    },
  ],

  // ===== GEO — ASN / geoip pins for traceroute & network topology =====
  geo: {
    pins: [
      { id: 'g_self', kind: 'self', label: 'operator', city: 'San Francisco', country: 'US', lat: 37.7749, lon: -122.4194, asn: 'AS7922', org: 'Comcast', status: 'live' },
      { id: 'g_relay', kind: 'relay', label: 'relay (Frankfurt)', city: 'Frankfurt', country: 'DE', lat: 50.1109, lon: 8.6821, asn: 'AS24940', org: 'Hetzner Online', status: 'live' },
      { id: 'g_htb', kind: 'target', label: 'pirate.htb (10.129.47.117)', city: 'HTB Lab', country: 'EU', lat: 51.5074, lon: -0.1278, asn: 'AS33915', org: 'HTB Net', status: 'probing' },
      { id: 'g_dc', kind: 'target', label: 'DC01 (10.129.47.118)', city: 'HTB Lab', country: 'EU', lat: 51.5174, lon: -0.1378, asn: 'AS33915', org: 'HTB Net', status: 'gated' },
      { id: 'g_caido', kind: 'tool', label: 'caido proxy', city: 'localhost', country: 'US', lat: 37.7749, lon: -122.4194, asn: 'local', org: 'Caido', status: 'live' },
      { id: 'g_ollama', kind: 'tool', label: 'ollama serve', city: 'localhost', country: 'US', lat: 37.7649, lon: -122.4094, asn: 'local', org: 'GPU node', status: 'live' },
      { id: 'g_notion', kind: 'sync', label: 'notion api', city: 'San Francisco', country: 'US', lat: 37.7749, lon: -122.4194, asn: 'AS54113', org: 'Notion', status: 'idle' },
      { id: 'g_discord', kind: 'sync', label: 'discord webhook', city: 'San Francisco', country: 'US', lat: 37.7749, lon: -122.4194, asn: 'AS49544', org: 'Discord', status: 'live' },
    ],
    traces: [
      { from: 'g_self', to: 'g_relay', kind: 'ok', label: 'relay · 14ms' },
      { from: 'g_relay', to: 'g_htb', kind: 'ok', label: 'tcp:8443 · 41ms' },
      { from: 'g_relay', to: 'g_dc', kind: 'fail', label: 'tcp:88 unreachable' },
      { from: 'g_self', to: 'g_caido', kind: 'ok', label: 'graphql · 0ms' },
      { from: 'g_self', to: 'g_ollama', kind: 'ok', label: 'gpu · 0ms' },
      { from: 'g_self', to: 'g_discord', kind: 'warn', label: 'webhook · last 13:59:48' },
    ],
    asns: [
      { num: 'AS24940', org: 'Hetzner Online GmbH',     country: 'DE', refs: 4, role: 'transit' },
      { num: 'AS33915', org: 'HTB Lab Network',          country: 'EU', refs: 6, role: 'target-net' },
      { num: 'AS7922',  org: 'Comcast Cable',            country: 'US', refs: 1, role: 'operator' },
      { num: 'AS54113', org: 'Notion Labs Inc.',         country: 'US', refs: 1, role: 'sync' },
      { num: 'AS49544', org: 'Discord Inc.',             country: 'US', refs: 1, role: 'sync' },
      { num: 'local',   org: 'localhost · loopback',     country: '—',  refs: 2, role: 'tooling' },
    ],
  },
};
