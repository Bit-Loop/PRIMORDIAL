/* global React, Panel, Pill, Dot, StatusPill, Field */
const { useState: useStateD, useEffect: useEffectD, useMemo: useMemoD } = React;

function MeterRow({ label, val, tone }) {
  const cls = val > 0.85 ? 'crit' : val > 0.65 ? 'warn' : '';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--mono)', fontSize: 10.5 }}>
        <span className="dim" style={{ textTransform: 'uppercase', letterSpacing: '0.08em', fontSize: 9.5 }}>{label}</span>
        <span className="strong">{Math.round(val * 100)}%</span>
      </div>
      <div className="meter"><div className={`meter-fill ${cls}`} style={{ width: `${val * 100}%` }}></div></div>
    </div>
  );
}

function Sparkline({ data, color = 'var(--cyan)', height = 28 }) {
  const w = 120, h = height;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const span = max - min || 1;
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - min) / span) * (h - 2) - 1}`).join(' ');
  return (
    <svg width={w} height={h} style={{ display: 'block' }}>
      <polyline fill="none" stroke={color} strokeWidth="1.25" points={pts} />
    </svg>
  );
}

function DashboardMode({ tweaks, onApprove, onReject }) {
  const D = window.PD_DATA;
  const API = window.PD_API || {};
  const [tab, setTab] = useStateD('controls');
  const [autonomy, setAutonomy] = useStateD(D.runtime.autonomy);
  const [intent, setIntent] = useStateD(D.runtime.intent);
  const [contMode, setContMode] = useStateD(D.runtime.executionMode?.mode === 'continuous');
  const [maxExec, setMaxExec] = useStateD(3);
  const [interval, setInterval] = useStateD(D.runtime.executionMode?.interval_seconds || 30);
  const [tuning, setTuning] = useStateD(D.runtime.runtimeTuning || {});
  const [credentialDraft, setCredentialDraft] = useStateD({});
  const [modelDraft, setModelDraft] = useStateD({});
  const [processorDraft, setProcessorDraft] = useStateD({});
  const [targetDraft, setTargetDraft] = useStateD({});
  const [scopeImport, setScopeImport] = useStateD('{\n  "targets": []\n}');
  const [selfTest, setSelfTest] = useStateD(D.selfTest || null);

  useEffectD(() => {
    setAutonomy(D.runtime.autonomy);
    setIntent(D.runtime.intent);
    setContMode(D.runtime.executionMode?.mode === 'continuous');
    setInterval(D.runtime.executionMode?.interval_seconds || 30);
    setTuning(D.runtime.runtimeTuning || {});
  }, [D.runtime.autonomy, D.runtime.intent, D.runtime.executionMode?.mode, D.runtime.executionMode?.interval_seconds, D.runtime.runtimeTuning]);

  const cpu = D.runtime.cpu;
  const gpu = D.runtime.gpu;
  const mem = D.runtime.mem;
  const countsPayload = D.runtime.counts || {};

  // fake live sparklines
  const [tickT, setTickT] = useStateD(0);
  useEffectD(() => {
    const id = window.setInterval(() => setTickT(t => t + 1), 1500);
    return () => window.clearInterval(id);
  }, []);
  const sparks = useMemoD(() => {
    const seed = (n, base) => Array.from({ length: 24 }, (_, i) =>
      base + Math.sin((tickT + i) * 0.45 + n) * 0.15 + Math.sin((tickT + i) * 0.13 + n * 2) * 0.1
    );
    return { cpu: seed(1, cpu), gpu: seed(2, gpu), mem: seed(3, mem) };
  }, [tickT, cpu, gpu, mem]);

  const counts = [
    { k: 'targets',   v: D.scope.length,                  d: `${D.scope.filter(s => s.status === 'active').length} active`, tone: 'ok' },
    { k: 'evidence',  v: countsPayload.evidence || 0,     d: 'runtime', tone: '' },
    { k: 'findings',  v: countsPayload.findings || 0,     d: 'verified + candidates', tone: (countsPayload.findings || 0) ? 'warn' : '' },
    { k: 'tasks',     v: D.tasks.length,                  d: `${D.runtime.activeTasks || 0} running`, tone: '' },
    { k: 'memory',    v: countsPayload.memory_entries || 0, d: 'entries', tone: '' },
    { k: 'approvals', v: D.approvals.length,              d: 'pending', tone: D.approvals.length ? 'crit' : '' },
    { k: 'artifacts', v: countsPayload.artifacts || 0,    d: 'stored', tone: '' },
    { k: 'traces',    v: D.traces[0]?.children?.length || 0, d: 'audit', tone: '' },
  ];

  const intentOptions = D.runtime.operatorIntent?.intents || [];
  const updateTuning = (key, value) => setTuning(t => ({ ...t, [key]: Number(value) || 0 }));
  const modelRoles = D.modelPayload?.roles || [];
  const availableModels = D.modelPayload?.available_models || [];
  const roleMetric = (role) => D.modelPayload?.role_metrics?.[role] || modelRoles.find(r => r.role === role)?.metrics || {};
  const saveModels = () => API.post?.('/api/models', { roles: modelDraft, processors: processorDraft });
  const resetModels = () => { setModelDraft({}); setProcessorDraft({}); };
  const saveTarget = () => {
    const assets = String(targetDraft.assets || '').split(/\n|,/).map(v => v.trim()).filter(Boolean);
    return API.post?.('/api/targets', {
      handle: targetDraft.handle,
      display_name: targetDraft.display_name,
      profile: targetDraft.profile || 'hack_the_box',
      active_ip: targetDraft.active_ip,
      in_scope: targetDraft.in_scope !== false,
      assets,
    });
  };
  const editTarget = (row) => setTargetDraft({
    handle: row.handle,
    display_name: row.handle,
    profile: row.profile,
    active_ip: row.ip,
    in_scope: row.status === 'active',
    assets: (D.scopePayload?.targets || []).find(item => item.target?.handle === row.handle)?.assets?.map(a => a.asset).join('\n') || '',
  });
  const importScope = () => {
    let parsed = {};
    try { parsed = JSON.parse(scopeImport || '{}'); } catch (err) { return Promise.reject(err); }
    return API.post?.('/api/scope/import', { profile: parsed.profile || 'hack_the_box', source: 'ops-panel', scope: parsed });
  };
  const runSelfTest = async () => {
    const payload = await API.request?.('/api/self-test');
    setSelfTest(payload);
    return payload;
  };
  const setCredentialValue = (service, key, value) => {
    setCredentialDraft(d => ({ ...d, [service]: { ...(d[service] || {}), [key]: value } }));
  };
  const credentialStatus = (service, key) => D.credentials?.services?.[service]?.[key] || {};
  const saveCredentials = (service) => API.post?.(`/api/credentials/${service}`, credentialDraft[service] || {});
  const clearCredentials = (service) => API.delete?.(`/api/credentials/${service}`);
  const applyControlSettings = async () => {
    await API.post?.('/api/execution-mode', { mode: contMode ? 'continuous' : 'tick', interval_seconds: interval });
    await API.post?.('/api/operator-intent', { intent_id: intent });
    await API.post?.('/api/runtime-settings', tuning);
  };
  const resolveApproval = (approval, verdict) => {
    if (verdict === 'approve') {
      onApprove?.(approval);
      return API.post?.('/api/actions/approve', { task_id: approval.task || approval.id });
    }
    onReject?.(approval);
    return API.post?.('/api/actions/deny', { task_id: approval.task || approval.id });
  };
  const integrationRows = [
    {
      n: 'Notion',
      d: D.notes?.syncStatus?.configured ? 'credentials configured' : 'local findings export only',
      s: D.notes?.syncStatus?.configured ? 'configured' : 'missing',
      tone: D.notes?.syncStatus?.configured ? 'green' : 'gray',
    },
    {
      n: 'Discord',
      d: credentialStatus('discord', 'webhook_url').hint || 'webhook not configured',
      s: credentialStatus('discord', 'webhook_url').configured ? 'configured' : 'missing',
      tone: credentialStatus('discord', 'webhook_url').configured ? 'green' : 'gray',
    },
    {
      n: 'Caido',
      d: D.caido?.connection?.graphql_url || 'GraphQL credentials missing',
      s: D.caido?.connection?.ok ? 'live' : D.caido?.connection?.configured ? 'configured' : 'missing',
      tone: D.caido?.connection?.ok ? 'green' : D.caido?.connection?.configured ? 'cyan' : 'gray',
    },
    {
      n: 'Lab',
      d: credentialStatus('lab', 'username').hint || 'lab credentials not configured',
      s: credentialStatus('lab', 'username').configured ? 'set' : 'missing',
      tone: credentialStatus('lab', 'username').configured ? 'cyan' : 'gray',
    },
    {
      n: 'Ollama',
      d: D.modelPayload?.ollama?.base_url || 'localhost',
      s: D.modelPayload?.ollama?.ok ? 'live' : 'offline',
      tone: D.modelPayload?.ollama?.ok ? 'cyan' : 'gray',
    },
    { n: 'Premium', d: 'remote_premium', s: 'disabled', tone: 'gray' },
  ];
  const credentialGroups = [
    { service: 'notion', n: 'Notion', fields: [['api_key', 'API Key'], ['parent_page_id', 'Parent Page ID'], ['version', 'API Version']] },
    { service: 'discord', n: 'Discord', fields: [['webhook_url', 'Webhook URL']] },
    { service: 'caido', n: 'Caido', fields: [['graphql_url', 'GraphQL URL'], ['api_token', 'API Token']] },
    { service: 'lab', n: 'Lab', fields: [['username', 'Username'], ['password', 'Password'], ['domain', 'Domain']] },
  ];

  return (
    <>
      <window.TopBar
        crumbs={['primordial', 'ops', 'control plane']}
        stats={[
          { k: 'autonomy', v: autonomy },
          { k: 'intent', v: intent },
          { k: 'uptime', v: D.runtime.uptime },
          { k: 'cpu', v: `${Math.round(cpu * 100)}%` },
          { k: 'gpu', v: `${Math.round(gpu * 100)}%` },
        ]}
      />
      <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(360px, 1fr)', gap: 8, padding: 8 }}>
        {/* left column */}
        <div className="col" style={{ minHeight: 0, gap: 8 }}>
          {/* KPI strip */}
          <div className="grid" style={{ gridTemplateColumns: `repeat(${counts.length}, minmax(0, 1fr))`, gap: 6 }}>
            {counts.map(c => (
              <div key={c.k} className={`kpi ${c.tone}`}>
                <span className="kpi-k">{c.k}</span>
                <span className="kpi-v">{c.v}</span>
                <span className="kpi-d">{c.d}</span>
              </div>
            ))}
          </div>

          {/* Tabs panel */}
          <Panel
            title="Runtime"
            actions={
              <>
                <button className="btn ghost sm" onClick={() => API.refresh?.()}>REFRESH</button>
                <button className="btn primary sm" onClick={() => API.action?.('tick', { max_executions: maxExec })}>RUN TICK</button>
                <button className="btn danger sm" onClick={() => API.action?.('stop-work')}>STOP WORK</button>
              </>
            }
            className="fill"
          >
            <div className="tabs" style={{ marginBottom: 10 }}>
              {['controls', 'models', 'targets', 'scope', 'self test', 'integrations', 'credentials'].map(t => (
                <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>{t}</button>
              ))}
            </div>
            {tab === 'controls' && (
              <div className="grid" style={{ gridTemplateColumns: 'repeat(4, minmax(0,1fr))', gap: 10 }}>
                <Field label="autonomy mode">
                  <select className="input" value={autonomy} onChange={e => setAutonomy(e.target.value)}>
                    <option>assisted</option>
                    <option>supervised</option>
                    <option>supervised_auto</option>
                    <option>high_autonomy</option>
                  </select>
                </Field>
                <Field label="operator intent">
                  <select className="input" value={intent} onChange={e => setIntent(e.target.value)}>
                    {intentOptions.length ? intentOptions.map(item => (
                      <option key={item.id} value={item.id}>{item.label || item.id}</option>
                    )) : <option value={intent}>{intent}</option>}
                  </select>
                </Field>
                <Field label="execution mode">
                  <select className="input" value={contMode ? 'cont' : 'tick'} onChange={e => setContMode(e.target.value === 'cont')}>
                    <option value="tick">Tick mode</option>
                    <option value="cont">Continuous (autonomous)</option>
                  </select>
                </Field>
                <Field label="max executions">
                  <input className="input" type="number" value={maxExec} onChange={e => setMaxExec(+e.target.value)} />
                </Field>
                <Field label="continuous interval (s)">
                  <input className="input" type="number" value={interval} onChange={e => setInterval(+e.target.value)} />
                </Field>
                <Field label="GPU AI timeout (s)">
                  <input className="input" type="number" value={tuning.gpu_ai_timeout_seconds || 120} onChange={e => updateTuning('gpu_ai_timeout_seconds', e.target.value)} />
                </Field>
                <Field label="CPU AI timeout (s)">
                  <input className="input" type="number" value={tuning.cpu_ai_timeout_seconds || 300} onChange={e => updateTuning('cpu_ai_timeout_seconds', e.target.value)} />
                </Field>
                <Field label="stale run timeout (s)">
                  <input className="input" type="number" value={tuning.stale_run_timeout_seconds || 3600} onChange={e => updateTuning('stale_run_timeout_seconds', e.target.value)} />
                </Field>
                <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  <button className="btn" onClick={() => API.action?.('compact')}>COMPACT MEMORY</button>
                  <button className="btn" onClick={() => API.action?.('process-queues')}>PROCESS QUEUES</button>
                  <button className="btn ghost" onClick={() => API.action?.('warm-models', { keep_alive: '8h' })}>WARM MODELS</button>
                  <button className="btn ghost" onClick={() => API.action?.('clear-models')}>CLEAR MODELS</button>
                  <button className="btn ghost" onClick={applyControlSettings}>APPLY TUNING</button>
                  <span style={{ flex: 1 }}></span>
                  <span className="banner green" style={{ alignSelf: 'center' }}>
                    <Dot tone="green" /> POLICY: PoC EXEC GATED · DDOS FORBIDDEN
                  </span>
                </div>
              </div>
            )}
            {tab === 'models' && (
              <div className="col gap-8">
                <table className="t">
                  <thead><tr><th>Role</th><th>Model</th><th>Processor</th><th>Score</th><th>Pass</th><th>Failures</th><th>Latency</th></tr></thead>
                  <tbody>
                    {modelRoles.map(r => {
                      const m = roleMetric(r.role);
                      return (
                        <tr key={r.role}>
                          <td><span className="strong">{r.label || r.role}</span><div className="dim mono">{r.role}</div></td>
                          <td>
                            <select className="input" value={modelDraft[r.role] || r.selected_model || r.default_model || ''} onChange={e => setModelDraft(d => ({ ...d, [r.role]: e.target.value }))}>
                              {[r.selected_model, r.default_model, ...availableModels].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).map(model => <option key={model} value={model}>{model}</option>)}
                            </select>
                          </td>
                          <td>
                            <select className="input" value={processorDraft[r.role] || r.processor || r.default_processor || 'gpu'} onChange={e => setProcessorDraft(d => ({ ...d, [r.role]: e.target.value }))}>
                              <option value="gpu">gpu</option><option value="cpu">cpu</option>
                            </select>
                          </td>
                          <td>{m.aggregate_score != null ? Number(m.aggregate_score).toFixed(3) : '—'}</td>
                          <td>{m.pass_rate != null ? `${Math.round(Number(m.pass_rate) * 100)}%` : '—'}</td>
                          <td className="dim">{m.hallucination_count || 0} halluc. · {m.unsafe_compliance_failures || 0} unsafe</td>
                          <td className="dim">{m.avg_latency_sec ? `${Number(m.avg_latency_sec).toFixed(1)}s` : '—'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <div className="row gap-6">
                  <button className="btn primary sm" onClick={saveModels}>SAVE ROLES</button>
                  <button className="btn ghost sm" onClick={resetModels}>RESET DRAFT</button>
                  <button className="btn ghost sm" onClick={() => API.action?.('warm-models', { keep_alive: '8h' })}>WARM</button>
                  <button className="btn ghost sm" onClick={() => API.action?.('clear-models')}>CLEAR</button>
                </div>
              </div>
            )}
            {tab === 'targets' && (
              <div className="grid" style={{ gridTemplateColumns: 'minmax(0, 1.4fr) minmax(280px, 0.8fr)', gap: 10 }}>
                <table className="t">
                  <thead><tr><th>Target</th><th>Profile</th><th>IP</th><th>Assets</th><th>Records</th><th></th></tr></thead>
                  <tbody>{D.scope.map(row => (
                    <tr key={row.handle}>
                      <td><span className="strong">{row.handle}</span><div className="dim mono">{row.status}</div></td>
                      <td>{row.profile}</td><td>{row.ip || '—'}</td><td>{row.assets}</td>
                      <td className="dim">{row.evidence} ev · {row.findings} fnd</td>
                      <td className="row gap-4"><button className="btn ghost sm" onClick={() => editTarget(row)}>EDIT</button><button className="btn danger sm" onClick={() => API.delete?.(`/api/targets/${encodeURIComponent(row.handle)}?profile=${encodeURIComponent(row.profile)}`)}>DELETE</button></td>
                    </tr>
                  ))}</tbody>
                </table>
                <div className="col gap-8" style={{ padding: 10, border: '1px solid var(--line)', borderRadius: 4, background: 'var(--bg-deep)' }}>
                  <Field label="handle"><input className="input" value={targetDraft.handle || ''} onChange={e => setTargetDraft(d => ({ ...d, handle: e.target.value }))} /></Field>
                  <Field label="display name"><input className="input" value={targetDraft.display_name || ''} onChange={e => setTargetDraft(d => ({ ...d, display_name: e.target.value }))} /></Field>
                  <Field label="profile"><input className="input" value={targetDraft.profile || 'hack_the_box'} onChange={e => setTargetDraft(d => ({ ...d, profile: e.target.value }))} /></Field>
                  <Field label="active ip"><input className="input" value={targetDraft.active_ip || ''} onChange={e => setTargetDraft(d => ({ ...d, active_ip: e.target.value }))} /></Field>
                  <Field label="assets"><textarea className="input" rows="4" value={targetDraft.assets || ''} onChange={e => setTargetDraft(d => ({ ...d, assets: e.target.value }))} /></Field>
                  <label className="row gap-6 mono" style={{ fontSize: 11 }}><input type="checkbox" checked={targetDraft.in_scope !== false} onChange={e => setTargetDraft(d => ({ ...d, in_scope: e.target.checked }))} /> in scope</label>
                  <button className="btn primary sm" onClick={saveTarget}>SAVE TARGET</button>
                </div>
              </div>
            )}
            {tab === 'scope' && (
              <div className="grid" style={{ gridTemplateColumns: '260px minmax(0, 1fr)', gap: 10 }}>
                <div className="grid" style={{ gap: 8 }}>
                  {Object.entries(D.scopePayload?.totals || {}).map(([k, v]) => <div key={k} className="kpi"><span className="kpi-k">{k}</span><span className="kpi-v">{v}</span></div>)}
                  {(D.scopeProfiles?.profiles || []).map(p => <div key={p.id} className="row gap-6 mono" style={{ fontSize: 10.5, padding: '6px 0', borderBottom: '1px dashed var(--line)' }}><Pill tone={p.builtin ? 'cyan' : 'green'}>{p.id}</Pill><span className="dim">{p.base_profile}</span></div>)}
                </div>
                <div className="col gap-8">
                  <textarea className="input mono" rows="10" value={scopeImport} onChange={e => setScopeImport(e.target.value)} />
                  <button className="btn primary sm" onClick={importScope}>IMPORT JSON</button>
                </div>
              </div>
            )}
            {tab === 'self test' && (
              <div className="col gap-8">
                <div className="row gap-8" style={{ alignItems: 'center' }}>
                  <Pill tone={selfTest?.status === 'pass' ? 'green' : selfTest?.status === 'fail' ? 'red' : 'yellow'}>{(selfTest?.status || 'not run').toUpperCase()}</Pill>
                  <button className="btn primary sm" onClick={runSelfTest}>RUN SELF TEST</button>
                </div>
                <table className="t">
                  <thead><tr><th>Status</th><th>Check</th><th>Details</th></tr></thead>
                  <tbody>{(selfTest?.checks || []).map(ch => (
                    <tr key={ch.id}><td><StatusPill status={ch.status === 'pass' ? 'done' : ch.status === 'fail' ? 'failed' : 'queued'} /></td><td className="strong">{ch.label}</td><td className="dim mono">{JSON.stringify(ch.details || {}).slice(0, 180)}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            )}
            {tab === 'integrations' && (
              <div className="grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
                {integrationRows.map(i => (
                  <div key={i.n} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 10px', border: '1px solid var(--line)', borderRadius: 4, background: 'var(--bg-deep)' }}>
                    <div>
                      <div className="strong" style={{ fontWeight: 600 }}>{i.n}</div>
                      <div className="dim mono" style={{ fontSize: 10.5 }}>{i.d}</div>
                    </div>
                    <Pill tone={i.tone}>{i.s.toUpperCase()}</Pill>
                  </div>
                ))}
              </div>
            )}
            {tab === 'credentials' && (
              <div className="grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
                {credentialGroups.map(g => (
                  <div key={g.n} style={{ padding: 10, border: '1px solid var(--line)', borderRadius: 4, background: 'var(--bg-deep)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, alignItems: 'center' }}>
                      <span className="strong" style={{ fontWeight: 600 }}>{g.n}</span>
                      <Pill tone={g.fields.some(([key]) => credentialStatus(g.service, key).configured) ? 'green' : 'gray'}>
                        {g.fields.some(([key]) => credentialStatus(g.service, key).configured) ? 'SAVED' : 'MISSING'}
                      </Pill>
                    </div>
                    <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                      {g.fields.map(([key, label]) => (
                        <Field key={key} label={label}>
                          <input
                            className="input"
                            type={key.includes('password') || key.includes('token') || key.includes('key') ? 'password' : 'text'}
                            placeholder={credentialStatus(g.service, key).hint || 'missing'}
                            value={credentialDraft[g.service]?.[key] || ''}
                            onChange={e => setCredentialValue(g.service, key, e.target.value)}
                          />
                        </Field>
                      ))}
                    </div>
                    <div className="row gap-4" style={{ marginTop: 8 }}>
                      <button className="btn primary sm" onClick={() => saveCredentials(g.service)}>SAVE</button>
                      <button className="btn ghost sm" onClick={() => clearCredentials(g.service)}>CLEAR</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          {/* Tasks */}
          <Panel
            title="Active Tasks"
            sub={`${D.tasks.filter(t => t.status === 'running').length} running · ${D.tasks.filter(t => t.status === 'queued').length} queued`}
            className="fill"
            bodyClass="tight"
          >
            <table className="t">
              <thead><tr><th>Status</th><th>Kind</th><th>Title</th><th>Target</th><th>Route · Model</th><th>Elapsed</th><th></th></tr></thead>
              <tbody>
                {D.tasks.map(t => (
                  <tr key={t.id} className={t.status === 'running' ? 'running' : ''}>
                    <td><StatusPill status={t.status} /></td>
                    <td><span className="strong">{t.kind}</span></td>
                    <td>{t.title}</td>
                    <td>{t.target}</td>
                    <td className="dim">{t.route} · {t.model}</td>
                    <td className="dim">{t.ms ? `${(t.ms / 1000).toFixed(1)}s` : '—'}</td>
                    <td><button className="btn ghost sm">INSPECT</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        </div>

        {/* right column */}
        <div className="col" style={{ minHeight: 0, gap: 8 }}>
          {/* host load */}
          <Panel title="Host Load">
            <div className="grid" style={{ gap: 14 }}>
              <div className="row" style={{ gap: 12, alignItems: 'center' }}>
                <div style={{ flex: 1 }}><MeterRow label="CPU" val={cpu} /></div>
                <Sparkline data={sparks.cpu} color="var(--cyan)" />
              </div>
              <div className="row" style={{ gap: 12, alignItems: 'center' }}>
                <div style={{ flex: 1 }}><MeterRow label="GPU" val={gpu} /></div>
                <Sparkline data={sparks.gpu} color="var(--violet)" />
              </div>
              <div className="row" style={{ gap: 12, alignItems: 'center' }}>
                <div style={{ flex: 1 }}><MeterRow label="MEM" val={mem} /></div>
                <Sparkline data={sparks.mem} color="var(--green)" />
              </div>
              <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 8, paddingTop: 4, borderTop: '1px dashed var(--line)' }}>
                <div><div className="kpi-k">net in</div><div className="mono strong">{D.runtime.netIn}</div></div>
                <div><div className="kpi-k">net out</div><div className="mono strong">{D.runtime.netOut}</div></div>
                <div><div className="kpi-k">gpu memory</div><div className="mono strong">{D.runtime.gpuMemory?.used_label || 'unavailable'}</div></div>
                <div><div className="kpi-k">gpu free</div><div className="mono strong">{D.runtime.gpuMemory?.free_label || 'unavailable'}</div></div>
              </div>
            </div>
          </Panel>

          {/* approvals */}
          <Panel
            title="Approvals"
            sub={`${D.approvals.length} pending`}
            actions={<button className="btn ghost sm">QUEUE ALL</button>}
            className="fill"
          >
            <div className="col" style={{ gap: 8 }}>
              {D.approvals.map((a, i) => (
                <div key={a.id} className={`approval ${a.risk} ${i === 0 ? 'urgent' : ''}`}>
                  <div className="approval-head">
                    <Pill tone={a.risk === 'high' ? 'red' : a.risk === 'med' ? 'yellow' : 'blue'}>{a.risk.toUpperCase()}</Pill>
                    <span className="approval-title">{a.title}</span>
                    <span className="approval-meta" style={{ marginLeft: 'auto' }}>{a.id}</span>
                  </div>
                  <div className="approval-meta">{a.target} · {a.primitive} · {a.limits}</div>
                  <div style={{ color: 'var(--txt)', fontSize: 11.5 }}>{a.detail}</div>
                  <div className="dim" style={{ fontSize: 11, fontStyle: 'italic' }}>{a.reason}</div>
                  <div className="approval-actions">
                    <button className="btn primary sm" onClick={() => resolveApproval(a, 'approve')}>APPROVE</button>
                    <button className="btn danger sm" onClick={() => resolveApproval(a, 'reject')}>REJECT</button>
                    <button className="btn ghost sm">DEFER</button>
                    <button className="btn ghost sm" style={{ marginLeft: 'auto' }}>OPEN IN CHAT →</button>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* events */}
          <Panel
            title="Audit Stream"
            sub="control-plane events"
            actions={<button className="btn ghost sm">CLEAR</button>}
            className="fill"
            bodyClass="tight"
          >
            <div className="log">
              {D.events.map((e, i) => (
                <div className="log-row" key={i}>
                  <span className="log-t">{e.t}</span>
                  <span className={`log-lvl ${e.lvl}`}>{e.lvl}</span>
                  <span className="log-msg" dangerouslySetInnerHTML={{ __html: e.msg }} />
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

window.DashboardMode = DashboardMode;
