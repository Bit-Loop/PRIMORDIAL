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
  const [tab, setTab] = useStateD('controls');
  const [autonomy, setAutonomy] = useStateD(D.runtime.autonomy);
  const [intent, setIntent] = useStateD(D.runtime.intent);
  const [contMode, setContMode] = useStateD(false);
  const [maxExec, setMaxExec] = useStateD(3);
  const [interval, setInterval] = useStateD(30);

  const cpu = D.runtime.cpu;
  const gpu = D.runtime.gpu;
  const mem = D.runtime.mem;

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
    { k: 'targets',   v: 3,   d: '2 active',     tone: 'ok' },
    { k: 'evidence',  v: 101, d: '+22 today',    tone: '' },
    { k: 'findings',  v: 4,   d: '1 verified',   tone: 'warn' },
    { k: 'tasks',     v: 8,   d: '4 running',    tone: '' },
    { k: 'memory',    v: 318, d: 'episodic',     tone: '' },
    { k: 'approvals', v: 2,   d: 'queued',       tone: 'crit' },
    { k: 'artifacts', v: 47,  d: '1.2 GB',       tone: '' },
    { k: 'traces',    v: 612, d: 'audit',        tone: '' },
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
                <button className="btn ghost sm">REFRESH</button>
                <button className="btn primary sm">RUN TICK</button>
                <button className="btn danger sm">STOP WORK</button>
              </>
            }
            className="fill"
          >
            <div className="tabs" style={{ marginBottom: 10 }}>
              {['controls', 'models', 'integrations', 'credentials'].map(t => (
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
                    <option>recon-and-enum</option>
                    <option>verify-findings</option>
                    <option>poc-research</option>
                    <option>credentialed-pivot</option>
                    <option>compact-and-rest</option>
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
                  <input className="input" type="number" defaultValue={120} />
                </Field>
                <Field label="CPU AI timeout (s)">
                  <input className="input" type="number" defaultValue={300} />
                </Field>
                <Field label="stale run timeout (s)">
                  <input className="input" type="number" defaultValue={3600} />
                </Field>
                <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  <button className="btn">COMPACT MEMORY</button>
                  <button className="btn">PROCESS QUEUES</button>
                  <button className="btn ghost">WARM MODELS</button>
                  <button className="btn ghost">CLEAR MODELS</button>
                  <button className="btn ghost">APPLY TUNING</button>
                  <span style={{ flex: 1 }}></span>
                  <span className="banner green" style={{ alignSelf: 'center' }}>
                    <Dot tone="green" /> POLICY: PoC EXEC GATED · DDOS FORBIDDEN
                  </span>
                </div>
              </div>
            )}
            {tab === 'models' && (
              <table className="t">
                <thead><tr><th>Route</th><th>Model</th><th>Status</th><th>Hot</th><th>Ctx</th><th>Action</th></tr></thead>
                <tbody>
                  {D.models.map(m => (
                    <tr key={m.route}>
                      <td><span className="strong">{m.route}</span></td>
                      <td>{m.model}</td>
                      <td>{m.loaded ? <Pill tone="green">LOADED</Pill> : <Pill tone="gray">COLD</Pill>}</td>
                      <td>{m.hot ? <Dot tone="cyan" /> : <Dot tone="gray" />}</td>
                      <td className="dim">{m.ctx ? m.ctx.toLocaleString() : '—'}</td>
                      <td><button className="btn ghost sm">SWAP</button> <button className="btn ghost sm">{m.loaded ? 'UNLOAD' : 'WARM'}</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {tab === 'integrations' && (
              <div className="grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
                {[
                  { n: 'Notion',  d: 'parent: HTB Lab Notes',         s: 'connected', tone: 'green' },
                  { n: 'Discord', d: 'webhook · #primordial-alerts',  s: 'connected', tone: 'green' },
                  { n: 'Caido',   d: '127.0.0.1:8080/graphql',        s: 'connected', tone: 'green' },
                  { n: 'Lab/HTB', d: 'pirate.htb · j.doe',            s: 'set',       tone: 'cyan' },
                  { n: 'Ollama',  d: 'localhost:11434 · 4 models',    s: 'live',      tone: 'cyan' },
                  { n: 'Premium', d: 'remote_premium',                 s: 'disabled',  tone: 'gray' },
                ].map(i => (
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
                {[
                  { n: 'Notion',  fields: ['API Key', 'Parent Page ID', 'API Version'] },
                  { n: 'Discord', fields: ['Webhook URL'] },
                  { n: 'Caido',   fields: ['GraphQL URL', 'API Token'] },
                  { n: 'Lab/HTB', fields: ['Username', 'Password', 'Domain'] },
                ].map(g => (
                  <div key={g.n} style={{ padding: 10, border: '1px solid var(--line)', borderRadius: 4, background: 'var(--bg-deep)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, alignItems: 'center' }}>
                      <span className="strong" style={{ fontWeight: 600 }}>{g.n}</span>
                      <Pill tone="green">SAVED</Pill>
                    </div>
                    <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                      {g.fields.map(f => (
                        <Field key={f} label={f}>
                          <input className="input" type={f.toLowerCase().includes('password') || f.toLowerCase().includes('token') || f.toLowerCase().includes('key') ? 'password' : 'text'} placeholder="•••••••••••" />
                        </Field>
                      ))}
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
                    <button className="btn primary sm" onClick={() => onApprove?.(a)}>APPROVE</button>
                    <button className="btn danger sm" onClick={() => onReject?.(a)}>REJECT</button>
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
