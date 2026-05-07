/* global React, Panel, Pill, Dot, StatusPill */
const { useState: useStateI, useMemo: useMemoI } = React;

const SEV_TONE = { high: 'red', med: 'yellow', low: 'blue', info: 'gray' };
const STATUS_TONE = { active: 'cyan', done: 'green', locked: 'gray', unverified: 'yellow', verified: 'green', rejected: 'red', ready_for_review: 'violet' };

function SurfaceRow({ s, sel, onSel }) {
  const active = sel === s.id;
  return (
    <tr className={active ? 'sel' : ''} onClick={() => onSel(s.id)} style={{ cursor: 'pointer' }}>
      <td><Pill tone={SEV_TONE[s.severity] || 'gray'}>{s.severity.toUpperCase()}</Pill></td>
      <td><span className="strong">{s.kind}</span></td>
      <td className="dim">{s.ports}</td>
      <td><Pill tone={STATUS_TONE[s.status] || 'gray'}>{s.status.toUpperCase()}</Pill></td>
      <td style={{ maxWidth: 280, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.desc}</td>
    </tr>
  );
}

function FindingRow({ f, sel, onSel }) {
  return (
    <div
      onClick={() => onSel(f.id)}
      style={{
        padding: '8px 10px', borderBottom: '1px solid var(--line)',
        background: sel === f.id ? 'var(--cyan-soft)' : 'transparent',
        cursor: 'pointer', display: 'flex', flexDirection: 'column', gap: 4,
      }}
    >
      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <Pill tone={SEV_TONE[f.severity] || 'gray'}>{f.severity.toUpperCase()}</Pill>
        <Pill tone={STATUS_TONE[f.status] || 'gray'}>{f.status.toUpperCase()}</Pill>
        <span className="strong" style={{ flex: 1, fontSize: 12 }}>{f.title}</span>
        <span className="dim mono" style={{ fontSize: 10 }}>{f.id}</span>
      </div>
      <div className="dim" style={{ fontSize: 11.5 }}>{f.desc}</div>
      {f.evidence.length > 0 && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {f.evidence.map(e => (
            <span key={e} style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--txt-mute)', background: 'var(--elev-1)', padding: '1px 5px', borderRadius: 2, border: '1px solid var(--line)' }}>{e.slice(0, 12)}…</span>
          ))}
        </div>
      )}
    </div>
  );
}

function PocCard({ p }) {
  const tone = STATUS_TONE[p.status] || 'gray';
  return (
    <div style={{ padding: '10px 12px', border: '1px solid var(--line)', borderLeft: `3px solid var(--${tone === 'violet' ? 'violet' : tone === 'green' ? 'green' : tone === 'red' ? 'red' : 'line-strong'})`, borderRadius: 'var(--r-2)', background: 'var(--bg-deep)', display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 3 }}>
            {p.edb !== 'N/A' && <span className="mono" style={{ fontSize: 10, color: 'var(--cyan)', background: 'var(--cyan-soft)', padding: '1px 6px', borderRadius: 2, border: '1px solid var(--cyan)' }}>{p.edb}</span>}
            <Pill tone={tone}>{p.status.replace(/_/g, ' ').toUpperCase()}</Pill>
            {p.gated && <Pill tone="yellow">GATED</Pill>}
          </div>
          <div className="strong" style={{ fontSize: 12, fontWeight: 600 }}>{p.title}</div>
          <div className="dim" style={{ fontSize: 11, marginTop: 3 }}>{p.applicability}</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '0 0 auto' }}>
          <button className={`btn sm ${p.gated ? '' : p.status === 'rejected' ? 'ghost' : 'primary'}`} disabled={p.status === 'rejected'} style={p.status === 'rejected' ? { opacity: 0.4 } : {}}>
            {p.gated ? '◆ REVIEW' : p.downloadable ? '↓ DOWNLOAD' : p.status === 'rejected' ? 'REJECTED' : 'VIEW'}
          </button>
          {p.evidence.length > 0 && <button className="btn ghost sm">EVIDENCE</button>}
        </div>
      </div>
    </div>
  );
}

function ArtifactRow({ a }) {
  const kindColor = { tool_output: 'var(--green)', model_review: 'var(--violet)', checkpoint: 'var(--cyan)', export: 'var(--blue)', caido_capture: 'var(--magenta)' };
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', borderBottom: '1px solid var(--line)', fontFamily: 'var(--mono)', fontSize: 11 }}>
      <span style={{ width: 10, height: 10, borderRadius: 2, background: kindColor[a.kind] || 'var(--txt-mute)', flex: '0 0 10px' }} />
      <span className="strong" style={{ flex: 1 }}>{a.title}</span>
      <span className="dim" style={{ width: 70 }}>{a.task}</span>
      <span style={{ color: 'var(--txt-mute)', width: 54, textAlign: 'right' }}>{a.size}</span>
      <button className="btn ghost sm" style={{ marginLeft: 4 }}>↓</button>
    </div>
  );
}

function InterestsMode() {
  const D = window.PD_DATA.interests;
  const [selSurface, setSelSurface] = useStateI(null);
  const [selFinding, setSelFinding] = useStateI(null);
  const [sub, setSub] = useStateI('surfaces');
  const [sfilt, setSfilt] = useStateI('all');

  const filteredSurfaces = useMemoI(() =>
    sfilt === 'all' ? D.surfaces : D.surfaces.filter(s => s.severity === sfilt),
    [sfilt, D.surfaces]
  );

  const sevCounts = useMemoI(() => {
    const c = {};
    D.surfaces.forEach(s => { c[s.severity] = (c[s.severity] || 0) + 1; });
    return c;
  }, [D.surfaces]);

  const stats = [
    { k: 'surfaces', v: D.surfaces.length },
    { k: 'findings', v: D.findings.length },
    { k: 'pocs', v: D.pocs.length },
    { k: 'artifacts', v: D.artifacts.length },
    { k: 'gated', v: D.pocs.filter(p => p.gated).length },
  ];

  return (
    <>
      <window.TopBar crumbs={['primordial', 'interests', sub]} stats={stats} />
      <div className="subtabs">
        {[
          ['surfaces', '◎ SURFACES', D.surfaces.length],
          ['findings', '! FINDINGS', D.findings.length],
          ['pocs',     '⌬ PoCs',    D.pocs.length],
          ['artifacts','⊞ ARTIFACTS', D.artifacts.length],
        ].map(([id, label, count]) => (
          <button key={id} className={`subtab ${sub === id ? 'active' : ''}`} onClick={() => setSub(id)}>
            {label} <span className="badge">{count}</span>
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <span className="dim mono" style={{ fontSize: 10.5, paddingRight: 8 }}>pirate.htb · active</span>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: 10, display: 'flex', flexDirection: 'column', gap: 10 }}>

        {sub === 'surfaces' && (
          <>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
              <span className="upper" style={{ color: 'var(--txt-mute)' }}>FILTER</span>
              {['all', 'high', 'med', 'low', 'info'].map(v => (
                <button key={v} className={`btn sm ${sfilt === v ? '' : 'ghost'}`}
                  style={sfilt === v && v !== 'all' ? { borderColor: `var(--${SEV_TONE[v] || 'cyan'})`, color: `var(--${SEV_TONE[v] || 'cyan'})` } : {}}
                  onClick={() => setSfilt(v)}>
                  {v.toUpperCase()} {v !== 'all' && <span className="dim mono">{sevCounts[v] || 0}</span>}
                </button>
              ))}
            </div>
            <Panel title="ATTACK SURFACES" sub={`${filteredSurfaces.length} surfaces · pirate.htb`} className="fill">
              <table className="t">
                <thead><tr><th>SEV</th><th>KIND</th><th>PORTS</th><th>STATUS</th><th>DESCRIPTION</th></tr></thead>
                <tbody>
                  {filteredSurfaces.map(s => (
                    <SurfaceRow key={s.id} s={s} sel={selSurface} onSel={setSelSurface} />
                  ))}
                </tbody>
              </table>
            </Panel>
          </>
        )}

        {sub === 'findings' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 10, flex: 1, minHeight: 0 }}>
            <Panel title="FINDINGS" sub={`${D.findings.length} total`} className="fill" bodyClass="tight">
              {D.findings.map(f => (
                <FindingRow key={f.id} f={f} sel={selFinding} onSel={setSelFinding} />
              ))}
            </Panel>
            <aside style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {D.findings.filter(f => f.severity === 'high' || f.severity === 'med').length > 0 && (
                <div style={{ padding: '8px 10px', background: 'var(--red-soft)', border: '1px solid var(--red)', borderRadius: 'var(--r-2)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                  <div className="upper" style={{ color: 'var(--red)', marginBottom: 4 }}>ACTION REQUIRED</div>
                  {D.findings.filter(f => f.status === 'unverified').map(f => (
                    <div key={f.id} className="row gap-6" style={{ marginBottom: 4 }}>
                      <Pill tone={SEV_TONE[f.severity] || 'gray'}>{f.severity.toUpperCase()}</Pill>
                      <span className="strong" style={{ fontSize: 11 }}>{f.title}</span>
                    </div>
                  ))}
                </div>
              )}
              <Panel title="SEVERITY BREAKDOWN">
                <div style={{ padding: 10, display: 'flex', flexDirection: 'column', gap: 8, fontFamily: 'var(--mono)', fontSize: 11 }}>
                  {['high','med','low','info'].map(sev => {
                    const cnt = D.findings.filter(f => f.severity === sev).length;
                    return (
                      <div key={sev} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <Pill tone={SEV_TONE[sev]}>{sev.toUpperCase()}</Pill>
                        <div className="meter" style={{ flex: 1 }}>
                          <div className="meter-fill" style={{ width: `${(cnt / D.findings.length) * 100}%`, background: `var(--${SEV_TONE[sev]})` }} />
                        </div>
                        <span className="strong" style={{ width: 16, textAlign: 'right' }}>{cnt}</span>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            </aside>
          </div>
        )}

        {sub === 'pocs' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 260px', gap: 10, flex: 1, minHeight: 0 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, overflow: 'auto' }}>
              {D.pocs.map(p => <PocCard key={p.id} p={p} />)}
            </div>
            <aside style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <Panel title="PoC STATUS">
                <div style={{ padding: 10, display: 'flex', flexDirection: 'column', gap: 6, fontFamily: 'var(--mono)', fontSize: 11 }}>
                  {[
                    ['ready_for_review', 'violet'],
                    ['rejected',         'red'],
                    ['generated',        'green'],
                  ].map(([s, tone]) => {
                    const cnt = D.pocs.filter(p => p.status === s).length;
                    return (
                      <div key={s} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Pill tone={tone}>{s.replace(/_/g,' ').toUpperCase()}</Pill>
                        <span className="strong">{cnt}</span>
                      </div>
                    );
                  })}
                  <div style={{ borderTop: '1px dashed var(--line)', paddingTop: 6, marginTop: 2 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span className="dim">gated on approval</span>
                      <span className="strong">{D.pocs.filter(p => p.gated).length}</span>
                    </div>
                  </div>
                </div>
              </Panel>
              <div style={{ padding: '8px 10px', background: 'var(--violet-soft)', border: '1px solid var(--violet)', borderRadius: 'var(--r-2)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                <div className="upper" style={{ color: 'var(--violet)', marginBottom: 4 }}>POLICY</div>
                <div className="dim">PoC exec requires operator approval and behavior verifier sign-off. Read-only review is permitted.</div>
              </div>
            </aside>
          </div>
        )}

        {sub === 'artifacts' && (
          <Panel title="AI ARTIFACTS &amp; TOOL OUTPUTS" sub={`${D.artifacts.length} items · pirate.htb`} className="fill" bodyClass="tight">
            <div style={{ display: 'flex', gap: 6, padding: '6px 10px', borderBottom: '1px solid var(--line)', flexWrap: 'wrap' }}>
              {[
                ['tool_output', 'var(--green)', 'Tool Output'],
                ['model_review', 'var(--violet)', 'AI Review'],
                ['checkpoint', 'var(--cyan)', 'Checkpoint'],
                ['export', 'var(--blue)', 'Export'],
                ['caido_capture', 'var(--magenta)', 'Caido'],
              ].map(([k, color, label]) => (
                <span key={k} style={{ display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'var(--mono)', fontSize: 10 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: color, display: 'inline-block' }} />
                  <span className="dim">{label}</span>
                </span>
              ))}
            </div>
            {D.artifacts.map(a => <ArtifactRow key={a.id} a={a} />)}
          </Panel>
        )}
      </div>
    </>
  );
}

window.InterestsMode = InterestsMode;
