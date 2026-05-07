/* global React, Panel, Pill, Dot */
const { useState: useStateM, useRef: useRefM, useEffect: useEffectM, useMemo: useMemoM } = React;

// kind -> short glyph for node icon
const KIND_GLYPH = {
  domain: 'D', host: 'H', svc: 'S', user: 'U', cred: 'K', finding: '!', tool: 'T',
};
const KIND_COLOR = {
  domain: 'var(--blue)', host: 'var(--cyan)', svc: 'var(--green)', user: 'var(--violet)',
  cred: 'var(--yellow)', finding: 'var(--red)', tool: 'var(--magenta)',
  self: 'var(--cyan)', relay: 'var(--violet)', target: 'var(--red)', sync: 'var(--blue)',
};

function Globe({ markers = [], onClick, w = 280, h = 160, traces = [], showLabels = true, big = false }) {
  const lonLat = (lon, lat) => [
    ((lon + 180) / 360) * w,
    ((90 - lat) / 180) * h,
  ];
  const markerById = {};
  markers.forEach(m => { markerById[m.id] = m; });
  const fontSize = big ? 9 : 6;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" style={{ display: 'block', borderRadius: 4 }}>
      <defs>
        <pattern id={`grid-${w}`} width="20" height="20" patternUnits="userSpaceOnUse">
          <path d="M 20 0 L 0 0 0 20" fill="none" stroke="var(--line)" strokeWidth="0.5" />
        </pattern>
      </defs>
      <rect width={w} height={h} fill="var(--bg-deep)" />
      <rect width={w} height={h} fill={`url(#grid-${w})`} />
      <g fill="var(--elev-2)" stroke="var(--line-strong)" strokeWidth="0.5">
        <path d="M 30 38 Q 40 30 60 36 Q 78 42 84 60 Q 80 78 60 80 Q 42 78 32 64 Z" transform={`scale(${w/280} ${h/160})`} />
        <path d="M 70 92 Q 82 90 86 110 Q 84 132 76 144 Q 68 138 70 118 Z" transform={`scale(${w/280} ${h/160})`} />
        <path d="M 132 40 Q 148 36 156 44 Q 158 56 148 60 Q 136 58 132 50 Z" transform={`scale(${w/280} ${h/160})`} />
        <path d="M 138 70 Q 156 68 164 86 Q 164 108 152 122 Q 140 116 138 96 Z" transform={`scale(${w/280} ${h/160})`} />
        <path d="M 160 38 Q 200 32 232 50 Q 242 64 226 76 Q 196 78 172 70 Q 162 60 160 50 Z" transform={`scale(${w/280} ${h/160})`} />
        <path d="M 218 110 Q 240 108 246 122 Q 240 134 222 132 Q 212 124 218 116 Z" transform={`scale(${w/280} ${h/160})`} />
      </g>
      <line x1="0" y1={h/2} x2={w} y2={h/2} stroke="var(--line-strong)" strokeWidth="0.4" strokeDasharray="2 3" />
      <line x1={w/2} y1="0" x2={w/2} y2={h} stroke="var(--line-strong)" strokeWidth="0.4" strokeDasharray="2 3" />

      {/* traces (great-circle approximated with quadratic bezier above midpoint) */}
      {traces.map((t, i) => {
        const a = markerById[t.from]; const b = markerById[t.to];
        if (!a || !b) return null;
        const [ax, ay] = lonLat(a.lon, a.lat);
        const [bx, by] = lonLat(b.lon, b.lat);
        const mx = (ax + bx) / 2;
        const arc = -Math.min(40, Math.abs(bx - ax) * 0.35 + 6);
        const my = (ay + by) / 2 + arc;
        const stroke =
          t.kind === 'fail' ? 'var(--red)' :
          t.kind === 'warn' ? 'var(--yellow)' :
          'var(--green)';
        return (
          <g key={i}>
            <path d={`M ${ax} ${ay} Q ${mx} ${my} ${bx} ${by}`}
                  fill="none" stroke={stroke} strokeWidth={big ? 1.4 : 0.8}
                  strokeOpacity={t.kind === 'fail' ? 0.95 : 0.8}
                  strokeDasharray="3 3" className="trail">
              <animate attributeName="stroke-dashoffset" from="0" to="-12" dur="1s" repeatCount="indefinite" />
            </path>
            {big && t.label && (
              <text x={mx} y={my - 3} textAnchor="middle" fontSize="7"
                    fontFamily="var(--mono)" fill={stroke}>{t.label}</text>
            )}
          </g>
        );
      })}

      {/* markers */}
      {markers.map((m, i) => {
        const [x, y] = lonLat(m.lon, m.lat);
        const c = KIND_COLOR[m.kind] || 'var(--cyan)';
        return (
          <g key={i} onClick={() => onClick?.(m)} style={{ cursor: 'pointer' }}>
            <circle cx={x} cy={y} r={big ? 9 : 6} fill={c} fillOpacity="0.16" />
            <circle cx={x} cy={y} r={big ? 4 : 2.5} fill={c}>
              <animate attributeName="r" values={big ? '4;5.5;4' : '2.5;3.5;2.5'} dur="2s" repeatCount="indefinite" />
            </circle>
            {showLabels && (
              <text x={x + (big ? 10 : 7)} y={y + 3} fontSize={fontSize}
                    fill="var(--txt-strong)" fontFamily="var(--mono)">{m.label}</text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

/* =========================================================
   GRAPH SUB-MODE — Maltego-style asset graph (existing)
   ========================================================= */
function GraphSub() {
  const D = window.PD_DATA;
  const stageRef = useRefM(null);
  const [pan, setPan] = useStateM({ x: 0, y: 0 });
  const [zoom, setZoom] = useStateM(1);
  const [sel, setSel] = useStateM('finding_1');
  const [nodePositions, setNodePositions] = useStateM(() => {
    const o = {};
    D.graph.nodes.forEach(n => { o[n.id] = { x: n.x, y: n.y }; });
    return o;
  });
  const [filter, setFilter] = useStateM({ host: true, domain: true, svc: true, user: true, cred: true, finding: true, tool: true });

  const filteredNodes = D.graph.nodes.filter(n => filter[n.kind]);
  const filteredEdges = D.graph.edges.filter(e =>
    filteredNodes.find(n => n.id === e.a) && filteredNodes.find(n => n.id === e.b)
  );

  const onStageDown = (e) => {
    if (e.target.closest('.node-card')) return;
    const start = { x: e.clientX, y: e.clientY, ...pan };
    const mv = (ev) => setPan({ x: start.x + ev.clientX - start.x, y: start.y + ev.clientY - start.y });
    const up = () => { window.removeEventListener('mousemove', mv); window.removeEventListener('mouseup', up); };
    window.addEventListener('mousemove', mv); window.addEventListener('mouseup', up);
  };

  const startNodeDrag = (e, n) => {
    e.stopPropagation();
    const start = { x: e.clientX, y: e.clientY, nx: nodePositions[n.id].x, ny: nodePositions[n.id].y };
    setSel(n.id);
    const mv = (ev) => {
      setNodePositions(p => ({ ...p, [n.id]: { x: start.nx + (ev.clientX - start.x) / zoom, y: start.ny + (ev.clientY - start.y) / zoom } }));
    };
    const up = () => { window.removeEventListener('mousemove', mv); window.removeEventListener('mouseup', up); };
    window.addEventListener('mousemove', mv); window.addEventListener('mouseup', up);
  };

  const selected = D.graph.nodes.find(n => n.id === sel);
  const pivotPath = useMemoM(() => {
    if (!selected) return null;
    const order = ['dom_pirate', 'host_main', 'svc_8443', 'cred_t1', 'finding_1'];
    if (selected.id === 'finding_2') return ['dom_pirate', 'host_dc', 'svc_88', 'user_jdoe', 'finding_2'];
    return order;
  }, [selected]);

  const markers = D.graph.nodes.filter(n => n.geo).map(n => ({ ...n.geo, kind: n.kind, label: n.label, id: n.id }));
  const edgeStyle = (e) => {
    if (e.kind === 'finding') return { stroke: 'var(--red)', dash: '4 3', label: 'var(--red)' };
    if (e.label === 'open') return { stroke: 'var(--green)', dash: '0', label: 'var(--green)' };
    if (e.label === 'enumerated') return { stroke: 'var(--violet)', dash: '2 2', label: 'var(--violet)' };
    return { stroke: 'var(--line-strong)', dash: '0', label: 'var(--txt-dim)' };
  };

  return (
    <div style={{ flex: 1, minHeight: 0, display: 'flex' }}>
      <div className="map-stage fill" ref={stageRef} onMouseDown={onStageDown} style={{ position: 'relative' }}>
        <div style={{
          position: 'absolute', inset: 0,
          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
          transformOrigin: '0 0',
        }}>
          <svg className="map-svg" style={{ width: 1400, height: 700, overflow: 'visible' }}>
            <defs>
              <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" fill="var(--line-strong)" />
              </marker>
              <marker id="arrow-red" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" fill="var(--red)" />
              </marker>
            </defs>
            {filteredEdges.map((e, i) => {
              const a = nodePositions[e.a]; const b = nodePositions[e.b];
              if (!a || !b) return null;
              const ax = a.x + 65, ay = a.y + 14;
              const bx = b.x + 65, by = b.y + 14;
              const mx = (ax + bx) / 2, my = (ay + by) / 2;
              const onPath = pivotPath && pivotPath.includes(e.a) && pivotPath.includes(e.b)
                && Math.abs(pivotPath.indexOf(e.a) - pivotPath.indexOf(e.b)) === 1;
              const st = edgeStyle(e);
              return (
                <g key={i}>
                  <path
                    d={`M ${ax} ${ay} C ${ax} ${(ay+by)/2}, ${bx} ${(ay+by)/2}, ${bx} ${by}`}
                    fill="none"
                    stroke={onPath ? 'var(--cyan)' : st.stroke}
                    strokeWidth={onPath ? 2 : 1}
                    strokeDasharray={onPath ? '6 4' : st.dash === '0' ? '4 6' : st.dash}
                    markerEnd={st.stroke === 'var(--red)' ? 'url(#arrow-red)' : 'url(#arrow)'}
                    opacity={onPath ? 1 : 0.3}
                  >
                    <animate attributeName="stroke-dashoffset" from="0" to="-20"
                      dur={onPath ? '0.9s' : '3.5s'} repeatCount="indefinite" />
                  </path>
                  <text x={mx} y={my - 3} textAnchor="middle" fontSize="9" fontFamily="var(--mono)" fill={onPath ? 'var(--cyan)' : st.label}>{e.label}</text>
                </g>
              );
            })}
          </svg>
          {filteredNodes.map(n => {
            const p = nodePositions[n.id];
            return (
              <div
                key={n.id}
                className={`node-card kind-${n.kind} ${sel === n.id ? 'sel' : ''}`}
                style={{ left: p.x, top: p.y }}
                onMouseDown={(e) => startNodeDrag(e, n)}
                onClick={(e) => { e.stopPropagation(); setSel(n.id); }}
              >
                <div className="node-head">
                  <span className="node-icon">{KIND_GLYPH[n.kind]}</span>
                  <span className="node-title">{n.label}</span>
                </div>
                <div className="node-sub">{n.sub}</div>
              </div>
            );
          })}
        </div>

        <div className="map-toolbar">
          <button className="btn ghost sm" onClick={() => setZoom(z => Math.min(2.5, z * 1.2))}>＋</button>
          <button className="btn ghost sm" onClick={() => setZoom(z => Math.max(0.4, z / 1.2))}>−</button>
          <button className="btn ghost sm" onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}>FIT</button>
          <span style={{ width: 1, background: 'var(--line)' }}></span>
          {Object.keys(filter).map(k => (
            <button
              key={k}
              className={`btn ${filter[k] ? '' : 'ghost'} sm`}
              style={{ borderColor: filter[k] ? KIND_COLOR[k] : 'var(--line)', color: filter[k] ? KIND_COLOR[k] : 'var(--txt-mute)' }}
              onClick={() => setFilter(f => ({ ...f, [k]: !f[k] }))}
            >
              {k}
            </button>
          ))}
          <span style={{ width: 1, background: 'var(--line)' }}></span>
          <button className="btn primary sm">+ NODE</button>
          <button className="btn ghost sm">+ TRACE</button>
          <button className="btn ghost sm">EXPORT</button>
        </div>

        <div className="map-legend">
          <div className="upper" style={{ color: 'var(--txt-mute)' }}>LEGEND</div>
          <div className="legend-row"><span className="dot cyan"></span><span className="dim">host</span></div>
          <div className="legend-row"><span className="dot" style={{ background: 'var(--blue)' }}></span><span className="dim">domain</span></div>
          <div className="legend-row"><span className="dot" style={{ background: 'var(--green)' }}></span><span className="dim">service</span></div>
          <div className="legend-row"><span className="dot" style={{ background: 'var(--violet)' }}></span><span className="dim">user</span></div>
          <div className="legend-row"><span className="dot yellow"></span><span className="dim">credential</span></div>
          <div className="legend-row"><span className="dot red"></span><span className="dim">finding</span></div>
        </div>

      </div>

      <aside className="inspector">
        <div className="tabs">
          <button className="tab active">INSPECT</button>
          <button className="tab">PIVOT</button>
          <button className="tab">EVIDENCE</button>
        </div>
        {selected && (
          <div className="panel-body" style={{ padding: 12, gap: 12, display: 'flex', flexDirection: 'column' }}>
            <div className="row gap-8" style={{ alignItems: 'center' }}>
              <span className="node-icon" style={{ width: 22, height: 22, fontSize: 12, background: KIND_COLOR[selected.kind] }}>{KIND_GLYPH[selected.kind]}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="strong" style={{ fontWeight: 600, fontSize: 14, fontFamily: 'var(--mono)' }}>{selected.label}</div>
                <div className="dim mono" style={{ fontSize: 10.5 }}>{selected.kind} · {selected.id}</div>
              </div>
            </div>

            <div className="kv">
              <span className="k">subtitle</span><span className="v">{selected.sub}</span>
              <span className="k">first seen</span><span className="v">2026-05-07 13:54:11</span>
              <span className="k">last evidence</span><span className="v">ev_2241 (caido replay)</span>
              <span className="k">tasks touched</span><span className="v">t_8c4c, t_8c4e</span>
              {selected.geo && (
                <>
                  <span className="k">geo</span><span className="v">{selected.geo.city}</span>
                  <span className="k">lat / lon</span><span className="v">{selected.geo.lat.toFixed(4)} / {selected.geo.lon.toFixed(4)}</span>
                </>
              )}
            </div>

            <div>
              <div className="upper" style={{ marginBottom: 6 }}>pivot trace</div>
              <div className="col gap-4">
                {pivotPath?.map((id, i) => {
                  const n = D.graph.nodes.find(x => x.id === id);
                  if (!n) return null;
                  return (
                    <div key={id} className="row gap-6" style={{ alignItems: 'center' }}>
                      <span className="dim mono" style={{ fontSize: 10, width: 14 }}>{i + 1}.</span>
                      <span className="node-icon" style={{ width: 14, height: 14, fontSize: 9, background: KIND_COLOR[n.kind] }}>{KIND_GLYPH[n.kind]}</span>
                      <span className="mono" style={{ fontSize: 11.5, color: id === sel ? 'var(--cyan)' : 'var(--txt-strong)' }}>{n.label}</span>
                      <span className="dim mono" style={{ fontSize: 10, marginLeft: 'auto' }}>{n.sub}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="upper" style={{ marginBottom: 6 }}>related findings</div>
              <div className="col gap-4">
                {[
                  { sev: 'high', t: 'Tomcat default manager exposed', id: 'fnd_001' },
                  { sev: 'med',  t: 'AS-REP roastable user discovered', id: 'fnd_002' },
                ].map(f => (
                  <div key={f.id} className="row gap-6" style={{ padding: '6px 8px', border: '1px solid var(--line)', borderRadius: 4, background: 'var(--bg-deep)', alignItems: 'center' }}>
                    <Pill tone={f.sev === 'high' ? 'red' : 'yellow'}>{f.sev.toUpperCase()}</Pill>
                    <span className="strong" style={{ flex: 1, fontSize: 11.5 }}>{f.t}</span>
                    <span className="dim mono" style={{ fontSize: 10 }}>{f.id}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="row gap-6">
              <button className="btn primary sm">RUN PROBE</button>
              <button className="btn sm">ADD INTEREST</button>
              <button className="btn ghost sm" style={{ marginLeft: 'auto' }}>EXPAND ↗</button>
            </div>
          </div>
        )}
      </aside>
    </div>
  );
}

/* =========================================================
   TRACES SUB-MODE — AI/event tree, pass/fail per task kind
   ========================================================= */
function TraceRow({ row, depth = 0, isLast = false }) {
  const [open, setOpen] = useStateM(true);
  const hasChildren = row.children && row.children.length > 0;
  const sym = {
    pass: '✓', fail: '✗', partial: '~', run: '▶', queued: '·', gated: '◆',
  }[row.status] || '·';
  return (
    <>
      <div className={`trace-row ${row.status} ${isLast ? 'last' : ''}`}>
        {depth > 0 && <span className="branch"></span>}
        <span className="marker">{sym}</span>
        <span className="kind" onClick={() => hasChildren && setOpen(o => !o)} style={{ cursor: hasChildren ? 'pointer' : 'default' }}>
          {hasChildren ? (open ? '▾ ' : '▸ ') : '  '}{row.kind}
        </span>
        <span className="summary">{row.summary}</span>
        <span className="meta">
          {row.task && <span style={{ color: 'var(--txt-mute)' }}>{row.task} · </span>}
          {row.route && <span style={{ color: 'var(--violet)' }}>{row.route}</span>}
          {row.time && row.time !== '—' && <span style={{ color: 'var(--txt-mute)' }}> · {row.time}</span>}
        </span>
      </div>
      {hasChildren && open && (
        <div className="trace-children">
          {row.children.map((c, i) => (
            <TraceRow key={c.id} row={c} depth={depth + 1} isLast={i === row.children.length - 1} />
          ))}
        </div>
      )}
    </>
  );
}

function TracesSub() {
  const D = window.PD_DATA;
  const [filter, setFilter] = useStateM({ pass: true, fail: true, partial: true, run: true, queued: true, gated: true });
  const counts = useMemoM(() => {
    const c = { pass: 0, fail: 0, partial: 0, run: 0, queued: 0, gated: 0 };
    const walk = (n) => { c[n.status] = (c[n.status] || 0) + 1; (n.children || []).forEach(walk); };
    D.traces.forEach(walk);
    return c;
  }, [D.traces]);

  const tonesFor = { pass: 'green', fail: 'red', partial: 'yellow', run: 'cyan', queued: 'mute', gated: 'violet' };

  return (
    <div style={{ flex: 1, minHeight: 0, display: 'flex' }}>
      <div className="fill" style={{ flex: 1, minWidth: 0, padding: 14, overflow: 'auto', background: 'var(--bg-deep)' }}>
        <div className="row gap-8" style={{ marginBottom: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div className="upper" style={{ color: 'var(--txt-mute)', marginRight: 4 }}>FILTER</div>
          {Object.keys(filter).map(k => (
            <button
              key={k}
              className={`btn sm ${filter[k] ? '' : 'ghost'}`}
              onClick={() => setFilter(f => ({ ...f, [k]: !f[k] }))}
            >
              <Dot tone={tonesFor[k]}/> {k} <span className="dim mono" style={{ marginLeft: 4 }}>{counts[k] || 0}</span>
            </button>
          ))}
          <div style={{ flex: 1 }}></div>
          <button className="btn ghost sm">EXPAND ALL</button>
          <button className="btn ghost sm">EXPORT JSONL</button>
        </div>

        <div className="panel live" style={{ background: 'var(--bg)' }}>
          <div className="panel-head">
            <span className="title">EVENT / AI TRACE TREE</span>
            <span className="dim mono" style={{ fontSize: 10.5 }}>orchestrator tick · 14:02:11 · live</span>
          </div>
          <div className="trace-tree">
            {D.traces.map((t, i) => (
              <TraceRow key={t.id} row={t} depth={0} isLast={i === D.traces.length - 1} />
            ))}
          </div>
        </div>

        <div className="row gap-8" style={{ marginTop: 12 }}>
          <Panel title="VERIFIER FINDINGS" style={{ flex: 1 }}>
            <div className="col gap-6" style={{ padding: 10, fontFamily: 'var(--mono)', fontSize: 11 }}>
              <div className="row gap-6"><Pill tone="yellow">LOOP</Pill><span className="strong">recon.kerberos_user_discovery</span><span className="dim" style={{ marginLeft: 'auto' }}>repeated 3× → cooled</span></div>
              <div className="row gap-6"><Pill tone="yellow">LOOP</Pill><span className="strong">recon.dns_enumeration</span><span className="dim" style={{ marginLeft: 'auto' }}>repeated 2× → backed off</span></div>
              <div className="row gap-6"><Pill tone="green">OK</Pill><span className="strong">workflow.tick.cadence</span><span className="dim" style={{ marginLeft: 'auto' }}>1.4s avg / 3.2s p95</span></div>
              <div className="row gap-6"><Pill tone="red">FAIL</Pill><span className="strong">searchsploit.research</span><span className="dim" style={{ marginLeft: 'auto' }}>missing evidence terms</span></div>
            </div>
          </Panel>
          <Panel title="ROUTING DECISIONS" style={{ flex: 1 }}>
            <div className="col gap-4" style={{ padding: 10, fontFamily: 'var(--mono)', fontSize: 11 }}>
              {[
                { task: 't_8c4c', from: 'planner', to: 'local_fast', model: 'gemma3:12b', why: 'high-cadence content discovery, prompt < 8k' },
                { task: 't_8c50', from: 'planner', to: 'local_code', model: 'qwen2.5-coder:14b', why: 'PoC source analysis, code reasoning' },
                { task: 't_8c51', from: 'planner', to: 'local_deep', model: 'llama3.1:70b', why: 'kerberos protocol nuance, escalated' },
                { task: 't_v01', from: 'verifier', to: 'local_compact', model: 'gemma3:4b', why: 'cheap behavior review' },
              ].map(r => (
                <div key={r.task} className="row gap-6" style={{ padding: '5px 0', borderBottom: '1px dashed var(--line)' }}>
                  <span className="dim" style={{ width: 56 }}>{r.task}</span>
                  <span style={{ color: 'var(--violet)' }}>{r.from}→{r.to}</span>
                  <span className="strong" style={{ marginLeft: 6 }}>{r.model}</span>
                  <span className="dim" style={{ marginLeft: 'auto', maxWidth: '50%', textAlign: 'right' }}>{r.why}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>

      {/* trace inspector */}
      <aside className="inspector">
        <div className="tabs">
          <button className="tab active">DETAIL</button>
          <button className="tab">EVIDENCE</button>
          <button className="tab">PROMPT</button>
        </div>
        <div className="panel-body" style={{ padding: 12, gap: 12, display: 'flex', flexDirection: 'column', fontSize: 11.5 }}>
          <div>
            <div className="upper" style={{ marginBottom: 4 }}>focus</div>
            <div className="strong mono" style={{ fontSize: 13 }}>web.content_discovery</div>
            <div className="dim mono" style={{ fontSize: 10.5 }}>t_8c4c · running · gemma3:12b · local_fast</div>
            <div className="loadbar" style={{ marginTop: 8 }}></div>
          </div>
          <div className="kv">
            <span className="k">target</span><span className="v">https://pirate.htb:8443</span>
            <span className="k">wordlist</span><span className="v">raft-medium.txt (4096)</span>
            <span className="k">progress</span><span className="v">312 / 4096 (7.6%)</span>
            <span className="k">started</span><span className="v">14:01:48</span>
            <span className="k">ttl budget</span><span className="v">10m / used 0m26s</span>
            <span className="k">parent</span><span className="v">workflow.tick (tr_root)</span>
            <span className="k">memory writes</span><span className="v">3 episodic · 0 semantic</span>
          </div>

          <div>
            <div className="upper" style={{ marginBottom: 6 }}>recent emissions</div>
            <div className="col gap-4 mono" style={{ fontSize: 10.5 }}>
              {[
                ['14:02:09', 'GET /admin/manager/html → 401'],
                ['14:02:08', 'GET /admin/users → 200 (1.2k)'],
                ['14:02:06', 'GET /admin → 302'],
                ['14:02:04', 'GET /api/v1/health → 200'],
                ['14:01:58', 'evidence ev_2241 attached'],
              ].map(([t, m], i) => (
                <div key={i} className="row gap-6">
                  <span className="dim" style={{ width: 56 }}>{t}</span>
                  <span className="strong" style={{ flex: 1 }}>{m}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="row gap-6">
            <button className="btn primary sm">PIN</button>
            <button className="btn sm">PAUSE</button>
            <button className="btn ghost sm">CANCEL</button>
          </div>
        </div>
      </aside>
    </div>
  );
}

/* =========================================================
   GLOBE 3D — interactive canvas globe, CP2077 style
   ========================================================= */
function Globe3D({ pins = [], traces = [], onClickPin, selectedId, framework = 'geop' }) {
  const canvasRef = useRefM(null);
  const containerRef = useRefM(null);
  const S = useRefM({ rotX: 0.25, rotY: -0.4, dragging: false, lastX: 0, lastY: 0, zoom: 1.0, frame: 0, mountTime: performance.now() });
  const selRef = useRefM(selectedId);
  const fwRef = useRefM(framework);
  const geoRef = useRefM({ loaded: false, worldRings: [], stateRings: [] });
  useEffectM(() => { selRef.current = selectedId; }, [selectedId]);
  useEffectM(() => { fwRef.current = framework; }, [framework]);

  // fetch world + US-states topojson once on mount
  useEffectM(() => {
    const topo = window.topojson;
    if (!topo) return;
    const toRings = (features) => {
      const rings = [];
      features.forEach(f => {
        const g = f.geometry;
        if (!g) return;
        const polys = g.type === 'Polygon' ? [g.coordinates] : g.type === 'MultiPolygon' ? g.coordinates : [];
        polys.forEach(poly => { if (poly[0]) rings.push(poly[0]); });
      });
      return rings;
    };
    Promise.all([
      fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json').then(r => r.json()),
      fetch('https://cdn.jsdelivr.net/npm/us-atlas@3/states-10m.json').then(r => r.json()),
    ]).then(([world, usData]) => {
      geoRef.current = {
        loaded: true,
        worldRings: toRings(topo.feature(world, world.objects.countries).features),
        stateRings: toRings(topo.feature(usData, usData.objects.states).features),
      };
    }).catch(() => {});
  }, []);

  const PIN_COL = { self:'#2aa198', relay:'#6c71c4', target:'#dc322f', tool:'#d33682', sync:'#268bd2', local:'#2aa198' };
  const ASN_COL = { 'AS24940':'#6c71c4','AS33915':'#dc322f','AS7922':'#2aa198','AS54113':'#268bd2','AS49544':'#d33682','local':'#859900' };

  useEffectM(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let raf;

    function proj(lat, lon, R) {
      const phi = (90 - lat) * Math.PI / 180;
      const th  = (lon + 180) * Math.PI / 180;
      let x = R * Math.sin(phi) * Math.cos(th);
      let y = R * Math.cos(phi);
      let z = R * Math.sin(phi) * Math.sin(th);
      const { rotX, rotY } = S.current;
      const cY = Math.cos(rotY), sY = Math.sin(rotY);
      [x, z] = [x*cY + z*sY, -x*sY + z*cY];
      const cX = Math.cos(rotX), sX = Math.sin(rotX);
      [y, z] = [y*cX - z*sX,  y*sX + z*cX];
      const fov = 700;
      const sc = fov / (fov + z + R * 0.05);
      return { sx: x*sc, sy: -y*sc, z, vis: z > -R*0.92, a: Math.max(0, (z+R)/(R*2)) };
    }

    function gcArc(la1,lo1,la2,lo2, n=56) {
      const d2r = Math.PI/180;
      const f1=la1*d2r, l1=lo1*d2r, f2=la2*d2r, l2=lo2*d2r;
      const d = Math.acos(Math.max(-1,Math.min(1, Math.sin(f1)*Math.sin(f2)+Math.cos(f1)*Math.cos(f2)*Math.cos(l2-l1))));
      if (d < 0.001) return [[la1,lo1]];
      return Array.from({length:n+1},(_,i)=>{
        const t=i/n, A=Math.sin((1-t)*d)/Math.sin(d), B=Math.sin(t*d)/Math.sin(d);
        const x=A*Math.cos(f1)*Math.cos(l1)+B*Math.cos(f2)*Math.cos(l2);
        const y=A*Math.cos(f1)*Math.sin(l1)+B*Math.cos(f2)*Math.sin(l2);
        const z=A*Math.sin(f1)+B*Math.sin(f2);
        return [Math.atan2(z,Math.sqrt(x*x+y*y))*180/Math.PI, Math.atan2(y,x)*180/Math.PI];
      });
    }

    function pathArc(pts, R, cx, cy) {
      ctx.beginPath(); let pen=false;
      pts.forEach(([la,lo])=>{
        const p=proj(la,lo,R);
        if(p.vis){pen?ctx.lineTo(cx+p.sx,cy+p.sy):ctx.moveTo(cx+p.sx,cy+p.sy);pen=true;}
        else pen=false;
      });
    }

    function drawRings(rings, R, cx, cy, fillStyle, strokeStyle, lw, dash) {
      rings.forEach(ring => {
        if (!ring || ring.length < 3) return;
        // sample visibility — skip entirely if back-facing
        const step = Math.max(1, Math.floor(ring.length / 16));
        let visCnt = 0, sampleN = 0;
        for (let i = 0; i < ring.length; i += step) {
          if (proj(ring[i][1], ring[i][0], R).vis) visCnt++;
          sampleN++;
        }
        if (visCnt === 0) return;
        const visFrac = visCnt / sampleN;

        // FILL — only when ring is mostly front-facing (avoids back-face bleed)
        if (fillStyle && visFrac >= 0.55) {
          ctx.beginPath();
          let pen = false;
          ring.forEach(([lon, lat]) => {
            const p = proj(lat, lon, R);
            // never close mid-ring — just lift pen at horizon
            if (p.vis) { pen ? ctx.lineTo(cx+p.sx, cy+p.sy) : ctx.moveTo(cx+p.sx, cy+p.sy); pen = true; }
            else pen = false;
          });
          ctx.fillStyle = fillStyle;
          ctx.fill();
        }

        // STROKE — draw visible arcs, lift pen at horizon, no closePath
        if (strokeStyle) {
          ctx.beginPath();
          let pen = false;
          ring.forEach(([lon, lat]) => {
            const p = proj(lat, lon, R);
            if (p.vis) { pen ? ctx.lineTo(cx+p.sx, cy+p.sy) : ctx.moveTo(cx+p.sx, cy+p.sy); pen = true; }
            else pen = false;
          });
          ctx.strokeStyle = strokeStyle; ctx.lineWidth = lw || 0.6;
          if (dash) ctx.setLineDash(dash);
          ctx.stroke(); ctx.setLineDash([]);
        }
      });
    }

    function draw() {
      const s = S.current;
      // auto-rotate for first 5 seconds only
      if (!s.dragging && (performance.now() - s.mountTime) < 5000) s.rotY += 0.0012;
      s.frame++;
      const t = s.frame;

      // resize canvas to container
      const cont = containerRef.current;
      if (cont && (canvas.width !== cont.clientWidth || canvas.height !== cont.clientHeight)) {
        canvas.width  = cont.clientWidth  || 800;
        canvas.height = cont.clientHeight || 520;
      }
      const W = canvas.width, H = canvas.height;
      const cx = W/2, cy = H/2;
      const R = Math.min(W,H) * 0.37 * s.zoom;
      const fw = fwRef.current;

      ctx.clearRect(0,0,W,H);

      // BG
      ctx.fillStyle='#000d12'; ctx.fillRect(0,0,W,H);

      // Outer atmosphere
      const atm = ctx.createRadialGradient(cx,cy,R*0.87,cx,cy,R*1.28);
      atm.addColorStop(0,'rgba(42,161,152,0)');
      atm.addColorStop(0.35,'rgba(42,161,152,0.06)');
      atm.addColorStop(0.7,'rgba(108,113,196,0.04)');
      atm.addColorStop(1,'transparent');
      ctx.fillStyle=atm; ctx.beginPath(); ctx.arc(cx,cy,R*1.28,0,Math.PI*2); ctx.fill();

      // Sphere clip
      ctx.save(); ctx.beginPath(); ctx.arc(cx,cy,R,0,Math.PI*2); ctx.clip();

      // Sphere fill gradient
      const sf=ctx.createRadialGradient(cx-R*0.22,cy-R*0.18,0,cx,cy,R*1.05);
      sf.addColorStop(0,'#003040'); sf.addColorStop(0.55,'#001828'); sf.addColorStop(1,'#000a12');
      ctx.fillStyle=sf; ctx.fillRect(cx-R,cy-R,R*2,R*2);

      // ── LANDMASSES ──
      if (geoRef.current.loaded) {
        drawRings(geoRef.current.worldRings, R, cx, cy, '#001e2c', 'rgba(42,161,152,0.2)', 0.55, null);
        drawRings(geoRef.current.stateRings, R, cx, cy, null, 'rgba(42,161,152,0.13)', 0.4, [2, 4]);
      }

      // ── GRID ──
      const gc = (bright) => bright?'rgba(42,161,152,0.22)':'rgba(42,161,152,0.07)';
      ctx.lineWidth=0.55;
      for(let lo=-165;lo<=180;lo+=15){
        ctx.beginPath(); let pen=false;
        for(let la=-87;la<=87;la+=4){
          const p=proj(la,lo,R);
          p.vis?(pen?ctx.lineTo(cx+p.sx,cy+p.sy):ctx.moveTo(cx+p.sx,cy+p.sy),pen=true):(pen=false);
        }
        ctx.strokeStyle=gc(lo===0||lo===180); ctx.stroke();
      }
      for(let la=-75;la<=75;la+=15){
        ctx.beginPath(); let pen=false;
        for(let lo=-180;lo<=180;lo+=4){
          const p=proj(la,lo,R);
          p.vis?(pen?ctx.lineTo(cx+p.sx,cy+p.sy):ctx.moveTo(cx+p.sx,cy+p.sy),pen=true):(pen=false);
        }
        ctx.strokeStyle=gc(la===0); ctx.stroke();
      }

      // ── GEO-ASN NETS framework ──
      if (fw==='asn') {
        const groups={};
        pins.forEach(p=>{ if(p.asn&&p.asn!=='local'){(groups[p.asn]=groups[p.asn]||[]).push(p);} });
        Object.entries(groups).forEach(([asn,gps])=>{
          const c = ASN_COL[asn]||'#859900';
          // ASN zone circle around each node
          gps.forEach(pin=>{
            const pd=proj(pin.lat,pin.lon,R);
            if(!pd.vis)return;
            const sx=cx+pd.sx, sy=cy+pd.sy;
            ctx.beginPath(); ctx.arc(sx,sy,18,0,Math.PI*2);
            ctx.strokeStyle=c+'44'; ctx.lineWidth=1; ctx.setLineDash([3,5]); ctx.stroke();
            ctx.setLineDash([]);
            // fill glow
            const zg=ctx.createRadialGradient(sx,sy,0,sx,sy,18);
            zg.addColorStop(0,c+'22'); zg.addColorStop(1,'transparent');
            ctx.fillStyle=zg; ctx.beginPath(); ctx.arc(sx,sy,18,0,Math.PI*2); ctx.fill();
          });
          // Mesh lines between same-ASN nodes
          for(let i=0;i<gps.length;i++) for(let j=i+1;j<gps.length;j++){
            const pts=gcArc(gps[i].lat,gps[i].lon,gps[j].lat,gps[j].lon,28);
            pathArc(pts,R,cx,cy);
            ctx.strokeStyle=c+'66'; ctx.lineWidth=1; ctx.setLineDash([4,5]);
            ctx.lineDashOffset=-(t*0.25);
            ctx.stroke(); ctx.setLineDash([]); ctx.lineDashOffset=0;
          }
        });
      }

      // ── TRACES ──
      traces.forEach((tr,ti)=>{
        const fp=pins.find(p=>p.id===tr.from), tp=pins.find(p=>p.id===tr.to);
        if(!fp||!tp)return;
        const pts=gcArc(fp.lat,fp.lon,tp.lat,tp.lon,64);
        const c=tr.kind==='fail'?'#dc322f':tr.kind==='warn'?'#b58900':'#859900';
        // ghost base
        pathArc(pts,R,cx,cy); ctx.strokeStyle=c+'33'; ctx.lineWidth=1; ctx.setLineDash([]); ctx.stroke();
        // animated dash
        pathArc(pts,R,cx,cy); ctx.strokeStyle=c+'cc'; ctx.lineWidth=1.4;
        ctx.setLineDash([5,9]); ctx.lineDashOffset=-(t*0.5+ti*14); ctx.stroke();
        ctx.setLineDash([]); ctx.lineDashOffset=0;
        // moving energy pulse dot
        const pIdx = Math.floor((t*0.6+ti*20) % pts.length);
        const pp=proj(pts[pIdx][0],pts[pIdx][1],R);
        if(pp.vis){
          ctx.beginPath(); ctx.arc(cx+pp.sx,cy+pp.sy,2.5,0,Math.PI*2);
          ctx.fillStyle=c; ctx.shadowColor=c; ctx.shadowBlur=8; ctx.fill(); ctx.shadowBlur=0;
        }
        // label at midpoint
        if(tr.label){
          const mid=pts[Math.floor(pts.length/2)];
          const mp=proj(mid[0],mid[1],R);
          if(mp.vis){
            ctx.font='9px JetBrains Mono,monospace';
            ctx.shadowColor='rgba(0,0,0,0.95)'; ctx.shadowBlur=5;
            ctx.fillStyle=c+'ee'; ctx.fillText(tr.label,cx+mp.sx+4,cy+mp.sy-2);
            ctx.shadowBlur=0;
          }
        }
      });

      // ── PINS ──
      pins.forEach(pin=>{
        const p=proj(pin.lat,pin.lon,R);
        if(!p.vis)return;
        const sx=cx+p.sx, sy=cy+p.sy;
        const c=PIN_COL[pin.kind]||'#2aa198';
        const isSel=selRef.current===pin.id;
        const pulse=0.5+0.5*Math.sin(t*0.05+pin.lat*0.12);
        const r=isSel?7:4.5;

        // status ring pulse
        if(pin.status==='live'||pin.status==='probing'){
          ctx.beginPath(); ctx.arc(sx,sy,r+5+pulse*5,0,Math.PI*2);
          ctx.strokeStyle=c+(isSel?'55':'33'); ctx.lineWidth=1; ctx.stroke();
        }
        // selection targeting ring
        if(isSel){
          ctx.beginPath(); ctx.arc(sx,sy,r+10,0,Math.PI*2);
          ctx.strokeStyle=c+'88'; ctx.lineWidth=1; ctx.setLineDash([4,4]); ctx.stroke();
          ctx.setLineDash([]);
          // crosshair ticks
          [[0,-1],[0,1],[-1,0],[1,0]].forEach(([dx,dy])=>{
            ctx.beginPath(); ctx.moveTo(sx+dx*(r+13),sy+dy*(r+13)); ctx.lineTo(sx+dx*(r+17),sy+dy*(r+17));
            ctx.strokeStyle=c+'bb'; ctx.lineWidth=1.2; ctx.stroke();
          });
        }
        // core dot
        ctx.beginPath(); ctx.arc(sx,sy,r,0,Math.PI*2);
        ctx.fillStyle=c; ctx.shadowColor=c; ctx.shadowBlur=isSel?16:8; ctx.fill(); ctx.shadowBlur=0;
        // inner highlight
        ctx.beginPath(); ctx.arc(sx-r*0.25,sy-r*0.25,r*0.4,0,Math.PI*2);
        ctx.fillStyle='rgba(255,255,255,0.3)'; ctx.fill();
        // label — opaque background pill for readability over terrain/overlaps
        const lx = sx+r+5, fontSize = isSel ? 11 : 9.5;
        ctx.font = `bold ${fontSize}px JetBrains Mono,monospace`;
        const lw2 = ctx.measureText(pin.label).width;
        // background rect
        ctx.fillStyle = isSel ? 'rgba(0,8,14,0.88)' : 'rgba(0,8,14,0.72)';
        ctx.fillRect(lx-2, sy-fontSize+1, lw2+6, fontSize+4);
        // text
        ctx.fillStyle = isSel ? '#fdf6e3' : c;
        ctx.fillText(pin.label, lx, sy+3);
        if(fw==='asn'&&pin.asn){
          ctx.font='8px JetBrains Mono,monospace';
          const aw = ctx.measureText(pin.asn).width;
          ctx.fillStyle='rgba(0,8,14,0.72)';
          ctx.fillRect(lx-2, sy+5, aw+6, 12);
          ctx.fillStyle=(ASN_COL[pin.asn]||'#859900')+'ee';
          ctx.fillText(pin.asn,lx,sy+14);
        }
      });

      ctx.restore(); // end sphere clip

      // Globe edge ring
      ctx.beginPath(); ctx.arc(cx,cy,R,0,Math.PI*2);
      ctx.strokeStyle='rgba(42,161,152,0.28)'; ctx.lineWidth=1.5; ctx.stroke();
      ctx.beginPath(); ctx.arc(cx,cy,R+4,0,Math.PI*2);
      ctx.strokeStyle='rgba(42,161,152,0.07)'; ctx.lineWidth=1; ctx.stroke();

      // Scan sweep (inside clip, re-apply)
      ctx.save(); ctx.beginPath(); ctx.arc(cx,cy,R,0,Math.PI*2); ctx.clip();
      const scanLa = Math.sin(t*0.009)*65;
      const sp=proj(scanLa,0,R);
      if(sp.vis){
        const syy=cy+sp.sy;
        const sg=ctx.createLinearGradient(cx-R,syy,cx+R,syy);
        sg.addColorStop(0,'rgba(42,161,152,0)'); sg.addColorStop(0.5,'rgba(42,161,152,0.07)'); sg.addColorStop(1,'rgba(42,161,152,0)');
        ctx.fillStyle=sg; ctx.fillRect(cx-R,syy-1.5,R*2,3);
      }
      ctx.restore();

      // ── HUD OVERLAY ──
      const bSz=18, bMg=14;
      ctx.strokeStyle='rgba(42,161,152,0.6)'; ctx.lineWidth=1.5; ctx.setLineDash([]);
      [[bMg,bMg,1,1],[W-bMg,bMg,-1,1],[bMg,H-bMg,1,-1],[W-bMg,H-bMg,-1,-1]].forEach(([x,y,dx,dy])=>{
        ctx.beginPath(); ctx.moveTo(x+dx*bSz,y); ctx.lineTo(x,y); ctx.lineTo(x,y+dy*bSz); ctx.stroke();
      });
      ctx.shadowColor='rgba(0,0,0,0.9)'; ctx.shadowBlur=4;
      ctx.font='bold 10px JetBrains Mono,monospace';
      ctx.fillStyle='rgba(42,161,152,0.85)';
      ctx.fillText('PRIMORDIAL//GEO-FRAMEWORK',bMg+bSz+7,bMg+13);
      ctx.font='9px JetBrains Mono,monospace';
      ctx.fillStyle='rgba(108,113,196,0.8)';
      ctx.fillText(fw==='asn'?'LAYER: GEO-ASN NETS':'LAYER: GEOP SURFACE',bMg+bSz+7,bMg+25);
      ctx.font='9px JetBrains Mono,monospace';
      ctx.fillStyle='rgba(42,161,152,0.75)';
      const fStr=`FRAME ${t.toString().padStart(5,'0')}`;
      ctx.fillText(fStr, W-bMg-bSz-7-ctx.measureText(fStr).width, bMg+13);
      ctx.fillStyle='rgba(42,161,152,0.6)';
      const pStr=`${pins.length}P · ${traces.length}T · ${(s.zoom*100).toFixed(0)}%`;
      ctx.fillText(pStr, W-bMg-bSz-7-ctx.measureText(pStr).width, bMg+25);
      ctx.shadowBlur=0;

      // Crosshair reference lines
      ctx.strokeStyle='rgba(42,161,152,0.1)'; ctx.lineWidth=0.5; ctx.setLineDash([3,8]);
      ctx.beginPath(); ctx.moveTo(cx,cy-R*1.15); ctx.lineTo(cx,cy+R*1.15); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(cx-R*1.15,cy); ctx.lineTo(cx+R*1.15,cy); ctx.stroke();
      ctx.setLineDash([]);

      raf = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(raf);
  }, [pins, traces]);

  const onDown = (e) => { const s=S.current; s.dragging=true; s.lastX=e.clientX; s.lastY=e.clientY; };
  const onMove = (e) => {
    const s=S.current; if(!s.dragging)return;
    s.rotY += (e.clientX-s.lastX)*0.005;
    s.rotX  = Math.max(-1.4,Math.min(1.4, s.rotX+(e.clientY-s.lastY)*0.005));
    s.lastX=e.clientX; s.lastY=e.clientY;
  };
  const onUp = () => { S.current.dragging=false; };
  const onWheel = (e) => { e.preventDefault(); S.current.zoom=Math.max(0.5,Math.min(2.8,S.current.zoom-e.deltaY*0.001)); };
  const onClick = (e) => {
    if(!onClickPin)return;
    const canvas=canvasRef.current, rect=canvas.getBoundingClientRect();
    const mx=e.clientX-rect.left, my=e.clientY-rect.top;
    const cx=canvas.width/2, cy=canvas.height/2, R=Math.min(canvas.width,canvas.height)*0.37*S.current.zoom;
    const {rotX,rotY}=S.current;
    let best=null, bestD=16;
    pins.forEach(pin=>{
      const phi=(90-pin.lat)*Math.PI/180, th=(pin.lon+180)*Math.PI/180;
      let x=R*Math.sin(phi)*Math.cos(th), y=R*Math.cos(phi), z=R*Math.sin(phi)*Math.sin(th);
      const cY=Math.cos(rotY),sY=Math.sin(rotY); [x,z]=[x*cY+z*sY,-x*sY+z*cY];
      const cX=Math.cos(rotX),sX=Math.sin(rotX); [y,z]=[y*cX-z*sX,y*sX+z*cX];
      if(z<=-R*0.92)return;
      const sc=700/(700+z+R*0.05);
      const d=Math.hypot(mx-(cx+x*sc), my-(cy-y*sc));
      if(d<bestD){bestD=d;best=pin;}
    });
    if(best)onClickPin(best);
  };

  return (
    <div ref={containerRef} style={{ flex:1, minHeight:0, minWidth:0, position:'relative', background:'#000d12', overflow:'hidden' }}>
      <canvas
        ref={canvasRef}
        style={{ display:'block', cursor: S.current.dragging?'grabbing':'grab' }}
        onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}
        onClick={onClick} onWheel={onWheel}
      />
    </div>
  );
}

/* =========================================================
   GEO SUB-MODE — 3D interactive globe + ASN/GeoIP detail
   ========================================================= */
function GeoSub() {
  const D = window.PD_DATA;
  const G = D.geo;
  const [sel, setSel] = useStateM('g_htb');
  const [fw,  setFw]  = useStateM('geop');
  const [inspTab, setInspTab] = useStateM('pin');
  const selPin = G.pins.find(p => p.id === sel) || G.pins[0];

  return (
    <div style={{ flex:1, minHeight:0, display:'flex', flexDirection:'column' }}>

      {/* framework selector bar */}
      <div style={{ padding:'5px 10px', borderBottom:'1px solid var(--line)', background:'var(--bg-deep)', display:'flex', gap:8, alignItems:'center', flex:'0 0 auto' }}>
        <span className="upper" style={{ color:'var(--txt-mute)', fontSize:9.5 }}>FRAMEWORK</span>
        {[['geop','◎ GEOP SURFACE'],['asn','⌬ GEO-ASN NETS']].map(([id,label])=>(
          <button key={id} className={`btn sm ${fw===id?'primary':'ghost'}`} onClick={()=>setFw(id)}>{label}</button>
        ))}
        <div style={{flex:1}}/>
        <button className="btn ghost sm">FOCUS TARGET</button>
      </div>

      <div style={{ flex:1, minHeight:0, display:'flex' }}>

        {/* 3D globe */}
        <Globe3D
          pins={G.pins}
          traces={G.traces}
          framework={fw}
          selectedId={sel}
          onClickPin={pin => setSel(pin.id)}
        />

        {/* inspector */}
        <aside className="inspector">
          <div className="tabs">
            {[['pin','PIN'],['route','ROUTE'],['asn','ASN']].map(([id,label])=>(
              <button key={id} className={`tab ${inspTab===id?'active':''}`} onClick={()=>setInspTab(id)}>{label}</button>
            ))}
          </div>
          <div className="panel-body" style={{ padding:12, gap:12, display:'flex', flexDirection:'column', fontSize:11.5, overflow:'auto' }}>

            {inspTab==='pin' && (
              <>
                <div className="row gap-8" style={{ alignItems:'center' }}>
                  <span className="node-icon" style={{ width:24, height:24, fontSize:11, background:KIND_COLOR[selPin.kind]||'var(--cyan)' }}>
                    {selPin.kind==='self'?'@':selPin.kind==='relay'?'R':selPin.kind==='target'?'!':selPin.kind==='tool'?'T':'S'}
                  </span>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div className="strong mono" style={{ fontSize:13 }}>{selPin.label}</div>
                    <div className="dim mono" style={{ fontSize:10.5 }}>{selPin.kind} · {selPin.id}</div>
                  </div>
                  <Pill tone={selPin.status==='live'?'green':selPin.status==='gated'?'violet':selPin.status==='probing'?'cyan':'gray'}>{selPin.status.toUpperCase()}</Pill>
                </div>
                <div className="kv">
                  <span className="k">city</span><span className="v">{selPin.city}</span>
                  <span className="k">country</span><span className="v">{selPin.country}</span>
                  <span className="k">lat / lon</span><span className="v">{selPin.lat.toFixed(4)} / {selPin.lon.toFixed(4)}</span>
                  <span className="k">asn</span><span className="v" style={{ color:'var(--cyan)' }}>{selPin.asn} · {selPin.org}</span>
                  <span className="k">status</span><span className="v">{selPin.status}</span>
                </div>
                <div className="row gap-6">
                  <button className="btn primary sm">OPEN IN GRAPH</button>
                  <button className="btn sm">PROBE</button>
                  <button className="btn ghost sm">WHOIS ↗</button>
                </div>
              </>
            )}

            {inspTab==='route' && (
              <>
                <div className="upper" style={{ marginBottom:4 }}>traceroute to {selPin.label}</div>
                {[
                  {hop:1,host:'10.10.0.1',ms:0.3,asn:'local',loc:'localhost'},
                  {hop:2,host:'198.51.100.1',ms:14,asn:'AS7922',loc:'San Francisco'},
                  {hop:3,host:'203.0.113.5',ms:38,asn:'AS24940',loc:'Frankfurt'},
                  {hop:4,host:'10.129.47.1',ms:41,asn:'AS33915',loc:'HTB Lab'},
                  {hop:5,host:'10.129.47.117',ms:41,asn:'AS33915',loc:'HTB Lab'},
                ].map(h=>(
                  <div key={h.hop} className="row gap-6 mono" style={{ fontSize:11, padding:'4px 0', borderBottom:'1px dashed var(--line)' }}>
                    <span className="dim" style={{width:16}}>{h.hop}.</span>
                    <span className="strong" style={{flex:1}}>{h.host}</span>
                    <span style={{color:'var(--cyan)'}}>{h.asn}</span>
                    <span className="dim" style={{width:44,textAlign:'right'}}>{h.ms}ms</span>
                  </div>
                ))}
              </>
            )}

            {inspTab==='asn' && (
              <>
                <div className="upper" style={{ marginBottom:6 }}>ASN REFERENCES</div>
                {G.asns.map(a=>(
                  <div key={a.num} style={{ padding:'7px 8px', marginBottom:4, border:'1px solid var(--line)', borderLeft:`3px solid ${ASN_COL[a.num]||'var(--line-strong)'}`, borderRadius:'var(--r-2)', background:'var(--bg-deep)', fontFamily:'var(--mono)', fontSize:11 }}>
                    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:3 }}>
                      <span style={{ color:ASN_COL[a.num]||'var(--cyan)', fontWeight:700 }}>{a.num}</span>
                      <span className="dim" style={{fontSize:9}}>×{a.refs} refs</span>
                    </div>
                    <div className="strong">{a.org}</div>
                    <div className="dim" style={{fontSize:10}}>{a.country} · {a.role}</div>
                  </div>
                ))}
              </>
            )}

          </div>
        </aside>
      </div>

      {/* ASN ref strip at bottom */}
      <div style={{ flex:'0 0 auto', padding:'5px 10px', borderTop:'1px solid var(--line)', background:'var(--bg-deep)', display:'flex', gap:8, flexWrap:'wrap', alignItems:'center' }}>
        <span className="upper" style={{ color:'var(--txt-mute)', fontSize:9.5 }}>ASN NET</span>
        {G.asns.map(a=>(
          <div className="asn-card" key={a.num} style={{ padding:'3px 8px', cursor:'pointer' }} onClick={()=>setFw('asn')}>
            <span className="num" style={{ background:`${ASN_COL[a.num]||'var(--cyan)'}22`, color:ASN_COL[a.num]||'var(--cyan)', borderColor:ASN_COL[a.num]||'var(--cyan)' }}>{a.num}</span>
            <span className="label">{a.org}</span>
            <span className="country">{a.country} · {a.role}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const ASN_COL = { 'AS24940':'#6c71c4','AS33915':'#dc322f','AS7922':'#2aa198','AS54113':'#268bd2','AS49544':'#d33682','local':'#859900' };

/* =========================================================
   FLOWCHART SUB-MODE — living vertical branch/merge tree
   ========================================================= */
const STATUS_STYLE = {
  pass:    { bg: 'var(--green)',   glow: 'var(--green)',   sym: '✓' },
  fail:    { bg: 'var(--red)',     glow: 'var(--red)',     sym: '✗' },
  partial: { bg: 'var(--yellow)',  glow: 'var(--yellow)',  sym: '~' },
  run:     { bg: 'var(--cyan)',    glow: 'var(--cyan)',    sym: '▶' },
  queued:  { bg: 'var(--txt-mute)',glow: 'none',           sym: '·' },
  gated:   { bg: 'var(--violet)',  glow: 'var(--violet)',  sym: '◆' },
};

function FlowNode({ node, isRoot }) {
  const [hover, setHover] = useStateM(false);
  const st = STATUS_STYLE[node.status] || STATUS_STYLE.queued;
  const isRunning = node.status === 'run';
  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        position: 'relative',
        padding: isRoot ? '8px 14px' : '6px 10px',
        border: `1px solid ${hover || isRunning ? st.bg : 'var(--line-strong)'}`,
        borderLeft: `3px solid ${st.bg}`,
        borderRadius: 'var(--r-2)',
        background: isRoot ? 'var(--elev-1)' : 'var(--bg-deep)',
        fontFamily: 'var(--mono)',
        boxShadow: isRunning ? `0 0 10px ${st.glow}44` : hover ? `0 0 6px ${st.bg}22` : 'none',
        transition: 'box-shadow 200ms, border-color 200ms',
        minWidth: isRoot ? 320 : 180,
        maxWidth: isRoot ? 480 : 220,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
        <span style={{
          width: 14, height: 14, borderRadius: 3, background: st.bg,
          display: 'grid', placeItems: 'center',
          fontSize: 8, fontWeight: 700, color: 'var(--bg-deep)', flex: '0 0 14px',
          boxShadow: isRunning ? `0 0 8px ${st.glow}` : 'none',
          animation: isRunning ? 'glow-pulse 1.6s infinite' : 'none',
        }}>{st.sym}</span>
        <span style={{ color: 'var(--txt-strong)', fontWeight: 600, fontSize: isRoot ? 12.5 : 11, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{node.kind}</span>
        {node.task && <span style={{ fontSize: 9, color: 'var(--txt-mute)' }}>{node.task}</span>}
      </div>
      <div style={{ fontSize: 10, color: 'var(--txt-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{node.summary}</div>
      {node.route && (
        <div style={{ display: 'flex', gap: 4, marginTop: 4, alignItems: 'center' }}>
          <span style={{ fontSize: 9, color: 'var(--violet)', background: 'var(--violet-soft)', padding: '1px 4px', borderRadius: 2, border: '1px solid var(--violet)' }}>{node.route}</span>
          {node.time && node.time !== '—' && <span style={{ fontSize: 9, color: 'var(--txt-mute)' }}>{node.time}</span>}
        </div>
      )}
      {isRunning && (
        <div className="loadbar" style={{ position: 'absolute', left: 0, right: 0, bottom: 0, borderRadius: '0 0 var(--r-2) var(--r-2)', height: 2 }} />
      )}
    </div>
  );
}

function BranchColumn({ branch }) {
  const st = STATUS_STYLE[branch.status] || STATUS_STYLE.queued;
  const isRunning = branch.status === 'run';
  const children = branch.children || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0 }}>
      {/* Branch node */}
      <FlowNode node={branch} />
      {children.length > 0 && (
        <>
          {/* Vertical connector from branch to children row */}
          <div style={{ width: 2, height: 20, position: 'relative', overflow: 'visible' }}>
            <svg width="2" height="20" style={{ position: 'absolute', left: 0 }}>
              <line x1="1" y1="0" x2="1" y2="20"
                stroke={isRunning ? 'var(--cyan)' : st.bg}
                strokeWidth="1.5"
                strokeDasharray={isRunning ? '4 3' : '3 3'}
                opacity={isRunning ? 1 : 0.6}
              >
                {isRunning && <animate attributeName="stroke-dashoffset" from="0" to="-14" dur="0.9s" repeatCount="indefinite" />}
              </line>
            </svg>
          </div>
          {/* Horizontal divider line spanning all children */}
          {children.length > 1 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '100%' }}>
              <svg width="100%" height="12" style={{ overflow: 'visible', display: 'block', minWidth: children.length * 192 }}>
                <line x1="0" y1="6" x2="100%" y2="6" stroke="var(--line-strong)" strokeWidth="1" strokeDasharray="3 4" />
              </svg>
              <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                {children.map(child => (
                  <div key={child.id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0 }}>
                    <svg width="2" height="10"><line x1="1" y1="0" x2="1" y2="10" stroke="var(--line-strong)" strokeWidth="1" strokeDasharray="2 3" /></svg>
                    <FlowNode node={child} />
                    {/* Terminate indicator */}
                    <div style={{ width: 2, height: 10, background: 'linear-gradient(var(--line-strong), transparent)' }} />
                    <div style={{ width: 6, height: 6, borderRadius: '50%', border: `1px solid ${STATUS_STYLE[child.status]?.bg || 'var(--line-strong)'}`, background: 'var(--bg-deep)' }} />
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <FlowNode node={children[0]} />
              <div style={{ width: 2, height: 12, background: 'linear-gradient(var(--line-strong), transparent)' }} />
              <div style={{ width: 6, height: 6, borderRadius: '50%', border: `1px solid ${STATUS_STYLE[children[0].status]?.bg || 'var(--line-strong)'}`, background: 'var(--bg-deep)' }} />
            </div>
          )}
        </>
      )}
      {children.length === 0 && (
        <>
          <div style={{ width: 2, height: 12, background: `linear-gradient(${st.bg}80, transparent)` }} />
          <div style={{ width: 6, height: 6, borderRadius: '50%', border: `1px solid ${st.bg}`, background: 'var(--bg-deep)' }} />
        </>
      )}
    </div>
  );
}

function FlowChartSub() {
  const D = window.PD_DATA;
  const root = D.traces[0];
  const branches = root?.children || [];

  const running = branches.filter(b => b.status === 'run');
  const gated   = branches.filter(b => b.status === 'gated');
  const failed  = branches.filter(b => b.status === 'fail' || (b.children || []).some(c => c.status === 'fail'));

  return (
    <div style={{ flex: 1, minHeight: 0, display: 'flex' }}>
      <div style={{ flex: 1, overflow: 'auto', padding: 20, background: 'var(--bg-deep)' }}>

        {/* summary strip */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap', alignItems: 'center' }}>
          <span className="upper" style={{ color: 'var(--txt-mute)' }}>LIVE EXECUTION TREE</span>
          <Pill tone="cyan"><Dot tone="cyan" /> {running.length} running</Pill>
          <Pill tone="violet">{gated.length} gated</Pill>
          {failed.length > 0 && <Pill tone="red">{failed.length} failed</Pill>}
          <span className="dim mono" style={{ fontSize: 10, marginLeft: 'auto' }}>
            {root?.time} · tick {root?.task || 'tr_root'}
          </span>
        </div>

        {/* root node */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 0 }}>
          <FlowNode node={root} isRoot />
        </div>

        {/* trunk line down to horizontal bus */}
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <svg width="2" height="28">
            <line x1="1" y1="0" x2="1" y2="28" stroke="var(--cyan)" strokeWidth="1.5" strokeDasharray="4 3">
              <animate attributeName="stroke-dashoffset" from="0" to="-14" dur="0.9s" repeatCount="indefinite" />
            </line>
          </svg>
        </div>

        {/* horizontal bus connecting to branches */}
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <svg style={{ width: '100%', height: 8, overflow: 'visible' }}>
            <line x1="5%" y1="4" x2="95%" y2="4" stroke="var(--line-strong)" strokeWidth="1.5" strokeDasharray="4 5">
              <animate attributeName="stroke-dashoffset" from="0" to="-18" dur="2.5s" repeatCount="indefinite" />
            </line>
          </svg>
        </div>

        {/* branches */}
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', justifyContent: 'center', flexWrap: 'wrap', paddingTop: 0 }}>
          {branches.map(branch => (
            <div key={branch.id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              {/* drop line from bus */}
              <svg width="2" height="18">
                <line x1="1" y1="0" x2="1" y2="18"
                  stroke={branch.status === 'run' ? 'var(--cyan)' : STATUS_STYLE[branch.status]?.bg || 'var(--line-strong)'}
                  strokeWidth="1.5" strokeDasharray="3 3"
                  opacity={branch.status === 'run' ? 1 : 0.5}
                >
                  {branch.status === 'run' && <animate attributeName="stroke-dashoffset" from="0" to="-12" dur="0.9s" repeatCount="indefinite" />}
                </line>
              </svg>
              <BranchColumn branch={branch} />
            </div>
          ))}
        </div>

      </div>

      {/* right inspector */}
      <aside className="inspector">
        <div className="tabs">
          <button className="tab active">DETAIL</button>
          <button className="tab">VERIFIER</button>
          <button className="tab">ROUTING</button>
        </div>
        <div className="panel-body" style={{ padding: 12, gap: 12, display: 'flex', flexDirection: 'column', fontSize: 11.5 }}>
          <div>
            <div className="upper" style={{ marginBottom: 4 }}>active branch</div>
            <div className="strong mono" style={{ fontSize: 13 }}>web.content_discovery</div>
            <div className="dim mono" style={{ fontSize: 10.5 }}>t_8c4c · running · gemma3:12b</div>
            <div className="loadbar" style={{ marginTop: 8 }} />
          </div>
          <div className="kv">
            <span className="k">branches</span><span className="v">{branches.length} from root</span>
            <span className="k">running</span><span className="v">{running.length}</span>
            <span className="k">gated</span><span className="v">{gated.length}</span>
            <span className="k">leaf nodes</span><span className="v">{branches.filter(b => !b.children?.length).length}</span>
            <span className="k">max depth</span><span className="v">3 levels</span>
          </div>
          <div>
            <div className="upper" style={{ marginBottom: 6 }}>verifier findings</div>
            <div className="col gap-4" style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>
              <div className="row gap-6"><Pill tone="yellow">LOOP</Pill><span className="strong">dns_enumeration</span><span className="dim" style={{ marginLeft: 'auto' }}>cooled</span></div>
              <div className="row gap-6"><Pill tone="yellow">LOOP</Pill><span className="strong">kerb_user_disco</span><span className="dim" style={{ marginLeft: 'auto' }}>backed off</span></div>
              <div className="row gap-6"><Pill tone="green">OK</Pill><span className="strong">tick.cadence</span><span className="dim" style={{ marginLeft: 'auto' }}>1.4s avg</span></div>
              <div className="row gap-6"><Pill tone="red">FAIL</Pill><span className="strong">searchsploit</span><span className="dim" style={{ marginLeft: 'auto' }}>missing terms</span></div>
            </div>
          </div>
          <div className="row gap-6">
            <button className="btn primary sm">PIN TREE</button>
            <button className="btn ghost sm">EXPORT</button>
          </div>
        </div>
      </aside>
    </div>
  );
}

/* =========================================================
   MAP — sub-tab host
   ========================================================= */
function TraceMode() {
  const [sub, setSub] = useStateM('tree');
  const D = window.PD_DATA;

  const stats = sub === 'tree'
    ? [
        { k: 'branches', v: (D.traces[0]?.children || []).length },
        { k: 'running',  v: 1 },
        { k: 'gated',    v: 3 },
        { k: 'failed',   v: 2 },
      ]
    : sub === 'graph'
      ? [
          { k: 'nodes', v: D.graph.nodes.length },
          { k: 'edges', v: D.graph.edges.length },
          { k: 'pivot', v: '5-step' },
          { k: 'mode',  v: 'maltego' },
        ]
      : [
          { k: 'pins',   v: D.geo.pins.length },
          { k: 'asns',   v: D.geo.asns.length },
          { k: 'relay',  v: (D.geo.pins.find(p => p.kind === 'relay') || {}).city || '—' },
          { k: 'rtt',    v: '41ms' },
        ];

  const subtitle = sub === 'tree'  ? 'execution flow · living tree'
                 : sub === 'graph' ? 'pirate.htb · asset graph'
                 : 'geoip · asn · network routing';

  return (
    <>
      <window.TopBar crumbs={['primordial', 'trace', subtitle]} stats={stats} />
      <div className="subtabs">
        <button className={`subtab ${sub === 'tree' ? 'active' : ''}`} onClick={() => setSub('tree')}>
          ⌥ TREE <span className="badge">{(D.traces[0]?.children || []).length}</span>
        </button>
        <button className={`subtab ${sub === 'graph' ? 'active' : ''}`} onClick={() => setSub('graph')}>
          ▣ GRAPH <span className="badge">{D.graph.nodes.length}</span>
        </button>
        <button className={`subtab ${sub === 'geo' ? 'active' : ''}`} onClick={() => setSub('geo')}>
          ◉ GEO <span className="badge">{D.geo.pins.length}</span>
        </button>
        <div style={{ flex: 1 }}></div>
        <span className="dim mono" style={{ fontSize: 10.5, paddingRight: 8 }}>
          {sub === 'tree'  && 'living flowchart · branches & merges · click to inspect'}
          {sub === 'graph' && 'drag nodes · scroll to zoom · subtle trace animation'}
          {sub === 'geo'   && 'click a pin to inspect'}
        </span>
      </div>
      {sub === 'tree'  && <FlowChartSub />}
      {sub === 'graph' && <GraphSub />}
      {sub === 'geo'   && <GeoSub />}
    </>
  );
}

window.TraceMode = TraceMode;
window.MapMode = TraceMode;
