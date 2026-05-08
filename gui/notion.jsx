/* global React, Panel, Pill, Dot */
const { useState: useStateN, useMemo: useMemoN } = React;

const KIND_ICON = {
  'target-root': '⊟', overview: '◈', notes: '✎', 'evidence-links': '⊞',
  findings: '!', 'open-hypotheses': '?', 'next-actions': '▷', 'agent-guidance': '⌂',
};
const KIND_COLOR = {
  'target-root': 'var(--cyan)', overview: 'var(--blue)', notes: 'var(--green)',
  'evidence-links': 'var(--violet)', findings: 'var(--red)', 'open-hypotheses': 'var(--yellow)',
  'next-actions': 'var(--cyan)', 'agent-guidance': 'var(--magenta)',
};

function FolderNode({ node, sel, onSel, depth = 0 }) {
  const [open, setOpen] = useStateN(depth === 0);
  const hasChildren = node.children && node.children.length > 0;
  const active = sel === node.id;
  const color = KIND_COLOR[node.kind] || 'var(--txt-mute)';
  return (
    <>
      <div
        onClick={() => { onSel(node.id); if (hasChildren) setOpen(o => !o); }}
        style={{
          display: 'flex', alignItems: 'center', gap: 5,
          padding: `4px 8px 4px ${8 + depth * 14}px`,
          background: active ? 'var(--cyan-soft)' : 'transparent',
          borderLeft: active ? '2px solid var(--cyan)' : '2px solid transparent',
          cursor: 'pointer', borderBottom: '1px solid var(--line)',
          fontFamily: 'var(--mono)', fontSize: 11,
        }}
      >
        {hasChildren && (
          <span style={{ color: 'var(--txt-mute)', fontSize: 9, width: 10, flex: '0 0 10px' }}>{open ? '▾' : '▸'}</span>
        )}
        <span style={{ color, fontSize: 12, flex: '0 0 14px', textAlign: 'center' }}>{KIND_ICON[node.kind] || '·'}</span>
        <span style={{ flex: 1, color: active ? 'var(--cyan)' : 'var(--txt-strong)', fontWeight: active ? 600 : 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {node.label}
        </span>
        {node.synced && <span style={{ fontSize: 9, color: 'var(--green)' }}>✓</span>}
      </div>
      {hasChildren && open && node.children.map(child => (
        <FolderNode key={child.id} node={child} sel={sel} onSel={onSel} depth={depth + 1} />
      ))}
    </>
  );
}

function PageBody({ body }) {
  const lines = (body || '').split('\n');
  return (
    <div style={{ fontFamily: 'var(--sans)', fontSize: 13, color: 'var(--txt-strong)', lineHeight: 1.7, display: 'flex', flexDirection: 'column', gap: 2 }}>
      {lines.map((line, i) => {
        if (!line.trim()) return <div key={i} style={{ height: 8 }} />;
        if (line.startsWith('•')) return (
          <div key={i} style={{ display: 'flex', gap: 8, paddingLeft: 8 }}>
            <span style={{ color: 'var(--cyan)', flex: '0 0 10px' }}>•</span>
            <span style={{ color: 'var(--txt)', fontSize: 12.5 }}>{line.slice(1).trim()}</span>
          </div>
        );
        const isNum = /^\d+\./.test(line);
        if (isNum) return (
          <div key={i} style={{ display: 'flex', gap: 8, paddingLeft: 8 }}>
            <span style={{ color: 'var(--cyan)', flex: '0 0 18px', fontFamily: 'var(--mono)', fontSize: 11 }}>{line.match(/^\d+/)[0]}.</span>
            <span style={{ color: 'var(--txt)', fontSize: 12.5 }}>{line.replace(/^\d+\.\s*/, '')}</span>
          </div>
        );
        if (line.startsWith('#')) return (
          <div key={i} style={{ color: 'var(--txt-hi)', fontWeight: 700, fontSize: 15, marginTop: 8, paddingBottom: 4, borderBottom: '1px solid var(--line)' }}>{line.replace(/^#+\s*/, '')}</div>
        );
        return (
          <div key={i} style={{ color: 'var(--txt)', fontSize: 12.5 }}>
            {line.split(/(`[^`]+`)/).map((seg, j) =>
              seg.startsWith('`') ? (
                <code key={j} style={{ fontFamily: 'var(--mono)', fontSize: 11, background: 'var(--bg-deep)', color: 'var(--cyan)', padding: '1px 4px', borderRadius: 2 }}>{seg.slice(1, -1)}</code>
              ) : seg
            )}
          </div>
        );
      })}
    </div>
  );
}

function NotesMode() {
  const D = window.PD_DATA.notes;
  const API = window.PD_API || {};
  const defaultTarget = D.targets?.[0]?.id || '';
  const defaultPage = D.folders?.[0]?.children?.[0]?.id || null;
  const [activeTgt, setActiveTgt] = useStateN(defaultTarget);
  const [sel, setSel] = useStateN(defaultPage);
  const [editing, setEditing] = useStateN(false);
  const [editBody, setEditBody] = useStateN('');

  const tgtFolders = useMemoN(() => D.folders.filter(f => f.target === activeTgt), [activeTgt, D.folders]);
  const page = useMemoN(() => D.pages[sel], [sel]);

  const startEdit = () => { setEditBody(page?.body || ''); setEditing(true); };
  const saveEdit = () => { setEditing(false); };

  const sync = D.syncStatus;
  const syncFindings = () => API.action?.('sync-findings-context');
  const command = (name, body = {}) => API.command?.(name, { target: activeTgt, page_id: sel, ...body });

  return (
    <>
      <window.TopBar
        crumbs={['primordial', 'notion', activeTgt]}
        stats={[
          { k: 'sync', v: sync.ok ? 'ok' : 'error' },
          { k: 'last sync', v: sync.lastSync },
          { k: 'pending', v: sync.pendingJobs },
          { k: 'failed', v: sync.failedJobs },
        ]}
      />

      <div style={{ flex: 1, minHeight: 0, display: 'flex' }}>

        {/* left sidebar: target + folder tree */}
        <aside style={{ width: 240, flex: '0 0 240px', borderRight: '1px solid var(--line)', display: 'flex', flexDirection: 'column', background: 'var(--bg-deep)' }}>
          {/* target switcher */}
          <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--line)' }}>
            <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>TARGET</div>
            {D.targets.map(t => (
              <button key={t.id}
                onClick={() => { setActiveTgt(t.id); setSel(null); }}
                style={{
                  width: '100%', textAlign: 'left', display: 'flex', alignItems: 'center', gap: 6,
                  padding: '6px 8px', marginBottom: 2,
                  background: activeTgt === t.id ? 'var(--cyan-soft)' : 'transparent',
                  border: `1px solid ${activeTgt === t.id ? 'var(--cyan)' : 'var(--line)'}`,
                  borderRadius: 'var(--r-2)', cursor: 'pointer',
                }}
              >
                <Dot tone={t.active ? 'green' : 'gray'} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 600, color: activeTgt === t.id ? 'var(--cyan)' : 'var(--txt-strong)' }}>{t.label}</div>
                  <div className="dim mono" style={{ fontSize: 9.5 }}>{t.profile}</div>
                </div>
              </button>
            ))}
            <button className="btn ghost sm" style={{ width: '100%', marginTop: 4 }} onClick={() => command('notion-add-project', { title: 'Add Notion project' })}>+ ADD PROJECT</button>
          </div>

          {/* folder tree */}
          <div style={{ flex: 1, overflow: 'auto' }}>
            <div style={{ padding: '6px 10px 4px', borderBottom: '1px solid var(--line)' }}>
              <div className="upper" style={{ color: 'var(--txt-mute)' }}>PAGES</div>
            </div>
            {tgtFolders.map(folder => (
              <FolderNode key={folder.id} node={folder} sel={sel} onSel={setSel} depth={0} />
            ))}
          </div>

          {/* sync status footer */}
          <div style={{ padding: '8px 10px', borderTop: '1px solid var(--line)', fontFamily: 'var(--mono)', fontSize: 10.5 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <Dot tone={sync.ok ? 'green' : 'red'} />
              <span className="strong" style={{ fontSize: 10.5 }}>NOTION SYNC</span>
              {sync.pendingJobs > 0 && <Pill tone="yellow">{sync.pendingJobs} PENDING</Pill>}
            </div>
            <div className="dim" style={{ fontSize: 10 }}>last sync {sync.lastSync}</div>
            <div style={{ display: 'flex', gap: 4, marginTop: 6 }}>
              <button className="btn primary sm" style={{ flex: 1 }} onClick={syncFindings}>↑ PUSH</button>
              <button className="btn ghost sm" style={{ flex: 1 }} onClick={() => command('notion-pull-target', { title: `Pull Notion pages for ${activeTgt || 'target'}` })}>↓ PULL</button>
            </div>
          </div>
        </aside>

        {/* center: page viewer/editor */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
          {page ? (
            <>
              {/* page toolbar */}
              <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--line)', background: 'var(--bg-deep)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ flex: 1 }}>
                  <div className="strong" style={{ fontSize: 16, fontWeight: 700, color: 'var(--txt-hi)' }}>{page.title}</div>
                  <div className="dim mono" style={{ fontSize: 10 }}>{sel} · {activeTgt}</div>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {editing ? (
                    <>
                      <button className="btn primary sm" onClick={saveEdit}>SAVE</button>
                      <button className="btn ghost sm" onClick={() => setEditing(false)}>CANCEL</button>
                    </>
                  ) : (
                    <>
                      <button className="btn ghost sm" onClick={startEdit}>EDIT</button>
                      <button className="btn ghost sm" onClick={syncFindings}>↑ PUSH TO NOTION</button>
                      <button className="btn ghost sm" onClick={() => command('notion-open-page', { title: `Open Notion page ${sel || ''}` })}>↗ OPEN IN NOTION</button>
                    </>
                  )}
                </div>
              </div>

              {/* page content */}
              <div style={{ flex: 1, overflow: 'auto', padding: '20px 32px' }}>
                {editing ? (
                  <textarea
                    className="input"
                    value={editBody}
                    onChange={e => setEditBody(e.target.value)}
                    style={{ width: '100%', minHeight: 400, fontFamily: 'var(--mono)', fontSize: 12, resize: 'vertical', lineHeight: 1.6 }}
                  />
                ) : (
                  <PageBody body={page.body} />
                )}
              </div>
            </>
          ) : (
            <div style={{ flex: 1, display: 'grid', placeItems: 'center', flexDirection: 'column', color: 'var(--txt-mute)', fontFamily: 'var(--mono)', fontSize: 12 }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 32, marginBottom: 10, opacity: 0.3 }}>◈</div>
                <div>SELECT A PAGE FROM THE FOLDER TREE</div>
              </div>
            </div>
          )}
        </div>

        {/* right: quick actions + metadata */}
        <aside style={{ width: 220, flex: '0 0 220px', borderLeft: '1px solid var(--line)', display: 'flex', flexDirection: 'column', background: 'var(--bg)', overflow: 'auto' }}>
          <div style={{ padding: '7px 10px', borderBottom: '1px solid var(--line)', background: 'linear-gradient(180deg, var(--elev-1), var(--bg))' }}>
            <span className="upper" style={{ fontSize: 10, fontWeight: 600, color: 'var(--txt-strong)' }}>ACTIONS</span>
          </div>
          <div style={{ padding: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
            <button className="btn sm" style={{ justifyContent: 'flex-start' }} onClick={syncFindings}>↑ PUSH ALL PAGES</button>
            <button className="btn ghost sm" style={{ justifyContent: 'flex-start' }} onClick={() => command('notion-pull-all', { title: 'Pull from Notion' })}>↓ PULL FROM NOTION</button>
            <button className="btn ghost sm" style={{ justifyContent: 'flex-start' }} onClick={() => command('notion-new-page', { title: 'Create Notion page proposal' })}>+ NEW PAGE</button>
            <button className="btn ghost sm" style={{ justifyContent: 'flex-start' }} onClick={() => command('notion-bulk-sync', { title: 'Bulk sync Notion workspace' })}>⊞ BULK SYNC</button>
          </div>
          <div style={{ padding: '8px 10px', borderTop: '1px solid var(--line)' }}>
            <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>WORKSPACE HEALTH</div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 10.5, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {[
                { k: 'pages synced', v: '6/6', tone: 'green' },
                { k: 'pending jobs', v: String(sync.pendingJobs), tone: sync.pendingJobs > 0 ? 'yellow' : 'green' },
                { k: 'failed jobs',  v: String(sync.failedJobs),  tone: sync.failedJobs > 0 ? 'red' : 'green' },
                { k: 'last pull',    v: '13:48:00', tone: '' },
              ].map(r => (
                <div key={r.k} style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span className="dim">{r.k}</span>
                  <span style={{ color: r.tone ? `var(--${r.tone})` : 'var(--txt-strong)', fontWeight: r.tone ? 600 : 400 }}>{r.v}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ padding: '8px 10px', borderTop: '1px solid var(--line)' }}>
            <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>ALL TARGETS</div>
            {D.targets.map(t => (
              <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 0', fontFamily: 'var(--mono)', fontSize: 10.5 }}>
                <Dot tone={t.active ? 'green' : 'gray'} />
                <span className="strong" style={{ flex: 1 }}>{t.label}</span>
                <span className="dim" style={{ fontSize: 9.5 }}>{t.profile}</span>
              </div>
            ))}
          </div>
        </aside>
      </div>
    </>
  );
}

window.NotesMode = NotesMode;
