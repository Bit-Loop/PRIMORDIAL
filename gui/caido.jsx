/* global React, Pill, Dot */
const { useState: useStateCA, useMemo: useMemoCA, useEffect: useEffectCA } = React;

const METHOD_COLOR = {
  GET: 'var(--green)', POST: 'var(--cyan)', PUT: 'var(--blue)',
  DELETE: 'var(--red)', PATCH: 'var(--yellow)', OPTIONS: 'var(--txt-mute)',
};
const STATUS_TONE = (s) => s >= 500 ? 'red' : s >= 400 ? 'yellow' : s >= 300 ? 'blue' : s >= 200 ? 'green' : 'gray';

function firstTarget(D) {
  return (D.targetOptions || [])[0]?.handle || '';
}

function targetHttpql(D, handle) {
  const target = (D.targetOptions || []).find(t => t.handle === handle);
  return target?.httpql || (D.savedFilters || [])[0]?.httpql || '';
}

function currentTargetHttpql(D, handle) {
  const target = (D.targetOptions || []).find(t => t.handle === handle);
  return target?.httpql || '';
}

function shortHash(value) {
  if (!value) return '';
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}

function replayTemplate(req) {
  if (!req?.host) return '';
  const path = req.path || '/';
  const host = req.host;
  return `${req.method || 'GET'} ${path} HTTP/1.1\nHost: ${host}\nConnection: close\n\n`;
}

function caidoAuthFailed(conn) {
  const errorText = String(conn?.error || '').toLowerCase();
  return !!conn?.auth_error || conn?.status_code === 401 || conn?.status_code === 403 || errorText.includes('unauthorized') || errorText.includes('forbidden');
}

function caidoConnectionState(conn) {
  const authFailed = caidoAuthFailed(conn);
  if (conn?.ok) return { label: 'LIVE', tone: 'green', stat: 'live', authFailed };
  if (authFailed) return { label: 'AUTH FAILED', tone: 'red', stat: 'auth failed', authFailed };
  if (conn?.configured && conn?.checked) return { label: 'ERROR', tone: 'red', stat: 'error', authFailed };
  if (conn?.configured) return { label: 'READY', tone: 'yellow', stat: 'configured', authFailed };
  return { label: 'MISSING', tone: 'red', stat: 'offline', authFailed };
}

function ReqRow({ r, selected, checked, onOpen, onToggle }) {
  const active = selected === r.id;
  return (
    <tr className={active ? 'sel' : ''} onClick={() => onOpen(r.id)} style={{ cursor: 'pointer' }}>
      <td onClick={e => e.stopPropagation()}>
        <input type="checkbox" checked={checked} onChange={() => onToggle(r.id)} />
      </td>
      <td>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, fontWeight: 700, color: METHOD_COLOR[r.method] || 'var(--txt-mute)' }}>{r.method || 'HTTP'}</span>
      </td>
      <td className="dim" style={{ maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.host}</td>
      <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--mono)', fontSize: 11 }}>{r.path}</td>
      <td><Pill tone={STATUS_TONE(Number(r.status || 0))}>{r.status || 0}</Pill></td>
      <td className="dim">{r.response_length || r.length || 0}B</td>
      <td className="dim">{r.source || 'caido'}</td>
    </tr>
  );
}

function SnippetBlock({ label, value, truncated }) {
  return (
    <div>
      <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>{label}{truncated ? ' TRUNCATED' : ''}</div>
      <pre style={{
        fontFamily: 'var(--mono)', fontSize: 10.5, background: 'var(--bg-deep)', border: '1px solid var(--line)',
        borderRadius: 'var(--r-2)', padding: '8px 10px', color: 'var(--txt)', margin: 0, overflow: 'auto', maxHeight: 220,
        whiteSpace: 'pre-wrap', overflowWrap: 'anywhere',
      }}>{value || 'No snippet loaded.'}</pre>
    </div>
  );
}

function RequestDetail({ detail, loading, onReplaySeed }) {
  if (loading) return <div style={{ padding: 14, color: 'var(--txt-mute)', fontFamily: 'var(--mono)', fontSize: 12 }}>LOADING DETAIL</div>;
  const req = detail?.request;
  if (!req) return (
    <div style={{ flex: 1, display: 'grid', placeItems: 'center', color: 'var(--txt-mute)', fontFamily: 'var(--mono)', fontSize: 12 }}>
      SELECT A REQUEST
    </div>
  );
  return (
    <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: 12, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: METHOD_COLOR[req.method] }}>{req.method}</span>
        <span className="strong mono" style={{ fontSize: 13, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{req.path}</span>
        <Pill tone={STATUS_TONE(Number(req.status || 0))}>{req.status || 0}</Pill>
      </div>
      <div className="dim mono" style={{ fontSize: 10, overflowWrap: 'anywhere' }}>
        {req.host}:{req.port || ''} | request {shortHash(req.request_sha256)} | response {shortHash(req.response_sha256)}
      </div>
      <SnippetBlock label="REQUEST SNIPPET" value={req.request_snippet} truncated={req.request_truncated} />
      <SnippetBlock label="RESPONSE SNIPPET" value={req.response_snippet} truncated={req.response_truncated} />
      <button className="btn sm" onClick={() => onReplaySeed(req)}>LOAD IN REPLAY</button>
    </div>
  );
}

function CaidoMode() {
  const D = window.PD_DATA.caido;
  const API = window.PD_API;
  const [target, setTarget] = useStateCA(() => firstTarget(D));
  const [httpql, setHttpql] = useStateCA(() => targetHttpql(D, firstTarget(D)));
  const [results, setResults] = useStateCA(() => D.requests || []);
  const [selectedId, setSelectedId] = useStateCA(null);
  const [checkedIds, setCheckedIds] = useStateCA([]);
  const [detail, setDetail] = useStateCA(null);
  const [loadingDetail, setLoadingDetail] = useStateCA(false);
  const [busy, setBusy] = useStateCA('');
  const [error, setError] = useStateCA('');
  const [replayRaw, setReplayRaw] = useStateCA('');
  const [draft, setDraft] = useStateCA(null);
  const [confirmed, setConfirmed] = useStateCA(false);
  const [connection, setConnection] = useStateCA(() => D.connection || {});

  useEffectCA(() => {
    if (!target && firstTarget(D)) setTarget(firstTarget(D));
  }, [D]);

  useEffectCA(() => {
    refreshConnection();
  }, []);

  async function refreshConnection() {
    setBusy('health');
    try {
      const payload = API.refreshCaido
        ? await API.refreshCaido({ checkHealth: true })
        : await API.request('/api/integrations/caido?check_health=1');
      setConnection(payload || {});
      if (payload?.error && !payload?.ok) setError(payload.error);
      return payload;
    } catch (err) {
      const message = err.message || String(err);
      setConnection(prev => ({ ...prev, ok: false, checked: true, error: message }));
      setError(message);
      return null;
    } finally {
      setBusy('');
    }
  }

  const selectedRows = useMemoCA(
    () => results.filter(r => checkedIds.includes(r.id)),
    [results, checkedIds],
  );
  const conn = connection || {};
  const connectionState = caidoConnectionState(conn);
  const schemaCaps = conn.schema?.capabilities || {};
  const schemaLabel = connectionState.authFailed ? 'auth-blocked' : (schemaCaps.requests_by_offset || schemaCaps.requests ? 'search' : 'unknown');
  const replayLabel = connectionState.authFailed ? 'auth-blocked' : (schemaCaps.start_replay_task ? 'send' : 'unknown');

  async function runSearch(nextHttpql = httpql) {
    setBusy('search');
    setError('');
    try {
      const payload = await API.request('/api/integrations/caido/search', {
        method: 'POST',
        body: { target, httpql: nextHttpql, limit: 75 },
      });
      setResults(payload.requests || []);
      setHttpql(payload.httpql || nextHttpql || '');
      setCheckedIds([]);
      setSelectedId(null);
      setDetail(null);
      if (!payload.ok) setError(payload.error || 'Caido search failed');
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function openDetail(id) {
    setSelectedId(id);
    const local = results.find(r => r.id === id);
    if (local?.requestSnippet || local?.responseSnippet) {
      setDetail({
        ok: true,
        request: {
          id: local.caidoRequestId || local.id,
          method: local.method,
          host: local.host,
          port: local.port || '',
          path: local.path,
          status: local.status,
          request_snippet: local.requestSnippet || '',
          response_snippet: local.responseSnippet || '',
          request_truncated: false,
          response_truncated: false,
        },
      });
      return;
    }
    setLoadingDetail(true);
    setError('');
    try {
      const caidoId = local?.caidoRequestId || id;
      const payload = await API.request(`/api/integrations/caido/requests/${encodeURIComponent(caidoId)}`);
      setDetail(payload);
      if (!payload.ok) setError(payload.error || 'Request detail failed');
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoadingDetail(false);
    }
  }

  function toggleId(id) {
    setCheckedIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  }

  async function importSelected() {
    if (!checkedIds.length) return;
    setBusy('import');
    setError('');
    try {
      const requestIds = checkedIds.map(id => {
        const local = results.find(r => r.id === id);
        return local?.caidoRequestId || id;
      });
      const payload = await API.post('/api/integrations/caido/import', { target, request_ids: requestIds, httpql });
      const imported = payload.result?.imported || [];
      const errors = payload.result?.errors || [];
      if (errors.length) setError(errors.map(e => e.error).join('; '));
      if (imported.length && API.refresh) API.refresh();
      setCheckedIds([]);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function draftReplay() {
    setBusy('draft');
    setError('');
    setDraft(null);
    setConfirmed(false);
    try {
      const payload = await API.request('/api/integrations/caido/replay/draft', {
        method: 'POST',
        body: { target, raw_request: replayRaw },
      });
      setDraft(payload);
      if (!payload.ok) setError(payload.error || 'Replay draft failed');
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function sendReplay() {
    if (!draft?.parsed?.raw_sha256 || !confirmed) {
      setError('Confirm the draft hash before sending Replay.');
      return;
    }
    setBusy('send');
    setError('');
    try {
      const payload = await API.post('/api/integrations/caido/replay/send', {
        target,
        raw_request: replayRaw,
        session_id: draft.session?.id,
        confirmation: draft.parsed.raw_sha256,
      });
      if (!payload.ok) setError(payload.error || 'Replay send failed');
      setDraft(null);
      setConfirmed(false);
      if (API.refresh) API.refresh();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  const applyTarget = (handle) => {
    setTarget(handle);
    const next = targetHttpql(D, handle);
    setHttpql(next);
  };

  return (
    <>
      <window.TopBar
        crumbs={['primordial', 'caido', 'proxy integration']}
        stats={[
          { k: 'results', v: results.length },
          { k: 'selected', v: checkedIds.length },
          { k: 'imports', v: (D.requests || []).length },
          { k: 'status', v: connectionState.stat },
        ]}
      />

      <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '260px minmax(360px, 1fr) 460px', overflow: 'hidden' }}>
        <aside style={{ borderRight: '1px solid var(--line)', display: 'flex', flexDirection: 'column', background: 'var(--bg-deep)', minHeight: 0 }}>
          <div style={{ padding: 10, borderBottom: '1px solid var(--line)', display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Dot tone={connectionState.tone} />
              <span className="upper">CAIDO GRAPHQL</span>
              <Pill tone={connectionState.tone} style={{ marginLeft: 'auto' }}>
                {connectionState.label}
              </Pill>
            </div>
            <div className="dim mono" style={{ fontSize: 10, overflowWrap: 'anywhere' }}>{conn.graphql_url || 'No GraphQL URL configured'}</div>
            {conn.graphql_url_migrated_from && (
              <div className="dim mono" style={{ fontSize: 10, color: 'var(--yellow)', overflowWrap: 'anywhere' }}>
                migrated from {conn.graphql_url_migrated_from}
              </div>
            )}
            {conn.error && (
              <div className="mono" style={{ fontSize: 10, color: 'var(--red)', overflowWrap: 'anywhere' }}>
                {conn.error}
              </div>
            )}
            <div className="dim mono" style={{ fontSize: 10 }}>
              schema {schemaLabel} | replay {replayLabel}
            </div>
            <button className="btn ghost sm" onClick={refreshConnection} disabled={busy === 'health'}>
              HEALTH CHECK
            </button>
          </div>

          <div style={{ padding: 10, borderBottom: '1px solid var(--line)', display: 'flex', flexDirection: 'column', gap: 8 }}>
            <label className="upper" style={{ color: 'var(--txt-mute)' }}>TARGET</label>
            <select className="input" value={target} onChange={e => applyTarget(e.target.value)} style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>
              {(D.targetOptions || []).map(t => <option key={t.id || t.handle} value={t.handle}>{t.handle}</option>)}
            </select>
            <button className="btn ghost sm" onClick={() => setHttpql(currentTargetHttpql(D, target))} disabled={!currentTargetHttpql(D, target)}>
              USE TARGET SCOPE
            </button>
            <button className="btn sm" onClick={() => runSearch()} disabled={busy === 'search'}>SEARCH</button>
          </div>

          <div style={{ padding: 10, borderBottom: '1px solid var(--line)' }}>
            <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>HTTPQL PRESETS</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {(D.savedFilters || []).map(f => (
                <button key={f.id} className="btn ghost sm" style={{ justifyContent: 'flex-start', overflow: 'hidden' }} onClick={() => { setHttpql(f.httpql || ''); runSearch(f.httpql || ''); }}>
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          <div style={{ padding: 10, flex: 1, minHeight: 0, overflow: 'auto' }}>
            <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>IMPORT QUEUE</div>
            {selectedRows.length ? selectedRows.map(r => (
              <div key={r.id} className="mono" style={{ fontSize: 10.5, padding: '6px 0', borderBottom: '1px solid var(--line)' }}>
                <span style={{ color: METHOD_COLOR[r.method] || 'var(--txt-mute)', fontWeight: 700 }}>{r.method}</span> {r.host}{r.path}
              </div>
            )) : <div className="dim mono" style={{ fontSize: 11 }}>No selected rows.</div>}
            <button className="btn primary sm" style={{ width: '100%', marginTop: 8 }} onClick={importSelected} disabled={!checkedIds.length || busy === 'import'}>
              IMPORT SELECTED
            </button>
          </div>
        </aside>

        <main style={{ display: 'flex', flexDirection: 'column', minHeight: 0, minWidth: 0 }}>
          <div style={{ padding: '7px 10px', borderBottom: '1px solid var(--line)', background: 'var(--bg-deep)', display: 'flex', gap: 6, alignItems: 'center' }}>
            <span className="upper" style={{ color: 'var(--cyan)', fontSize: 10, flex: '0 0 auto' }}>HTTPQL</span>
            <input
              className="input"
              value={httpql}
              onChange={e => setHttpql(e.target.value)}
              placeholder='req.host.eq:"target.example" AND resp.code.gte:400'
              style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 11 }}
            />
            <button className="btn sm" onClick={() => setHttpql('')}>CLEAR</button>
          </div>
          {error && (
            <div style={{ padding: '6px 10px', borderBottom: '1px solid var(--line)', color: 'var(--red)', fontFamily: 'var(--mono)', fontSize: 11, display: 'flex', gap: 8 }}>
              <span style={{ flex: 1, overflowWrap: 'anywhere' }}>{error}</span>
              <button className="btn ghost sm" onClick={() => setError('')}>CLEAR</button>
            </div>
          )}
          <div style={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
            <table className="t">
              <thead>
                <tr><th></th><th>METHOD</th><th>HOST</th><th>PATH</th><th>STATUS</th><th>LEN</th><th>SOURCE</th></tr>
              </thead>
              <tbody>
                {results.map(r => (
                  <ReqRow key={r.id} r={r} selected={selectedId} checked={checkedIds.includes(r.id)} onOpen={openDetail} onToggle={toggleId} />
                ))}
              </tbody>
            </table>
          </div>
        </main>

        <aside style={{ borderLeft: '1px solid var(--line)', display: 'flex', flexDirection: 'column', background: 'var(--bg)', minHeight: 0 }}>
          <div style={{ height: '52%', minHeight: 0, borderBottom: '1px solid var(--line)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '7px 10px', borderBottom: '1px solid var(--line)' }}>
              <span className="upper" style={{ fontSize: 10, fontWeight: 600, color: 'var(--txt-strong)' }}>REQUEST DETAIL</span>
            </div>
            <RequestDetail detail={detail} loading={loadingDetail} onReplaySeed={req => { setReplayRaw(replayTemplate(req)); setDraft(null); setConfirmed(false); }} />
          </div>

          <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', gap: 8, padding: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="upper" style={{ color: 'var(--txt-strong)' }}>RAW REPLAY</span>
              {draft?.parsed?.raw_sha256 && <Pill tone="cyan" style={{ marginLeft: 'auto' }}>{shortHash(draft.parsed.raw_sha256)}</Pill>}
            </div>
            <textarea
              className="input"
              value={replayRaw}
              onChange={e => { setReplayRaw(e.target.value); setDraft(null); setConfirmed(false); }}
              spellCheck="false"
              style={{ flex: 1, minHeight: 120, resize: 'none', fontFamily: 'var(--mono)', fontSize: 11, lineHeight: 1.45 }}
            />
            {draft?.parsed && (
              <label className="dim mono" style={{ fontSize: 10.5, display: 'flex', gap: 6, alignItems: 'center' }}>
                <input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />
                confirm one request to {draft.parsed.host}:{draft.parsed.port} with hash {shortHash(draft.parsed.raw_sha256)}
              </label>
            )}
            <div style={{ display: 'flex', gap: 6 }}>
              <button className="btn sm" onClick={draftReplay} disabled={!replayRaw.trim() || busy === 'draft'}>DRAFT</button>
              <button className="btn primary sm" onClick={sendReplay} disabled={!draft?.parsed || !confirmed || busy === 'send'}>SEND ONE</button>
              <button className="btn ghost sm" onClick={() => { setReplayRaw(''); setDraft(null); setConfirmed(false); }} style={{ marginLeft: 'auto' }}>CLEAR</button>
            </div>
          </div>
        </aside>
      </div>
    </>
  );
}

window.CaidoMode = CaidoMode;
