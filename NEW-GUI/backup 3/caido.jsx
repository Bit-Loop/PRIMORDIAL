/* global React, Panel, Pill, Dot */
const { useState: useStateCA, useMemo: useMemoCA } = React;

const METHOD_COLOR = {
  GET: 'var(--green)', POST: 'var(--cyan)', PUT: 'var(--blue)',
  DELETE: 'var(--red)', PATCH: 'var(--yellow)', OPTIONS: 'var(--txt-mute)',
};
const STATUS_TONE = (s) => s >= 500 ? 'red' : s >= 400 ? 'yellow' : s >= 300 ? 'blue' : s >= 200 ? 'green' : 'gray';

function ReqRow({ r, sel, onSel }) {
  const active = sel === r.id;
  return (
    <tr className={active ? 'sel' : ''} onClick={() => onSel(r.id)} style={{ cursor: 'pointer' }}>
      <td>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, fontWeight: 700, color: METHOD_COLOR[r.method] || 'var(--txt-mute)' }}>{r.method}</span>
      </td>
      <td className="dim" style={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.host}</td>
      <td style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--mono)', fontSize: 11 }}>{r.path}</td>
      <td>
        <Pill tone={STATUS_TONE(r.status)}>{r.status}</Pill>
      </td>
      <td className="dim">{r.length ? `${r.length}B` : '—'}</td>
      <td className="dim">{r.time}</td>
      <td>
        {r.source === 'replay' && <Pill tone="violet">REPLAY</Pill>}
        {r.source === 'proxy' && <Pill tone="gray">PROXY</Pill>}
      </td>
    </tr>
  );
}

function RequestDetail({ req }) {
  if (!req) return (
    <div style={{ flex: 1, display: 'grid', placeItems: 'center', color: 'var(--txt-mute)', fontFamily: 'var(--mono)', fontSize: 12 }}>
      SELECT A REQUEST
    </div>
  );
  const mockReqHeaders = [
    ['GET', `${req.path} HTTP/1.1`],
    ['Host', req.host],
    ['User-Agent', 'Mozilla/5.0 (X11; Linux x86_64)'],
    ['Accept', 'text/html,application/xhtml+xml,*/*'],
    ['Accept-Encoding', 'gzip, deflate'],
    ['Connection', 'keep-alive'],
  ];
  const mockRespHeaders = [
    ['HTTP/1.1', `${req.status} ${req.status === 200 ? 'OK' : req.status === 302 ? 'Found' : req.status === 401 ? 'Unauthorized' : req.status === 404 ? 'Not Found' : 'Response'}`],
    ['Content-Type', req.mime || 'text/html'],
    ['Content-Length', String(req.length)],
    ['Server', 'Microsoft-IIS/10.0'],
    ['X-Powered-By', 'ASP.NET'],
    ['Date', 'Thu, 07 May 2026 14:02:09 GMT'],
  ];
  return (
    <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: 12, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: METHOD_COLOR[req.method] }}>{req.method}</span>
        <span className="strong mono" style={{ fontSize: 13 }}>{req.path}</span>
        <Pill tone={STATUS_TONE(req.status)}>{req.status}</Pill>
        {req.source === 'replay' && <Pill tone="violet">REPLAY</Pill>}
        <span className="dim mono" style={{ marginLeft: 'auto', fontSize: 10 }}>{req.time} · {req.length}B</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div>
          <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>REQUEST HEADERS</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 10.5, background: 'var(--bg-deep)', border: '1px solid var(--line)', borderRadius: 'var(--r-2)', padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 2 }}>
            {mockReqHeaders.map(([k, v], i) => (
              <div key={i} style={{ display: 'flex', gap: 8 }}>
                <span style={{ color: 'var(--cyan)', width: 100, flex: '0 0 100px' }}>{k}</span>
                <span style={{ color: 'var(--txt-strong)' }}>{v}</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>RESPONSE HEADERS</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 10.5, background: 'var(--bg-deep)', border: '1px solid var(--line)', borderRadius: 'var(--r-2)', padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 2 }}>
            {mockRespHeaders.map(([k, v], i) => (
              <div key={i} style={{ display: 'flex', gap: 8 }}>
                <span style={{ color: 'var(--violet)', width: 100, flex: '0 0 100px' }}>{k}</span>
                <span style={{ color: 'var(--txt-strong)' }}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {req.method === 'POST' && (
        <div>
          <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>REQUEST BODY</div>
          <pre style={{ fontFamily: 'var(--mono)', fontSize: 11, background: 'var(--bg-deep)', border: '1px solid var(--line)', borderRadius: 'var(--r-2)', padding: '8px 10px', color: 'var(--txt-strong)', margin: 0, overflow: 'auto' }}>
            {`username=admin&password=tomcat`}
          </pre>
        </div>
      )}

      <div>
        <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>RESPONSE BODY</div>
        <pre style={{ fontFamily: 'var(--mono)', fontSize: 10.5, background: 'var(--bg-deep)', border: '1px solid var(--line)', borderRadius: 'var(--r-2)', padding: '8px 10px', color: 'var(--txt)', margin: 0, overflow: 'auto', maxHeight: 160 }}>
          {req.status === 200 ? `<!DOCTYPE html>\n<html>\n<head><title>${req.host}</title></head>\n<body>\n  <!-- IIS default page -->\n  <h1>IIS Windows Server</h1>\n</body>\n</html>` :
           req.status === 302 ? `<html><body><a href="/login">Object moved</a></body></html>` :
           req.status === 401 ? `HTTP 401 Unauthorized\nWWW-Authenticate: Basic realm="Tomcat Manager Application"` :
           `(empty body)`}
        </pre>
      </div>

      <div style={{ display: 'flex', gap: 6 }}>
        <button className="btn primary sm">SEND TO REPLAY</button>
        <button className="btn sm">ATTACH AS EVIDENCE</button>
        <button className="btn ghost sm">COPY AS CURL</button>
        <button className="btn ghost sm" style={{ marginLeft: 'auto' }}>OPEN IN CAIDO ↗</button>
      </div>
    </div>
  );
}

function CaidoMode() {
  const D = window.PD_DATA.caido;
  const [sel, setSel] = useStateCA(null);
  const [httpql, setHttpql] = useStateCA('req.host.eq:"pirate.htb"');
  const [activeFilt, setActiveFilt] = useStateCA('sf_01');

  const filtered = useMemoCA(() => {
    if (!httpql.trim()) return D.requests;
    const hostMatch = httpql.match(/req\.host\.eq:"([^"]+)"/);
    const pathCont = httpql.match(/req\.path\.cont:"([^"]+)"/g);
    const statusGte = httpql.match(/resp\.code\.gte:(\d+)/);
    return D.requests.filter(r => {
      if (hostMatch && r.host !== hostMatch[1]) return false;
      if (statusGte && r.status < parseInt(statusGte[1])) return false;
      if (pathCont) {
        const terms = pathCont.map(m => m.match(/"([^"]+)"/)[1]);
        if (!terms.some(t => r.path.includes(t))) return false;
      }
      return true;
    });
  }, [httpql, D.requests]);

  const selReq = D.requests.find(r => r.id === sel);

  const connOk = D.connection.ok;

  return (
    <>
      <window.TopBar
        crumbs={['primordial', 'caido', 'proxy integration']}
        stats={[
          { k: 'requests', v: D.requests.length },
          { k: 'replays',  v: D.replays.length },
          { k: 'filtered', v: filtered.length },
          { k: 'status',   v: connOk ? 'live' : 'offline' },
        ]}
      />

      <div style={{ flex: 1, minHeight: 0, display: 'flex', gap: 0 }}>

        {/* left sidebar */}
        <aside style={{ width: 220, flex: '0 0 220px', borderRight: '1px solid var(--line)', display: 'flex', flexDirection: 'column', background: 'var(--bg-deep)' }}>
          {/* connection */}
          <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--line)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <Dot tone={connOk ? 'green' : 'red'} />
              <span className="upper" style={{ fontSize: 10 }}>CAIDO PROXY</span>
              <Pill tone={connOk ? 'green' : 'red'} style={{ marginLeft: 'auto' }}>{connOk ? 'LIVE' : 'OFFLINE'}</Pill>
            </div>
            <div className="dim mono" style={{ fontSize: 10 }}>{D.connection.graphql_url}</div>
          </div>

          {/* saved filters */}
          <div style={{ padding: '6px 10px 4px', borderBottom: '1px solid var(--line)' }}>
            <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>SAVED FILTERS</div>
            {D.savedFilters.map(f => (
              <button key={f.id}
                onClick={() => { setActiveFilt(f.id); setHttpql(f.httpql); }}
                style={{
                  width: '100%', textAlign: 'left', background: activeFilt === f.id ? 'var(--cyan-soft)' : 'transparent',
                  border: 0, borderLeft: `2px solid ${activeFilt === f.id ? 'var(--cyan)' : 'transparent'}`,
                  padding: '5px 8px', color: activeFilt === f.id ? 'var(--cyan)' : 'var(--txt-dim)',
                  cursor: 'pointer', display: 'flex', flexDirection: 'column', gap: 2,
                }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 600 }}>{f.label}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--txt-mute)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.httpql}</span>
              </button>
            ))}
          </div>

          {/* replays */}
          <div style={{ flex: 1, padding: '6px 10px', overflow: 'auto' }}>
            <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>REPLAYS</div>
            {D.replays.map(r => (
              <div key={r.id} style={{ padding: '6px 8px', marginBottom: 4, border: '1px solid var(--line)', borderRadius: 'var(--r-2)', background: 'var(--bg)', fontFamily: 'var(--mono)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="strong" style={{ fontSize: 11 }}>{r.name}</span>
                  <Pill tone={r.status === 'completed' ? 'green' : 'cyan'}>{r.status.toUpperCase()}</Pill>
                </div>
                <div className="dim" style={{ fontSize: 10, marginTop: 2 }}>{r.requests} reqs · {r.created} · {r.target}</div>
                <div style={{ display: 'flex', gap: 4, marginTop: 6 }}>
                  <button className="btn ghost sm" style={{ flex: 1 }}>▶ LOAD</button>
                  <button className="btn ghost sm">↓</button>
                </div>
              </div>
            ))}
            <button className="btn ghost sm" style={{ width: '100%', marginTop: 4 }}>+ NEW REPLAY</button>
          </div>
        </aside>

        {/* center — request list */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
          {/* HTTPQL bar */}
          <div style={{ padding: '6px 10px', borderBottom: '1px solid var(--line)', background: 'var(--bg-deep)', display: 'flex', gap: 6, alignItems: 'center' }}>
            <span className="upper" style={{ color: 'var(--cyan)', fontSize: 10, flex: '0 0 auto' }}>HTTPQL</span>
            <input
              className="input"
              value={httpql}
              onChange={e => setHttpql(e.target.value)}
              placeholder='req.host.eq:"pirate.htb" AND resp.code.gte:400'
              style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 11 }}
            />
            <button className="btn sm" onClick={() => setHttpql('')}>✕</button>
            <span className="dim mono" style={{ fontSize: 10, flex: '0 0 auto' }}>{filtered.length} results</span>
          </div>

          {/* request table */}
          <div style={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
            <table className="t">
              <thead>
                <tr><th>METHOD</th><th>HOST</th><th>PATH</th><th>STATUS</th><th>LENGTH</th><th>TIME</th><th>SOURCE</th></tr>
              </thead>
              <tbody>
                {filtered.map(r => <ReqRow key={r.id} r={r} sel={sel} onSel={setSel} />)}
              </tbody>
            </table>
          </div>
        </div>

        {/* right — request detail */}
        <aside style={{ width: 460, flex: '0 0 460px', borderLeft: '1px solid var(--line)', display: 'flex', flexDirection: 'column', background: 'var(--bg)' }}>
          <div style={{ padding: '7px 10px', borderBottom: '1px solid var(--line)', background: 'linear-gradient(180deg, var(--elev-1), var(--bg))' }}>
            <span className="upper" style={{ fontSize: 10, fontWeight: 600, color: 'var(--txt-strong)' }}>REQUEST DETAIL</span>
          </div>
          <RequestDetail req={selReq} />
        </aside>
      </div>
    </>
  );
}

window.CaidoMode = CaidoMode;
