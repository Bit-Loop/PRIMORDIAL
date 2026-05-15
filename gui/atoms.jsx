/* global React */
const { useState, useEffect, useRef, useMemo } = React;

// ===== shared atoms =====
function Pill({ tone = 'gray', children }) {
  return <span className={`pill ${tone}`}>{children}</span>;
}
function Dot({ tone = 'green' }) { return <span className={`dot ${tone}`}></span>; }

function StatusPill({ status }) {
  const map = {
    running: ['cyan', 'RUNNING'],
    done: ['green', 'DONE'],
    queued: ['gray', 'QUEUED'],
    failed: ['red', 'FAILED'],
    await_approval: ['yellow', 'AWAIT APPR'],
  };
  const [tone, label] = map[status] || ['gray', status];
  return <Pill tone={tone}>{label}</Pill>;
}

function Panel({ title, sub, actions, children, className = '', bodyClass = '' }) {
  return (
    <div className={`panel ${className}`}>
      <div className="panel-head">
        <span className="title">{title}</span>
        {sub && <span className="sub">{sub}</span>}
        {actions && <span className="actions">{actions}</span>}
      </div>
      <div className={`panel-body ${bodyClass}`}>{children}</div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  );
}

// ===== rail icons =====
const RailIcons = {
  dashboard: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="2.5" y="2.5" width="6" height="7" rx="1" />
      <rect x="11.5" y="2.5" width="6" height="4" rx="1" />
      <rect x="2.5" y="12.5" width="6" height="5" rx="1" />
      <rect x="11.5" y="9.5" width="6" height="8" rx="1" />
    </svg>
  ),
  trace: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="10" cy="3.5" r="1.5" />
      <line x1="10" y1="5" x2="10" y2="7.5" />
      <line x1="10" y1="7.5" x2="5" y2="7.5" />
      <line x1="10" y1="7.5" x2="15" y2="7.5" />
      <circle cx="5" cy="10" r="1.5" />
      <circle cx="15" cy="10" r="1.5" />
      <line x1="5" y1="11.5" x2="5" y2="13.5" />
      <line x1="15" y1="11.5" x2="15" y2="13.5" />
      <circle cx="5" cy="15" r="1.5" />
      <circle cx="15" cy="15" r="1.5" />
    </svg>
  ),
  chat: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="2" y="3" width="10" height="9" rx="1.5" />
      <rect x="8" y="8" width="10" height="9" rx="1.5" />
    </svg>
  ),
  pair: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="7" cy="7" r="3" />
      <circle cx="14" cy="7" r="2" />
      <path d="M4 17c0-2.2 1.3-4 3-4s3 1.8 3 4" />
      <path d="M14 13c1.1 0 3 1 3 3" />
      <line x1="10" y1="7" x2="12" y2="7" strokeDasharray="1.5 1.5" />
    </svg>
  ),
  notion: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="3" y="2" width="14" height="16" rx="1.5" />
      <line x1="6" y1="6" x2="14" y2="6" />
      <line x1="6" y1="9.5" x2="14" y2="9.5" />
      <line x1="6" y1="13" x2="11" y2="13" />
      <circle cx="14" cy="14" r="2.5" fill="var(--bg)" strokeWidth="1.5" />
      <path d="M13 14h2M14 13v2" strokeWidth="1.2" />
    </svg>
  ),
  interests: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M10 2l2.5 5 5.5.8-4 3.9.9 5.3-4.9-2.6L5.1 18l.9-5.3-4-3.9 5.5-.8z" />
    </svg>
  ),
  caido: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M2 5h16M2 10h16M2 15h16" />
      <circle cx="14" cy="5" r="1.5" fill="currentColor" />
      <circle cx="6" cy="10" r="1.5" fill="currentColor" />
      <circle cx="10" cy="15" r="1.5" fill="currentColor" />
    </svg>
  ),
  rag: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M4 4.5h12M4 9.5h12M4 14.5h12" />
      <circle cx="5.5" cy="4.5" r="1.5" fill="var(--bg)" />
      <circle cx="12" cy="9.5" r="1.5" fill="var(--bg)" />
      <circle cx="8" cy="14.5" r="1.5" fill="var(--bg)" />
      <path d="M7 4.5l3.5 3.8M10.5 10.6l-2 2.7" strokeDasharray="1.5 1.5" />
    </svg>
  ),
};

function Rail({ mode, setMode }) {
  const items = [
    { id: 'dashboard', label: 'OPS',    icon: RailIcons.dashboard },
    { id: 'trace',     label: 'TRACE',  icon: RailIcons.trace },
    { id: 'chat',      label: 'CHAT',   icon: RailIcons.chat },
    { id: 'pair',      label: 'PAIR',   icon: RailIcons.pair },
    { id: 'notion',    label: 'NOTION', icon: RailIcons.notion },
    { id: 'interests', label: 'INTRS',  icon: RailIcons.interests },
    { id: 'caido',     label: 'CAIDO',  icon: RailIcons.caido },
    { id: 'rag',       label: 'RAG',    icon: RailIcons.rag },
  ];
  return (
    <aside className="rail">
      <div className="rail-brand"><span className="rail-brand-glyph">P</span></div>
      {items.map(it => (
        <button key={it.id} className={`rail-btn ${mode === it.id ? 'active' : ''}`} onClick={() => setMode(it.id)}>
          {it.icon}
          <span>{it.label}</span>
        </button>
      ))}
      <div className="rail-spacer"></div>
      <div className="rail-status">
        <div className="rail-pulse"></div>
        LIVE<br/>v0.7.4
      </div>
    </aside>
  );
}

// ===== top bar =====
function TopBar({ crumbs, stats = [] }) {
  const api = window.PD_API || {};
  const uiStatus = window.PD_STATUS || {};
  const busy = !!uiStatus.busy;
  const error = String(uiStatus.error || '');
  return (
    <div className="mode-topbar">
      <div className="crumbs">
        {crumbs.map((c, i) => (
          <React.Fragment key={i}>
            {i > 0 && <span className="sep">/</span>}
            <span className={i === crumbs.length - 1 ? 'crumb' : ''}>{c}</span>
          </React.Fragment>
        ))}
      </div>
      <div className="right">
        <div className="stats">
          {stats.map((s, i) => (
            <span key={i} className="stat">
              <span className="stat-k">{s.k}</span>
              <span className="stat-v mono" title={String(s.v)}>{s.v}</span>
            </span>
          ))}
        </div>
        <div className="topbar-actions">
          {error && <span className="pd-error mono" title={error}>{error}</span>}
          {api.refresh && (
            <button className="btn ghost sm topbar-refresh" onClick={() => api.refresh()} disabled={busy}>
              {busy ? 'WORKING' : 'REFRESH'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// expose
Object.assign(window, { Pill, Dot, StatusPill, Panel, Field, Rail, TopBar });
