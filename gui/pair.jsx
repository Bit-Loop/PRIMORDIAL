/* global React, Panel, Pill, Dot, StatusPill, Field */
const { useState: useStateP, useRef: useRefP, useEffect: useEffectP } = React;

const PHASE_TONE = { active: 'cyan', locked: 'gray', done: 'green', partial: 'yellow' };
const PIN_COLOR = { evidence: 'var(--green)', interest: 'var(--yellow)', artifact: 'var(--violet)', guidance: 'var(--blue)' };
const INTENT_FLAG_KEYS = [
  'public_poc_research',
  'searchsploit_allowed',
  'read_poc_examples',
  'poc_applicability_validation',
  'exploit_code_generation',
  'poc_execution',
  'credential_validation',
  'credential_guessing',
  'credential_spraying',
  'hash_cracking',
  'kerberos_asrep_roast',
  'kerberos_kerberoast',
  'lab_flag_collection',
  'htb_lab_behavior',
  'reverse_shell',
];

function intentFlagsFromPolicy(policy = {}) {
  const kerberos = policy.kerberos_policy || {};
  const credential = policy.credential_policy || {};
  const lab = policy.lab_policy || {};
  const flat = {
    public_poc_research: !!policy.public_poc_research,
    searchsploit_allowed: !!policy.searchsploit_allowed,
    read_poc_examples: !!policy.read_poc_examples,
    poc_applicability_validation: !!policy.poc_applicability_validation,
    exploit_code_generation: !!policy.exploit_code_generation,
    poc_execution: !!policy.poc_execution,
    credential_validation: !!(policy.credential_validation ?? credential.credential_validation_allowed),
    credential_guessing: !!(policy.credential_guessing ?? credential.credential_guessing_allowed),
    credential_spraying: !!(policy.credential_spraying ?? credential.credential_spraying_allowed),
    hash_cracking: !!(policy.hash_cracking ?? credential.hash_cracking_allowed),
    kerberos_asrep_roast: !!(policy.kerberos_asrep_roast ?? kerberos.asrep_roast_check_allowed),
    kerberos_kerberoast: !!(policy.kerberos_kerberoast ?? kerberos.kerberoast_check_allowed),
    lab_flag_collection: !!(policy.lab_flag_collection ?? lab.lab_flag_collection_allowed),
    htb_lab_behavior: !!(policy.htb_lab_behavior ?? lab.htb_lab_behavior_allowed),
    reverse_shell: !!(policy.reverse_shell ?? lab.reverse_shell_allowed),
  };
  return INTENT_FLAG_KEYS.reduce((acc, key) => ({ ...acc, [key]: !!flat[key] }), {});
}

function nonEmptyObject(value) {
  return value && typeof value === 'object' && Object.keys(value).length > 0;
}

function FormattedPairText({ text }) {
  const parts = String(text ?? '').split(/(\*\*[^*]+\*\*|`[^`]+`|\n|→)/g).filter(part => part !== '');
  return (
    <>
      {parts.map((part, index) => {
        if (part === '\n') return <br key={index} />;
        if (part === '→') return <span key={index} style={{ color: 'var(--cyan)' }}>→</span>;
        if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
          return <b key={index} style={{ color: 'var(--txt-hi)' }}>{part.slice(2, -2)}</b>;
        }
        if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
          return <code key={index} style={{ background: 'var(--bg-deep)', padding: '1px 4px', borderRadius: 2, fontSize: 11, color: 'var(--cyan)' }}>{part.slice(1, -1)}</code>;
        }
        return <React.Fragment key={index}>{part}</React.Fragment>;
      })}
    </>
  );
}

function PhaseBar({ phase }) {
  const pct = phase.tasks > 0 ? Math.round((phase.done / phase.tasks) * 100) : 0;
  const tone = PHASE_TONE[phase.status] || 'gray';
  return (
    <div style={{ padding: '7px 8px', borderBottom: '1px solid var(--line)', display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: `var(--${tone})`, boxShadow: phase.status === 'active' ? `0 0 6px var(--${tone})` : 'none', flex: '0 0 8px' }} />
        <span className="strong" style={{ fontFamily: 'var(--mono)', fontSize: 12, flex: 1 }}>{phase.label}</span>
        <Pill tone={tone}>{phase.status.toUpperCase()}</Pill>
      </div>
      {phase.tasks > 0 && (
        <>
          <div className="meter" style={{ height: 3 }}>
            <div className="meter-fill" style={{ width: `${pct}%`, background: `var(--${tone})` }} />
          </div>
          <div className="dim mono" style={{ fontSize: 9.5 }}>{phase.done}/{phase.tasks} tasks · {pct}%</div>
        </>
      )}
    </div>
  );
}

function PinCard({ pin, onUnpin }) {
  const color = PIN_COLOR[pin.kind] || 'var(--txt-mute)';
  return (
    <div style={{
      padding: '8px 10px', border: '1px solid var(--line)', borderLeft: `3px solid ${color}`,
      borderRadius: 'var(--r-2)', background: 'var(--bg-deep)',
      display: 'flex', flexDirection: 'column', gap: 4,
    }}>
      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 9, background: color, color: 'var(--bg-deep)', padding: '1px 5px', borderRadius: 2, fontWeight: 700, textTransform: 'uppercase' }}>{pin.kind}</span>
        <span className="dim mono" style={{ fontSize: 10, flex: 1 }}>{pin.ref}</span>
        <button onClick={onUnpin} className="btn ghost sm" style={{ padding: '1px 5px', fontSize: 9 }}>✕</button>
      </div>
      <div className="strong" style={{ fontSize: 12, fontWeight: 600 }}>{pin.label}</div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span className="dim mono" style={{ fontSize: 10 }}>{pin.target}</span>
        <span className="dim mono" style={{ fontSize: 9.5 }}>pinned {pin.pinned}</span>
      </div>
    </div>
  );
}

function ThinkCard({ ct, onResolve }) {
  const API = window.PD_API || {};
  const [open, setOpen] = useStateP(ct.status === 'open');
  return (
    <div style={{
      padding: '8px 10px', border: '1px solid var(--line)',
      borderLeft: `3px solid ${ct.status === 'open' ? 'var(--yellow)' : 'var(--green)'}`,
      borderRadius: 'var(--r-2)', background: 'var(--bg-deep)',
    }}>
      <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start', cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
        <span style={{ flex: '0 0 12px', marginTop: 1, color: ct.status === 'open' ? 'var(--yellow)' : 'var(--green)', fontFamily: 'var(--mono)', fontSize: 11 }}>{ct.status === 'open' ? '?' : '✓'}</span>
        <span className="strong" style={{ flex: 1, fontSize: 12 }}>{ct.prompt}</span>
        <span className="dim mono" style={{ fontSize: 9 }}>phase:{ct.phase}</span>
      </div>
      {open && (
        <div style={{ marginTop: 8, display: 'flex', gap: 6 }}>
          <button className="btn primary sm" onClick={() => onResolve(ct.id)}>MARK RESOLVED</button>
          <button className="btn ghost sm" onClick={() => API.command?.('ask-about-critical-question', { question_id: ct.id, title: `Ask about ${ct.prompt}` })}>ASK AI →</button>
          <button className="btn ghost sm" onClick={() => API.command?.('pin-critical-question', { question_id: ct.id, title: `Pin ${ct.prompt}` })}>PIN</button>
        </div>
      )}
    </div>
  );
}

function FlagToggle({ k, v, onChange }) {
  const on = !!v;
  return (
    <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', padding: '3px 0' }}>
      <div
        onClick={() => onChange?.(!on)}
        style={{
          width: 28, height: 14, borderRadius: 999,
          background: on ? 'var(--cyan-soft)' : 'var(--elev-1)',
          border: `1px solid ${on ? 'var(--cyan)' : 'var(--line-strong)'}`,
          position: 'relative', transition: '120ms', flex: '0 0 28px',
        }}
      >
        <span style={{
          position: 'absolute', top: 1,
          left: on ? 15 : 1,
          width: 10, height: 10, borderRadius: '50%',
          background: on ? 'var(--cyan)' : 'var(--txt-mute)',
          transition: '120ms',
        }} />
      </div>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: on ? 'var(--txt-strong)' : 'var(--txt-dim)' }}>{k.replace(/_/g, ' ')}</span>
    </label>
  );
}

function PairChat() {
  const API = window.PD_API || {};
  const targetLabel = window.PD_DATA?.traceMeta?.selectedTarget || window.PD_DATA?.scope?.[0]?.handle || 'current target';
  const [msgs, setMsgs] = useStateP([
    { who: 'system', t: new Date().toTimeString().slice(0, 8), text: `Pair session ready · ${targetLabel} · ${window.PD_DATA?.runtime?.intent || 'recon_only'}` },
  ]);
  const [input, setInput] = useStateP('');
  const ref = useRefP(null);

  useEffectP(() => { ref.current?.scrollTo({ top: 1e9, behavior: 'smooth' }); }, [msgs]);

  const send = (txt) => {
    const v = (txt ?? input).trim();
    if (!v) return;
    setInput('');
    const t = new Date().toTimeString().slice(0, 8);
    setMsgs(m => [...m, { who: 'me', t, text: v }]);
    if (API.post) {
      API.post('/api/chat', { message: v })
        .then(payload => {
          const reply = payload?.result?.chat?.answer?.body || 'Runtime chat updated.';
          setMsgs(m => [...m, { who: 'agent', t: new Date().toTimeString().slice(0, 8), text: reply }]);
        })
        .catch(err => setMsgs(m => [...m, { who: 'system', t: new Date().toTimeString().slice(0, 8), text: err.message || String(err) }]));
    } else {
      setMsgs(m => [...m, {
        who: 'system',
        t: new Date().toTimeString().slice(0, 8),
        text: 'Runtime chat API unavailable; no request was sent.',
      }]);
    }
  };

  const suggestions = [
    'what blocks exploitation phase?',
    'what\'s the weakest assumption?',
    'generate next 3 tasks',
    'summarize findings so far',
  ];

  return (
    <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', fontFamily: 'var(--sans)' }}>
      <div ref={ref} style={{ flex: 1, overflow: 'auto', padding: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {msgs.map((m, i) => {
          const cls = m.who === 'me' ? 'me' : m.who === 'system' ? 'system' : 'agent';
          return (
            <div key={i} className={`bubble ${cls}`} style={{ fontSize: 11.5 }}>
              <div className="who">
                <Dot tone={m.who === 'me' ? 'cyan' : m.who === 'system' ? 'yellow' : 'green'} />
                <span>{m.who === 'me' ? 'OPERATOR' : m.who === 'system' ? 'SYSTEM' : 'PAIR AI'}</span>
                <span className="mute" style={{ marginLeft: 'auto' }}>{m.t}</span>
              </div>
              <div className="body"><FormattedPairText text={m.text} /></div>
            </div>
          );
        })}
      </div>
      <div style={{ padding: 8, borderTop: '1px solid var(--line)', background: 'var(--bg-deep)' }}>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 6 }}>
          {suggestions.map(s => (
            <button key={s} className="btn ghost sm" onClick={() => send(s)} style={{ textTransform: 'none', letterSpacing: 0, fontSize: 10 }}>{s}</button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <textarea className="input" rows={2} placeholder="Ask about methodology, evidence, or next steps…"
            value={input} onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); send(); } }}
            style={{ resize: 'none', flex: 1, fontSize: 11.5 }} />
          <button className="btn primary sm" onClick={() => send()}>SEND<span style={{ fontSize: 9, opacity: 0.7, marginLeft: 4 }}>⌘↵</span></button>
        </div>
      </div>
    </div>
  );
}

function PlanMode() {
  const D = window.PD_DATA.plan;
  const API = window.PD_API || {};
  const root = window.PD_DATA || {};
  const targetLabel = root.traceMeta?.selectedTarget || root.scope?.[0]?.handle || 'All targets';
  const activeIntent = root.runtime?.operatorIntent?.active || {};
  const sourceIntentPolicy = nonEmptyObject(D.intent?.flags)
    ? D.intent.flags
    : nonEmptyObject(D.intent?.policy)
      ? D.intent.policy
      : activeIntent.policy || {};
  const sourceIntentFlags = intentFlagsFromPolicy(sourceIntentPolicy);
  const sourceIntentSignature = JSON.stringify(sourceIntentFlags);
  const [pinned, setPinned] = useStateP(D.pinnedAssets);
  const [thinks, setThinks] = useStateP(D.criticalThinking);
  const [sub, setSub] = useStateP('workspace');
  const [intentFlags, setIntentFlags] = useStateP(sourceIntentFlags);
  const [intentDraftDirty, setIntentDraftDirty] = useStateP(false);

  const resolveThink = (id) => setThinks(ts => ts.map(t => t.id === id ? { ...t, status: 'resolved' } : t));
  const unpin = (id) => setPinned(ps => ps.filter(p => p.id !== id));
  const updateIntentFlag = (key, value) => {
    setIntentDraftDirty(true);
    setIntentFlags(flags => ({ ...flags, [key]: !!value }));
  };
  const resetIntentDraft = () => {
    setIntentFlags(sourceIntentFlags);
    setIntentDraftDirty(false);
  };

  useEffectP(() => {
    if (!intentDraftDirty) setIntentFlags(sourceIntentFlags);
  }, [sourceIntentSignature, D.intent?.id, activeIntent.id, intentDraftDirty]);

  const openCount = thinks.filter(t => t.status === 'open').length;

  return (
    <>
      <window.TopBar
        crumbs={['primordial', 'pair', sub]}
        stats={[
          { k: 'phase', v: D.methodology.phases.find(p => p.status === 'active')?.label || '—' },
          { k: 'pinned', v: pinned.length },
          { k: 'open qs', v: openCount },
          { k: 'autonomy', v: D.autonomy },
        ]}
      />
      <div className="subtabs">
        {[
          ['workspace', '⊞ WORKSPACE'],
          ['methodology', '◎ METHODOLOGY'],
          ['intent', '▷ INTENT FLAGS'],
          ['skills', '⌥ SKILLS'],
        ].map(([id, label]) => (
          <button key={id} className={`subtab ${sub === id ? 'active' : ''}`} onClick={() => setSub(id)}>{label}</button>
        ))}
        <div style={{ flex: 1 }} />
        <span className="dim mono" style={{ fontSize: 10.5, paddingRight: 8 }}>{targetLabel} · {D.methodology.label}</span>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: 'hidden', display: 'flex' }}>

        {/* ---- WORKSPACE ---- */}
        {sub === 'workspace' && (
          <>
            {/* left: methodology sidebar */}
            <aside style={{ width: 220, flex: '0 0 220px', borderRight: '1px solid var(--line)', display: 'flex', flexDirection: 'column', background: 'var(--bg-deep)', overflow: 'auto' }}>
              <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--line)' }}>
                <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>METHODOLOGY PHASES</div>
                {D.methodology.phases.map(ph => <PhaseBar key={ph.id} phase={ph} />)}
              </div>
              <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--line)' }}>
                <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>PLAYBOOKS</div>
                {D.playbooks.map(pb => (
                  <div key={pb.id} style={{ padding: '6px 8px', marginBottom: 4, border: '1px solid var(--line)', borderRadius: 'var(--r-2)', background: 'var(--bg)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                      <span className="strong" style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{pb.label}</span>
                      <Pill tone={pb.status === 'active' ? 'cyan' : 'gray'}>{pb.status.toUpperCase()}</Pill>
                    </div>
                    <div className="dim" style={{ fontSize: 10.5 }}>{pb.desc}</div>
                    <div style={{ marginTop: 5, display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                      {pb.tasks.map(t => <span key={t} style={{ fontFamily: 'var(--mono)', fontSize: 9, background: 'var(--elev-1)', color: 'var(--txt-mute)', padding: '1px 4px', borderRadius: 2, border: '1px solid var(--line)' }}>{t}</span>)}
                    </div>
                  </div>
                ))}
              </div>
              <div style={{ padding: '8px 10px' }}>
                <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 6 }}>SKILLS</div>
                {D.skills.map(sk => (
                  <div key={sk.id} style={{ padding: '6px 8px', marginBottom: 4, border: '1px solid var(--line)', borderRadius: 'var(--r-2)', background: 'var(--bg)' }}>
                    <div className="strong" style={{ fontFamily: 'var(--mono)', fontSize: 11, marginBottom: 3 }}>{sk.title}</div>
                    <div className="dim" style={{ fontSize: 10.5 }}>{sk.summary}</div>
                    <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginTop: 4 }}>
                      {sk.tags.map(t => <span key={t} style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--cyan)', background: 'var(--cyan-soft)', padding: '1px 4px', borderRadius: 2, border: '1px solid var(--cyan)' }}>{t}</span>)}
                    </div>
                  </div>
                ))}
              </div>
            </aside>

            {/* center: pinned workspace + critical thinking */}
            <div style={{ flex: 1, minWidth: 0, overflow: 'auto', padding: 10, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div className="upper" style={{ color: 'var(--txt-mute)' }}>PINNED WORKSPACE</div>
                <span className="dim mono" style={{ fontSize: 10 }}>{pinned.length} items</span>
                <button className="btn ghost sm" style={{ marginLeft: 'auto' }} onClick={() => API.command?.('pin-workspace-item', { target: targetLabel, title: 'Pin workspace item' })}>+ PIN ITEM</button>
              </div>
              {pinned.length === 0 ? (
                <div style={{ padding: 24, textAlign: 'center', color: 'var(--txt-mute)', fontFamily: 'var(--mono)', fontSize: 12, border: '1px dashed var(--line)', borderRadius: 'var(--r-2)' }}>
                  No pinned items. Pin evidence, interests, artifacts, or guidance from other tabs.
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 8 }}>
                  {pinned.map(p => <PinCard key={p.id} pin={p} onUnpin={() => unpin(p.id)} />)}
                </div>
              )}

              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                <div className="upper" style={{ color: 'var(--txt-mute)' }}>CRITICAL THINKING</div>
                <Pill tone="yellow">{openCount} OPEN</Pill>
                <button className="btn ghost sm" style={{ marginLeft: 'auto' }} onClick={() => API.command?.('add-critical-question', { target: targetLabel, title: 'Add critical thinking question' })}>+ ADD QUESTION</button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {thinks.map(ct => <ThinkCard key={ct.id} ct={ct} onResolve={resolveThink} />)}
              </div>
            </div>

            {/* right: pair AI */}
            <aside style={{ width: 300, flex: '0 0 300px', borderLeft: '1px solid var(--line)', display: 'flex', flexDirection: 'column', background: 'var(--bg)' }}>
              <div style={{ padding: '7px 10px', borderBottom: '1px solid var(--line)', background: 'linear-gradient(180deg, var(--elev-1), var(--bg))', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Dot tone="green" />
                <span className="upper" style={{ fontSize: 10, fontWeight: 600, color: 'var(--txt-strong)' }}>PAIR ASSIST</span>
                <span className="dim mono" style={{ fontSize: 9.5, marginLeft: 4 }}>local-deep · deepseek-r1</span>
              </div>
              <PairChat />
            </aside>
          </>
        )}

        {/* ---- METHODOLOGY ---- */}
        {sub === 'methodology' && (
          <div style={{ flex: 1, overflow: 'auto', padding: 10, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
              {D.methodology.phases.map((ph, i) => {
                const tone = PHASE_TONE[ph.status] || 'gray';
                const pct = ph.tasks > 0 ? Math.round((ph.done / ph.tasks) * 100) : 0;
                return (
                  <div key={ph.id} style={{ padding: '14px 14px 12px', border: `1px solid var(--${tone === 'gray' ? 'line' : tone})`, borderRadius: 'var(--r-2)', background: 'var(--bg-deep)', display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span className="dim mono" style={{ fontSize: 10 }}>{i + 1}.</span>
                      <span className="strong" style={{ fontFamily: 'var(--mono)', fontSize: 14, flex: 1 }}>{ph.label}</span>
                      <Pill tone={tone}>{ph.status.toUpperCase()}</Pill>
                    </div>
                    {ph.tasks > 0 ? (
                      <>
                        <div className="meter"><div className="meter-fill" style={{ width: `${pct}%`, background: `var(--${tone})` }} /></div>
                        <div className="dim mono" style={{ fontSize: 10 }}>{ph.done} / {ph.tasks} tasks complete</div>
                      </>
                    ) : (
                      <div className="dim mono" style={{ fontSize: 10 }}>locked · entry conditions unmet</div>
                    )}
                    {ph.status !== 'locked' && (
                      <button className="btn ghost sm" style={{ marginTop: 4 }} onClick={() => API.command?.('view-phase-tasks', { target: targetLabel, phase: ph.id, title: `View ${ph.label} tasks` })}>VIEW TASKS</button>
                    )}
                  </div>
                );
              })}
            </div>
            <Panel title="PHASE TRANSITION CONDITIONS">
              <div style={{ padding: 10, fontFamily: 'var(--mono)', fontSize: 11, display: 'flex', flexDirection: 'column', gap: 10 }}>
                {[
                  { from: 'Recon', to: 'Analysis', status: 'partial', conditions: ['TCP scan complete (✓)', 'DNS enum complete (✓)', 'At least 1 attack surface identified (✓)', 'All services fingerprinted (✗ 3 remaining)'] },
                  { from: 'Analysis', to: 'Exploitation', status: 'locked', conditions: ['Viable vulnerability identified', 'Evidence chain established', 'Behavior verifier sign-off', 'Operator approval required'] },
                ].map(tr => (
                  <div key={tr.from} style={{ padding: '8px 10px', border: '1px solid var(--line)', borderRadius: 'var(--r-2)' }}>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ color: 'var(--cyan)' }}>{tr.from}</span>
                      <span className="dim">→</span>
                      <span style={{ color: 'var(--txt-strong)' }}>{tr.to}</span>
                      <Pill tone={tr.status === 'partial' ? 'yellow' : 'gray'} style={{ marginLeft: 'auto' }}>{tr.status.toUpperCase()}</Pill>
                    </div>
                    {tr.conditions.map((c, i) => (
                      <div key={i} style={{ display: 'flex', gap: 6, color: c.includes('✓') ? 'var(--green)' : c.includes('✗') ? 'var(--red)' : 'var(--txt-mute)', marginBottom: 2 }}>
                        <span>{c.includes('✓') ? '✓' : c.includes('✗') ? '✗' : '·'}</span>
                        <span>{c.replace(/\s*\(✓\)|\s*\(✗\)/g, '')}</span>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        )}

        {/* ---- INTENT FLAGS ---- */}
        {sub === 'intent' && (
          <div style={{ flex: 1, overflow: 'auto', padding: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, fontFamily: 'var(--mono)', fontSize: 11 }}>
              <Pill tone={D.intent?.id === 'htb_lab' ? 'green' : 'cyan'}>{(D.intent?.id || 'recon_only').toUpperCase()}</Pill>
              <span className="dim">{D.intent?.label || activeIntent.label || 'Operator Intent'}</span>
              {intentDraftDirty && <Pill tone="yellow">DRAFT</Pill>}
              <div style={{ flex: 1 }} />
              <button className="btn ghost sm" onClick={resetIntentDraft} disabled={!intentDraftDirty}>RESET</button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
              {[
                { group: 'Recon & Research', flags: ['public_poc_research','searchsploit_allowed','read_poc_examples','poc_applicability_validation'] },
                { group: 'Exploitation', flags: ['exploit_code_generation','poc_execution','credential_validation','credential_guessing','credential_spraying','hash_cracking'] },
                { group: 'Active Directory', flags: ['kerberos_asrep_roast','kerberos_kerberoast'] },
                { group: 'HTB Specific', flags: ['lab_flag_collection','htb_lab_behavior','reverse_shell'] },
              ].map(grp => (
                <div key={grp.group} style={{ padding: '10px 12px', border: '1px solid var(--line)', borderRadius: 'var(--r-2)', background: 'var(--bg-deep)' }}>
                  <div className="upper" style={{ color: 'var(--txt-mute)', marginBottom: 8 }}>{grp.group}</div>
                  {grp.flags.map(k => (
                    <FlagToggle key={k} k={k} v={!!intentFlags[k]} onChange={value => updateIntentFlag(k, value)} />
                  ))}
                </div>
              ))}
            </div>
            <div style={{ marginTop: 10 }}>
              <div style={{ padding: '8px 10px', background: 'var(--green-soft)', border: '1px solid var(--green)', borderRadius: 'var(--r-2)', fontFamily: 'var(--mono)', fontSize: 11, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Dot tone="green" />
                POLICY: DDoS forbidden · PoC exec gated · Scope: {targetLabel}
              </div>
            </div>
          </div>
        )}

        {/* ---- SKILLS ---- */}
        {sub === 'skills' && (
          <div style={{ flex: 1, overflow: 'auto', padding: 10, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <Panel title="AVAILABLE SKILLS" sub={`${D.skills.length} registered`}>
              {D.skills.map(sk => (
                <div key={sk.id} style={{ padding: '10px 12px', borderBottom: '1px solid var(--line)', display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                  <div style={{ flex: 1 }}>
                    <div className="strong" style={{ fontSize: 13, marginBottom: 3 }}>{sk.title}</div>
                    <div className="dim" style={{ fontSize: 11.5 }}>{sk.summary}</div>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 6 }}>
                      {sk.tags.map(t => <span key={t} style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--cyan)', background: 'var(--cyan-soft)', padding: '1px 5px', borderRadius: 2, border: '1px solid var(--cyan)' }}>{t}</span>)}
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <button className="btn primary sm" onClick={() => API.command?.('run-skill', { skill_id: sk.id, target: targetLabel, title: `Run skill ${sk.title}` })}>RUN</button>
                    <button className="btn ghost sm" onClick={() => API.command?.('skill-detail', { skill_id: sk.id, target: targetLabel, title: `Skill detail ${sk.title}` })}>DETAIL</button>
                  </div>
                </div>
              ))}
            </Panel>
          </div>
        )}

      </div>
    </>
  );
}

window.PlanMode = PlanMode;
