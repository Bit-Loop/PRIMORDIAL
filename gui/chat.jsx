/* global React, Panel, Pill, Dot */
const { useState: useStateC, useRef: useRefC, useEffect: useEffectC } = React;

function FormattedChatText({ text }) {
  const parts = String(text ?? '').split(/(\*\*[^*]+\*\*|`[^`]+`|\n)/g).filter(part => part !== '');
  return (
    <>
      {parts.map((part, index) => {
        if (part === '\n') return <br key={index} />;
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

function ChatBubble({ msg }) {
  const cls = msg.who === 'me' ? 'me' : msg.who === 'system' ? 'system' : 'agent';
  const label = msg.who === 'me' ? 'OPERATOR' : msg.who === 'agent' ? 'AGENT · local-deep' : 'SYSTEM';
  const dot = msg.who === 'me' ? 'cyan' : msg.who === 'system' ? 'yellow' : 'green';
  return (
    <div className={`bubble ${cls}`}>
      <div className="who">
        <Dot tone={dot} />
        <span>{label}</span>
        <span className="mute" style={{ marginLeft: 'auto' }}>{msg.t}</span>
      </div>
      <div className="body"><FormattedChatText text={msg.text} /></div>
      {msg.attachments && (
        <div className="row gap-4" style={{ marginTop: 6, flexWrap: 'wrap' }}>
          {msg.attachments.map((a, i) => (
            <Pill key={i} tone="cyan">📎 {a}</Pill>
          ))}
        </div>
      )}
    </div>
  );
}

function ApprovalPaneInChat({ approval, onResolve }) {
  if (!approval) return null;
  return (
    <div className={`approval ${approval.risk}`} style={{ marginBottom: 10 }}>
      <div className="approval-head">
        <Pill tone={approval.risk === 'high' ? 'red' : approval.risk === 'med' ? 'yellow' : 'blue'}>{approval.risk.toUpperCase()}</Pill>
        <span className="approval-title">{approval.title}</span>
        <span className="approval-meta" style={{ marginLeft: 'auto' }}>{approval.id} · {approval.task}</span>
      </div>
      <div className="approval-meta">{approval.target} · {approval.primitive} · {approval.limits}</div>
      <div style={{ color: 'var(--txt)', fontSize: 11.5 }}>{approval.detail}</div>
      <div className="dim" style={{ fontSize: 11, fontStyle: 'italic' }}>{approval.reason}</div>
    </div>
  );
}

function ChatPane({ title, kind, messages, setMessages, approval, model, onResolve, onSend, targetLabel }) {
  const API = window.PD_API || {};
  const [input, setInput] = useStateC('');
  const scrollRef = useRefC(null);

  useEffectC(() => {
    scrollRef.current?.scrollTo({ top: 1e9, behavior: 'smooth' });
  }, [messages]);

  const send = (text) => {
    const v = (text ?? input).trim();
    if (!v) return;
    const t = new Date().toTimeString().slice(0, 8);
    const next = [...messages, { who: 'me', t, text: v }];
    setMessages(next);
    setInput('');
    if (onSend) {
      onSend(v)
        .then(reply => {
          if (!reply) return;
          setMessages(m => [...m, { who: 'agent', t: new Date().toTimeString().slice(0, 8), text: reply }]);
        })
        .catch(err => {
          setMessages(m => [...m, { who: 'system', t: new Date().toTimeString().slice(0, 8), text: err.message || String(err) }]);
        });
      return;
    }
    setMessages(m => [...m, {
      who: 'system',
      t: new Date().toTimeString().slice(0, 8),
      text: 'No chat handler is available; no request was sent.',
    }]);
  };

  const suggestions = kind === 'approval' ? [
    'show me the exact request',
    'reduce scope: only check banner',
    'what evidence backs this?',
    'reject with reason: too noisy',
  ] : [
    `summarize ${targetLabel}`,
    'next 3 scoped recon steps',
    'compact memory now',
    'why did the latest task fail?',
  ];

  return (
    <div className="panel fill" style={{ minHeight: 0 }}>
      <div className="panel-head">
        <span className="title">{title}</span>
        <span className="sub mono">· {model}</span>
        <span className="actions">
          {kind === 'approval' && approval && (
            <>
              <button className="btn primary sm" onClick={() => onResolve?.('approve')}>✓ APPROVE</button>
              <button className="btn danger sm" onClick={() => onResolve?.('reject')}>✗ REJECT</button>
            </>
          )}
          <button className="btn ghost sm" onClick={() => setMessages([])}>CLEAR</button>
        </span>
      </div>
      <div className="panel-body" ref={scrollRef} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {kind === 'approval' && <ApprovalPaneInChat approval={approval} onResolve={onResolve} />}
        {messages.map((m, i) => <ChatBubble key={i} msg={m} />)}
      </div>
      <div style={{ padding: 8, borderTop: '1px solid var(--line)', background: 'var(--bg-deep)' }}>
        <div className="row gap-4" style={{ flexWrap: 'wrap', marginBottom: 6 }}>
          {suggestions.map(s => (
            <button key={s} className="btn ghost sm" onClick={() => send(s)} style={{ textTransform: 'none', letterSpacing: 0 }}>
              {s}
            </button>
          ))}
        </div>
        <div className="row gap-6">
          <textarea
            className="input"
            rows={2}
            placeholder={kind === 'approval'
              ? 'Discuss with the blocked agent. Modify scope. Then APPROVE or REJECT.'
              : 'Ask anything about runtime, evidence, targets, or methodology.'}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); send(); }
            }}
            style={{ resize: 'none', fontFamily: 'var(--sans)', fontSize: 12.5 }}
          />
          <div className="col gap-4" style={{ flex: '0 0 auto' }}>
            <button className="btn primary sm" onClick={() => send()} title="⌘+Enter">
              SEND
              <span style={{ fontSize: 9, opacity: 0.7, marginLeft: 4 }}>⌘↵</span>
            </button>
            <button className="btn ghost sm" onClick={() => API.command?.('attach-chat-context', { target: targetLabel, title: `Attach context to ${title}` })}>📎</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ChatMode() {
  const D = window.PD_DATA;
  const API = window.PD_API || {};
  const [approvalChat, setApprovalChat] = useStateC(D.approvalChat);
  const [inquiryChat, setInquiryChat] = useStateC(D.inquiryChat);
  const [activeAp, setActiveAp] = useStateC(D.approvals[0]);
  const [resolved, setResolved] = useStateC({});
  const [layout, setLayout] = useStateC('split'); // split | approval-focus | inquiry-focus

  useEffectC(() => {
    setApprovalChat(D.approvalChat);
    setInquiryChat(D.inquiryChat);
    setActiveAp(current => current && D.approvals.find(a => a.id === current.id) ? current : D.approvals[0]);
    setResolved({});
  }, [D.approvalChat, D.inquiryChat, D.approvals]);

  const resolveApproval = (verdict) => {
    if (!activeAp) return;
    setResolved(r => ({ ...r, [activeAp.id]: verdict }));
    const t = new Date().toTimeString().slice(0, 8);
    setApprovalChat(m => [...m, {
      who: 'system', t,
      text: verdict === 'approve'
        ? `✓ APPROVED · ${activeAp.id} released to runtime. Task ${activeAp.task} resumed under bounded limits.`
        : `✗ REJECTED · ${activeAp.id} blocked. Verifier will record reason and avoid the same path.`
    }]);
    const endpoint = verdict === 'approve' ? '/api/actions/approve' : '/api/actions/deny';
    API.post?.(endpoint, { task_id: activeAp.task || activeAp.id }).catch(err => {
      setApprovalChat(m => [...m, { who: 'system', t: new Date().toTimeString().slice(0, 8), text: err.message || String(err) }]);
    });
    // advance to next pending approval
    const remaining = D.approvals.filter(a => !resolved[a.id] && a.id !== activeAp.id);
    if (remaining.length) setActiveAp(remaining[0]); else setActiveAp(null);
  };

  // Dynamic target for suggestions and grounded inquiry routing.
  const activeTarget = activeAp?.target && activeAp.target !== '*'
    ? activeAp.target
    : (D.traceMeta?.selectedTarget || D.scope?.[0]?.handle || 'current');

  const askRuntime = async (message) => {
    const request = { message };
    if (activeTarget && activeTarget !== 'current' && activeTarget !== 'All targets') {
      request.target = activeTarget;
    }
    const payload = await API.post?.('/api/chat', request);
    let answer = payload?.result?.chat?.answer?.body || payload?.result?.chat?.error;
    // If answer is a string that looks like JSON, try to extract readable format
    if (typeof answer === 'string' && answer.startsWith('{')) {
      try {
        const json = JSON.parse(answer);
        // If it has expected fields, extract readable content
        if (json.body) answer = json.body;
        else if (json.text) answer = json.text;
        else if (json.response) answer = json.response;
      } catch (e) {
        // Not JSON or parse failed, use as-is
      }
    }
    return answer || 'Runtime chat updated.';
  };

  const queue = D.approvals.filter(a => !resolved[a.id]);

  return (
    <>
      <window.TopBar
        crumbs={['primordial', 'chat']}
        stats={[
          { k: 'pending appr', v: queue.length },
          { k: 'approval lane', v: 'local-deep' },
          { k: 'inquiry lane', v: 'local-deep' },
          { k: 'context', v: activeTarget },
        ]}
      />
      <div style={{ flex: 1, minHeight: 0, display: 'flex', gap: 8, padding: 8 }}>
        {/* approvals queue rail */}
        <aside style={{ flex: '0 0 240px', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          <Panel title="Approval Queue" sub={`${queue.length} pending`} className="fill" bodyClass="tight">
            <div className="col">
              {D.approvals.map(a => {
                const r = resolved[a.id];
                const active = activeAp?.id === a.id;
                return (
                  <button
                    key={a.id}
                    onClick={() => setActiveAp(a)}
                    style={{
                      textAlign: 'left',
                      background: active ? 'var(--cyan-soft)' : 'transparent',
                      border: 0, borderLeft: `3px solid ${active ? 'var(--cyan)' : 'transparent'}`,
                      borderBottom: '1px solid var(--line)',
                      padding: '8px 10px',
                      color: 'var(--txt)',
                      cursor: 'pointer',
                      display: 'flex', flexDirection: 'column', gap: 4,
                    }}
                  >
                    <div className="row gap-4" style={{ alignItems: 'center' }}>
                      <Pill tone={a.risk === 'high' ? 'red' : a.risk === 'med' ? 'yellow' : 'blue'}>{a.risk.toUpperCase()}</Pill>
                      {r === 'approve' && <Pill tone="green">✓</Pill>}
                      {r === 'reject' && <Pill tone="red">✗</Pill>}
                      <span className="dim mono" style={{ marginLeft: 'auto', fontSize: 10 }}>{a.id}</span>
                    </div>
                    <div className="strong" style={{ fontSize: 12, fontWeight: 600 }}>{a.title}</div>
                    <div className="dim mono" style={{ fontSize: 10 }}>{a.target} · {a.primitive}</div>
                  </button>
                );
              })}
            </div>
          </Panel>
          <div style={{ marginTop: 8, padding: '8px 10px', background: 'var(--bg)', border: '1px solid var(--line)', borderRadius: 4, fontFamily: 'var(--mono)', fontSize: 10.5 }}>
            <div className="upper" style={{ marginBottom: 4 }}>POLICY</div>
            <div className="dim">PoC exec: gated</div>
            <div className="dim">DDoS: forbidden</div>
            <div className="dim">Out of scope: blocked</div>
            <div className="dim">Premium AI: disabled</div>
          </div>
        </aside>

        {/* dual chat */}
        <div className="row fill" style={{ gap: 8, minHeight: 0 }}>
          {layout !== 'inquiry-focus' && (
            <div className="col fill" style={{ flex: layout === 'approval-focus' ? 2 : 1, minHeight: 0 }}>
              <div className="row gap-6" style={{ marginBottom: 6, alignItems: 'center' }}>
                <span className="upper">▌ AGENT BLOCKING / APPROVAL</span>
                <span className="dim mono" style={{ fontSize: 10 }}>chat with the agent that's holding for approval</span>
                <span style={{ marginLeft: 'auto' }}>
                  <button className="btn ghost sm" onClick={() => setLayout(l => l === 'approval-focus' ? 'split' : 'approval-focus')}>{layout === 'approval-focus' ? 'SPLIT' : 'FOCUS'}</button>
                </span>
              </div>
              <ChatPane
                title="Agent · Approval Lane"
                kind="approval"
                messages={approvalChat}
                setMessages={setApprovalChat}
                approval={activeAp}
                model="local-deep · deepseek-r1:8b"
                onResolve={resolveApproval}
                onSend={async (message) => `Approval note recorded locally: ${message}`}
                targetLabel={activeAp?.target && activeAp.target !== '*' ? activeAp.target : 'approval'}
              />
            </div>
          )}
          {layout !== 'approval-focus' && (
            <div className="col fill" style={{ flex: layout === 'inquiry-focus' ? 2 : 1, minHeight: 0 }}>
              <div className="row gap-6" style={{ marginBottom: 6, alignItems: 'center' }}>
                <span className="upper">▌ GENERAL INQUIRY</span>
                <span className="dim mono" style={{ fontSize: 10 }}>ask about runtime, evidence, targets — bounded Q&amp;A</span>
                <span style={{ marginLeft: 'auto' }}>
                  <button className="btn ghost sm" onClick={() => setLayout(l => l === 'inquiry-focus' ? 'split' : 'inquiry-focus')}>{layout === 'inquiry-focus' ? 'SPLIT' : 'FOCUS'}</button>
                </span>
              </div>
              <ChatPane
                title="Operator AI · Inquiry"
                kind="inquiry"
                messages={inquiryChat}
                setMessages={setInquiryChat}
                approval={null}
                model="local-deep · deepseek-r1:8b"
                onSend={askRuntime}
                targetLabel={activeTarget}
              />
            </div>
          )}
        </div>
      </div>
    </>
  );
}

window.ChatMode = ChatMode;
