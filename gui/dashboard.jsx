/* global React, Panel, Pill, Dot, StatusPill, Field */
const { useState: useStateD, useEffect: useEffectD } = React;
const CAIDO_DEFAULT_GRAPHQL_URL = 'http://127.0.0.1:8650/graphql';

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

function clampMetric(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(1, numeric));
}

function runtimeNumber(value, fallback = 0) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function RuntimeTile({ label, value, detail, tone = '' }) {
  return (
    <div className={`runtime-tile ${tone}`}>
      <span className="runtime-tile-label">{label}</span>
      <span className="runtime-tile-value">{value}</span>
      {detail && <span className="runtime-tile-detail">{detail}</span>}
    </div>
  );
}

function RuntimeHint({ children }) {
  return <span className="runtime-hint">{children}</span>;
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
  const [credentialFeedback, setCredentialFeedback] = useStateD(null);
  const [integrationSelected, setIntegrationSelected] = useStateD('discord');
  const [selectedCredentialKey, setSelectedCredentialKey] = useStateD('');
  const [modelDraft, setModelDraft] = useStateD({});
  const [processorDraft, setProcessorDraft] = useStateD({});
  const [wrapperOnlyDraft, setWrapperOnlyDraft] = useStateD(!!D.modelPayload?.wrapper_mode?.use_only_wrapper);
  const [wrapperPresetDraft, setWrapperPresetDraft] = useStateD(D.modelPayload?.wrapper_mode?.preset || 'claude_sonnet');
  const [wrapperDraftDirty, setWrapperDraftDirty] = useStateD(false);
  const [targetDraft, setTargetDraft] = useStateD({});
  const [targetAdvancedOpen, setTargetAdvancedOpen] = useStateD(false);
  const [targetFeedback, setTargetFeedback] = useStateD(null);
  const [targetSaving, setTargetSaving] = useStateD(false);
  const [approvalBusy, setApprovalBusy] = useStateD('');
  const [approvalFeedback, setApprovalFeedback] = useStateD(null);
  const [runtimeBusy, setRuntimeBusy] = useStateD('');
  const [runtimeFeedback, setRuntimeFeedback] = useStateD(null);
  const [runtimeDraftDirty, setRuntimeDraftDirty] = useStateD(false);
  const [tuningDraftDirty, setTuningDraftDirty] = useStateD(false);
  const [caidoHealthBusy, setCaidoHealthBusy] = useStateD(false);
  const [scopeImport, setScopeImport] = useStateD('{\n  "targets": []\n}');
  const [selfTest, setSelfTest] = useStateD(D.selfTest || null);

  useEffectD(() => {
    setAutonomy(D.runtime.autonomy);
    if (!runtimeDraftDirty) {
      setIntent(D.runtime.intent);
      setContMode(D.runtime.executionMode?.mode === 'continuous');
      setInterval(D.runtime.executionMode?.interval_seconds || 30);
    }
    if (!tuningDraftDirty) {
      setTuning(D.runtime.runtimeTuning || {});
    }
    if (!wrapperDraftDirty) {
      setWrapperOnlyDraft(!!D.modelPayload?.wrapper_mode?.use_only_wrapper);
      setWrapperPresetDraft(D.modelPayload?.wrapper_mode?.preset || 'claude_sonnet');
    }
  }, [
    D.runtime.autonomy,
    D.runtime.intent,
    D.runtime.executionMode?.mode,
    D.runtime.executionMode?.interval_seconds,
    D.runtime.runtimeTuning,
    D.modelPayload?.wrapper_mode?.use_only_wrapper,
    D.modelPayload?.wrapper_mode?.preset,
    runtimeDraftDirty,
    tuningDraftDirty,
    wrapperDraftDirty,
  ]);

  const cpu = D.runtime.cpu;
  const gpu = D.runtime.gpu;
  const mem = D.runtime.mem;
  const countsPayload = D.runtime.counts || {};

  const [sparks, setSparks] = useStateD(() => ({
    cpu: Array.from({ length: 24 }, () => clampMetric(cpu)),
    gpu: Array.from({ length: 24 }, () => clampMetric(gpu)),
    mem: Array.from({ length: 24 }, () => clampMetric(mem)),
  }));
  useEffectD(() => {
    setSparks(previous => ({
      cpu: [...(previous.cpu || []), clampMetric(cpu)].slice(-24),
      gpu: [...(previous.gpu || []), clampMetric(gpu)].slice(-24),
      mem: [...(previous.mem || []), clampMetric(mem)].slice(-24),
    }));
  }, [cpu, gpu, mem]);

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
  const activeIntent = D.runtime.operatorIntent?.active || {};
  const intentLabel = activeIntent.label || activeIntent.id || intent;
  const workStatus = D.runtime.workStatus || {};
  const workCounts = workStatus.counts || {};
  const activeWork = runtimeNumber(workCounts.active, D.runtime.activeTasks || 0);
  const queuedWork = runtimeNumber(workCounts.queued, D.runtime.queued || 0);
  const waitingWork = runtimeNumber(workCounts.waiting, 0);
  const webActionCount = runtimeNumber(workCounts.web_actions, (workStatus.web_actions || []).length);
  const staleWebActionCount = runtimeNumber(workCounts.stale_web_actions, 0);
  const premiumWrapper = D.runtime.premiumWrapper || {};
  const premiumWrapperAvailable = !!premiumWrapper.local_wrapper_available;
  const premiumWrapperTone = premiumWrapper.tone || (premiumWrapperAvailable ? 'cyan' : premiumWrapper.remote_premium_flag_enabled ? 'green' : 'gray');
  const premiumWrapperStatus = premiumWrapper.status || (premiumWrapperAvailable ? 'local wrapper' : 'disabled');
  const premiumWrapperLabel = premiumWrapper.label
    || (premiumWrapper.local_chat_wrapper === 'agent_chat_api' ? 'agent_chat_api wrapper' : '')
    || premiumWrapper.local_chat_wrapper
    || 'remote_premium';
  const executionMode = contMode ? 'continuous' : 'tick';
  const persistedExecutionMode = D.runtime.executionMode?.mode || 'tick';
  const persistedContinuous = persistedExecutionMode === 'continuous';
  const runtimeTone = activeWork ? 'cyan' : waitingWork ? 'yellow' : queuedWork ? 'gray' : 'green';
  const runtimeStatus = activeWork ? 'working' : waitingWork ? 'waiting' : queuedWork ? 'queued' : 'idle';
  const blockerRows = (Array.isArray(workStatus.blockers) ? workStatus.blockers : [])
    .map(item => ({
      summary: item.summary || item.reason || item.code || 'Runtime blocker',
      detail: item.detail || item.target || '',
    }))
    .concat((Array.isArray(workStatus.waiting) ? workStatus.waiting : []).map(item => ({
      summary: item.title || item.summary || 'Waiting task',
      detail: item.target || item.status || '',
    })))
    .slice(0, 4);
  const policy = activeIntent.policy && typeof activeIntent.policy === 'object' ? activeIntent.policy : {};
  const policyFlags = Object.entries(policy)
    .filter(([, value]) => value === true)
    .map(([key]) => key.replaceAll('_', ' '))
    .slice(0, 3);
  const tuningDefaults = tuning.defaults || D.runtime.runtimeTuning?.defaults || {};
  const tuningMinimums = tuning.minimums || D.runtime.runtimeTuning?.minimums || {};
  const updateTuning = (key, value) => {
    setTuningDraftDirty(true);
    setTuning(t => ({ ...t, [key]: Number(value) || 0 }));
  };
  const updateIntentDraft = (value) => {
    setRuntimeDraftDirty(true);
    setIntent(value);
  };
  const updateExecutionModeDraft = (value) => {
    setRuntimeDraftDirty(true);
    setContMode(value === 'cont');
  };
  const updateIntervalDraft = (value) => {
    setRuntimeDraftDirty(true);
    setInterval(Math.max(2, Number(value) || 2));
  };
  const modelRoles = D.modelPayload?.roles || [];
  const availableModels = D.modelPayload?.available_models || [];
  const wrapperMode = D.modelPayload?.wrapper_mode || {};
  const wrapperPresetOptions = (wrapperMode.presets || []).length
    ? wrapperMode.presets
    : [
        { id: 'claude_sonnet', label: 'Claude Sonnet', provider: 'claude', model: 'sonnet', effort: null },
        { id: 'codex_gpt55_high', label: 'GPT 5.5 High', provider: 'codex', model: 'gpt-5.5', effort: 'high' },
      ];
  const selectedWrapperPreset = wrapperPresetOptions.find(item => item.id === wrapperPresetDraft) || wrapperPresetOptions[0];
  const roleMetric = (role) => D.modelPayload?.role_metrics?.[role] || modelRoles.find(r => r.role === role)?.metrics || {};
  const saveModels = async () => {
    const result = await API.post?.('/api/models', {
      roles: modelDraft,
      processors: processorDraft,
      wrapper_mode: {
        use_only_wrapper: wrapperOnlyDraft,
        preset: selectedWrapperPreset?.id || wrapperPresetDraft,
        provider: selectedWrapperPreset?.provider,
        model: selectedWrapperPreset?.model,
        effort: selectedWrapperPreset?.effort || null,
      },
    });
    setWrapperDraftDirty(false);
    return result;
  };
  const resetModels = () => {
    setModelDraft({});
    setProcessorDraft({});
    setWrapperOnlyDraft(!!D.modelPayload?.wrapper_mode?.use_only_wrapper);
    setWrapperPresetDraft(D.modelPayload?.wrapper_mode?.preset || 'claude_sonnet');
    setWrapperDraftDirty(false);
  };
  const scopeProfileOptions = (D.scopeProfiles?.profiles || []).length
    ? D.scopeProfiles.profiles
    : [{ id: 'hack_the_box', label: 'Hack The Box', base_profile: 'hack_the_box', description: 'Lab scope profile.' }];
  const targetProfile = targetDraft.profile || scopeProfileOptions[0]?.id || 'hack_the_box';
  const selectedScopeProfile = scopeProfileOptions.find(p => p.id === targetProfile) || scopeProfileOptions[0] || {};
  const splitTargetAssets = (value) => String(value || '').split(/\n|,/).map(v => v.trim()).filter(Boolean);
  const saveTarget = async () => {
    const handle = String(targetDraft.handle || '').trim();
    const activeIp = String(targetDraft.active_ip || '').trim();
    const displayName = String(targetDraft.display_name || '').trim() || handle;
    const profile = String(targetProfile || 'hack_the_box').trim();
    const assets = splitTargetAssets(targetDraft.assets);
    for (const asset of [handle, activeIp]) {
      if (asset && !assets.includes(asset)) assets.push(asset);
    }
    setTargetFeedback(null);
    if (!handle) {
      setTargetFeedback({ tone: 'red', message: 'Target / domain is required.' });
      return null;
    }
    setTargetSaving(true);
    try {
      const payload = await API.post?.('/api/targets', {
        handle,
        display_name: displayName,
        profile,
        active_ip: activeIp,
        in_scope: targetDraft.in_scope !== false,
        assets,
        replace_scope_assets: true,
      });
      setTargetDraft(d => ({
        ...d,
        handle,
        display_name: displayName,
        profile,
        active_ip: activeIp,
        assets: assets.filter(asset => asset !== handle && asset !== activeIp).join('\n'),
      }));
      setTargetFeedback({
        tone: 'green',
        message: activeIp ? `Saved ${handle} with active IP ${activeIp}.` : `Saved ${handle}.`,
      });
      return payload;
    } catch (err) {
      setTargetFeedback({ tone: 'red', message: err.message || String(err) });
      return null;
    } finally {
      setTargetSaving(false);
    }
  };
  const editTarget = (row) => {
    const detail = (D.scopePayload?.targets || []).find(item => item.target?.handle === row.handle && item.target?.profile === row.profile);
    const target = detail?.target || {};
    setTargetDraft({
      handle: row.handle,
      display_name: target.display_name || row.handle,
      profile: row.profile,
      active_ip: row.ip,
      in_scope: row.status === 'active',
      assets: (detail?.assets || []).map(a => a.asset).filter(asset => asset !== row.handle && asset !== row.ip).join('\n'),
    });
    setTargetAdvancedOpen(true);
    setTargetFeedback({ tone: 'yellow', message: `Editing ${row.handle}.` });
  };
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
  const credentialGroups = [
    { service: 'notion', n: 'Notion', fields: [['api_key', 'API Key'], ['parent_page_id', 'Parent Page ID'], ['version', 'API Version']] },
    { service: 'discord', n: 'Discord', fields: [['webhook_url', 'Webhook URL']] },
    { service: 'caido', n: 'Caido', fields: [['graphql_url', 'GraphQL URL', CAIDO_DEFAULT_GRAPHQL_URL], ['api_token', 'API Token']] },
    { service: 'known', n: 'Known Credentials', fields: [['username', 'Username'], ['password', 'Password'], ['domain', 'Domain']] },
  ];
  const credentialGroup = (service) => credentialGroups.find(group => group.service === service);
  const credentialInputType = (key) => (key.includes('password') || key.includes('token') || key.includes('key') || key.includes('webhook') ? 'password' : 'text');
  const credentialFieldHint = (service, key, placeholder = '') => credentialStatus(service, key).hint || placeholder || 'missing';
  const credentialSourceLabel = (source) => {
    if (!source || source === 'missing') return 'not stored';
    const [base, alias] = String(source).split('_alias:');
    const label = base === 'local_store' ? 'secure local store' : base === 'environment' ? 'environment' : base.replaceAll('_', ' ');
    return alias ? `${label} · ${alias} alias` : label;
  };
  const credentialGroupConfigured = (service) => {
    const group = credentialGroup(service);
    return !!group?.fields.some(([key]) => credentialStatus(service, key).configured);
  };
  const caidoConnectionState = (connection, credentialConfigured) => {
    const conn = connection || {};
    const errorText = String(conn.error || '').toLowerCase();
    const authFailed = !!conn.auth_error || conn.status_code === 401 || conn.status_code === 403 || errorText.includes('unauthorized') || errorText.includes('forbidden');
    const migrated = !!conn.graphql_url_migrated_from;
    const configured = !!conn.configured || !!credentialConfigured;
    if (conn.ok) {
      return {
        label: migrated ? 'live migrated' : 'live',
        tone: 'green',
        detail: migrated ? `Migrated legacy URL to ${conn.graphql_url || CAIDO_DEFAULT_GRAPHQL_URL}.` : 'Caido health check is live.',
      };
    }
    if (authFailed) {
      return {
        label: 'auth failed',
        tone: 'red',
        detail: migrated ? 'Legacy URL migrated; token authentication failed.' : 'Caido rejected the configured token.',
      };
    }
    if (configured && conn.checked) {
      return {
        label: migrated ? 'migrated unreachable' : 'unreachable',
        tone: 'red',
        detail: conn.error || 'Caido GraphQL did not answer the health check.',
      };
    }
    if (configured) {
      return {
        label: migrated ? 'configured migrated' : 'configured',
        tone: migrated ? 'yellow' : 'cyan',
        detail: migrated ? `Legacy URL will use ${conn.graphql_url || CAIDO_DEFAULT_GRAPHQL_URL}.` : 'Credentials are configured; run health check for live status.',
      };
    }
    return { label: 'missing', tone: 'gray', detail: 'GraphQL URL and API token are missing.' };
  };
  const credentialSummary = (service, keys) => keys
    .map(key => {
      const status = credentialStatus(service, key);
      return status.configured && status.hint ? status.hint : '';
    })
    .filter(Boolean)
    .join(' · ');
  const saveCredentials = async (service) => {
    setCredentialFeedback(null);
    try {
      const payload = await API.post?.(`/api/credentials/${service}`, credentialDraft[service] || {});
      setCredentialDraft(d => ({ ...d, [service]: {} }));
      setCredentialFeedback({ tone: 'green', message: `Saved ${credentialGroup(service)?.n || service} credentials.` });
      return payload;
    } catch (err) {
      setCredentialFeedback({ tone: 'red', message: err.message || String(err) });
      return null;
    }
  };
  const clearCredentials = async (service) => {
    setCredentialFeedback(null);
    try {
      const payload = await API.delete?.(`/api/credentials/${service}`);
      setCredentialDraft(d => ({ ...d, [service]: {} }));
      setCredentialFeedback({ tone: 'green', message: `Cleared ${credentialGroup(service)?.n || service} credentials.` });
      return payload;
    } catch (err) {
      setCredentialFeedback({ tone: 'red', message: err.message || String(err) });
      return null;
    }
  };
  const refreshCaidoHealth = async () => {
    setCaidoHealthBusy(true);
    setCredentialFeedback(null);
    try {
      const payload = await API.refreshCaido?.({ checkHealth: true });
      if (!payload?.ok) {
        setCredentialFeedback({ tone: 'red', message: payload?.error || 'Caido health check failed.' });
      } else {
        setCredentialFeedback({ tone: 'green', message: 'Caido health check OK: GraphQL, auth, and schema answered.' });
      }
      return payload;
    } catch (err) {
      setCredentialFeedback({ tone: 'red', message: err.message || String(err) });
      return null;
    } finally {
      setCaidoHealthBusy(false);
    }
  };
  useEffectD(() => {
    if (tab !== 'integrations') return;
    API.refreshCredentials?.().catch(err => {
      setCredentialFeedback({ tone: 'red', message: err.message || String(err) });
    });
  }, [tab]);
  useEffectD(() => {
    if (tab !== 'integrations' || integrationSelected !== 'caido') return;
    refreshCaidoHealth();
  }, [tab, integrationSelected]);
  const withRuntimeAction = async (busyKey, worker, successMessage) => {
    if (runtimeBusy) return null;
    setRuntimeBusy(busyKey);
    setRuntimeFeedback(null);
    try {
      const payload = await worker();
      const message = typeof successMessage === 'function' ? successMessage(payload) : successMessage;
      setRuntimeFeedback({ tone: 'green', message });
      return payload;
    } catch (err) {
      setRuntimeFeedback({ tone: 'red', message: err.message || String(err) });
      return null;
    } finally {
      setRuntimeBusy('');
    }
  };
  const boundedMaxExec = () => Math.max(1, Math.floor(runtimeNumber(maxExec, 1)));
  const boundedInterval = () => Math.max(2, Math.floor(runtimeNumber(interval, 30)));
  const runTickNow = () => withRuntimeAction(
    'tick',
    () => API.action?.('tick', { max_executions: boundedMaxExec() }),
    payload => {
      const summary = payload?.result?.report?.summary;
      return summary ? `Tick complete: ${summary}` : 'Tick complete.';
    },
  );
  const stopActiveWork = () => withRuntimeAction(
    'stop-work',
    () => API.action?.('stop-work'),
    'Stop request sent.',
  );
  const saveModeAndIntent = () => withRuntimeAction(
    'mode-intent',
    async () => {
      const payload = await API.post?.('/api/runtime-control', {
        mode: executionMode,
        interval_seconds: boundedInterval(),
        intent_id: intent,
      });
      setRuntimeDraftDirty(false);
      return payload;
    },
    'Saved runtime mode and operator intent.',
  );
  const setContinuousTicks = (enabled) => withRuntimeAction(
    enabled ? 'start-continuous' : 'stop-continuous',
    async () => {
      const payload = await API.post?.('/api/runtime-control', {
        mode: enabled ? 'continuous' : 'tick',
        interval_seconds: boundedInterval(),
        intent_id: intent,
      });
      setContMode(!!enabled);
      setRuntimeDraftDirty(false);
      return payload;
    },
    enabled ? 'Continuous ticks started.' : 'Continuous ticks stopped.',
  );
  const saveRuntimeSettings = () => withRuntimeAction(
    'runtime-settings',
    async () => {
      const payload = await API.post?.('/api/runtime-settings', tuning);
      setTuningDraftDirty(false);
      return payload;
    },
    'Saved resource limits.',
  );
  const runMaintenance = (action, body, message) => withRuntimeAction(
    action,
    () => API.action?.(action, body),
    message,
  );
  const stopServer = () => withRuntimeAction(
    'server-stop',
    () => API.post?.('/api/server/stop', { confirm: 'stop' }),
    'Server stop requested.',
  );
  const tuningHint = (key, unit) => {
    const bits = [];
    if (tuningMinimums[key] != null) bits.push(`min ${tuningMinimums[key]}${unit}`);
    if (tuningDefaults[key] != null) bits.push(`default ${tuningDefaults[key]}${unit}`);
    return bits.join(' / ');
  };
  const resolveApproval = async (approval, verdict) => {
    const taskId = approval?.task || approval?.id;
    if (!taskId || approvalBusy) return null;
    const approving = verdict === 'approve';
    setApprovalBusy(taskId);
    setApprovalFeedback(null);
    try {
      if (approving) onApprove?.(approval); else onReject?.(approval);
      const payload = await API.post?.(approving ? '/api/actions/approve' : '/api/actions/deny', { task_id: taskId });
      setApprovalFeedback({
        tone: approving ? 'green' : 'red',
        message: `${approving ? 'Approved' : 'Denied'} ${approval.title || taskId}.`,
      });
      return payload;
    } catch (err) {
      setApprovalFeedback({ tone: 'red', message: err.message || String(err) });
      return null;
    } finally {
      setApprovalBusy('');
    }
  };
  const caidoState = caidoConnectionState(D.caido?.connection, credentialGroupConfigured('caido'));
  const integrationRows = [
    {
      service: 'notion',
      n: 'Notion',
      d: credentialSummary('notion', ['api_key', 'parent_page_id']) || 'local findings export only',
      s: credentialGroupConfigured('notion') || D.notes?.syncStatus?.configured ? 'configured' : 'missing',
      tone: credentialGroupConfigured('notion') || D.notes?.syncStatus?.configured ? 'green' : 'gray',
      detail: 'Notes and evidence sync destination.',
    },
    {
      service: 'discord',
      n: 'Discord',
      d: credentialStatus('discord', 'webhook_url').hint || 'webhook not configured',
      s: credentialStatus('discord', 'webhook_url').configured ? 'configured' : 'missing',
      tone: credentialStatus('discord', 'webhook_url').configured ? 'green' : 'gray',
      detail: 'Operator notification webhook.',
    },
    {
      service: 'caido',
      n: 'Caido',
      d: caidoState.detail || credentialSummary('caido', ['graphql_url', 'api_token']) || D.caido?.connection?.graphql_url || 'GraphQL credentials missing',
      s: caidoState.label,
      tone: caidoState.tone,
      detail: 'HTTPQL search, request import, replay approvals, and targeted live health.',
    },
    {
      service: 'known',
      n: 'Known Credentials',
      d: credentialSummary('known', ['username', 'domain', 'password']) || 'known credentials not configured',
      s: credentialStatus('known', 'username').configured ? 'set' : 'missing',
      tone: credentialStatus('known', 'username').configured ? 'cyan' : 'gray',
      detail: 'Durable known username and password record; execution still needs intent and approval.',
    },
    {
      service: 'ollama',
      n: 'Ollama',
      d: D.modelPayload?.ollama?.base_url || 'localhost',
      s: D.modelPayload?.ollama?.ok ? 'live' : 'offline',
      tone: D.modelPayload?.ollama?.ok ? 'cyan' : 'gray',
      detail: 'Local model backend status.',
    },
    {
      service: 'premium',
      n: 'Claude/GPT',
      d: premiumWrapperLabel,
      s: premiumWrapperStatus,
      tone: premiumWrapperTone,
      detail: premiumWrapper.detail || 'Remote premium escalation status.',
    },
  ];
  const activeIntegration = integrationRows.find(row => row.service === integrationSelected) || integrationRows[0];
  const activeCredentialGroup = activeIntegration ? credentialGroup(activeIntegration.service) : null;
  const selectedCredentialField = selectedCredentialKey || activeCredentialGroup?.fields?.[0]?.[0] || '';
  const firstTarget = D.scope[0]?.handle || D.traceMeta?.selectedTarget || 'All targets';

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
              </>
            }
            className="fill"
          >
            <div className="tabs" style={{ marginBottom: 10 }}>
              {['controls', 'models', 'targets', 'scope', 'self test', 'integrations'].map(t => (
                <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>{t}</button>
              ))}
            </div>
            {tab === 'controls' && (
              <div className="runtime-pane">
                {runtimeFeedback && (
                  <div className={`banner ${runtimeFeedback.tone === 'red' ? 'red' : 'green'} runtime-feedback`}>
                    <Dot tone={runtimeFeedback.tone === 'red' ? 'red' : 'green'} />
                    <span>{runtimeFeedback.message}</span>
                    <button className="btn ghost sm" onClick={() => setRuntimeFeedback(null)}>CLEAR</button>
                  </div>
                )}

                <div className="runtime-section">
                  <div className="runtime-section-head">
                    <div>
                      <span className="runtime-section-title">Runtime State</span>
                      <span className="runtime-section-sub">{workStatus.summary || 'No runtime status.'}</span>
                    </div>
                    <Pill tone={runtimeTone}>{runtimeStatus}</Pill>
                  </div>
                  <div className="runtime-state-grid">
                    <RuntimeTile label="autonomy" value={autonomy || 'assisted'} detail="current config" tone="cyan" />
                    <RuntimeTile label="intent" value={intentLabel} detail={intent} tone="green" />
                    <RuntimeTile label="mode" value={executionMode} detail={contMode ? `${interval}s interval` : 'manual ticks'} tone={contMode ? 'yellow' : 'gray'} />
                    <RuntimeTile label="work" value={activeWork} detail={`${queuedWork} queued / ${waitingWork} waiting`} tone={waitingWork ? 'warn' : ''} />
                    <RuntimeTile label="approvals" value={D.approvals.length} detail="pending" tone={D.approvals.length ? 'crit' : ''} />
                    <RuntimeTile label="Claude/GPT" value={premiumWrapperStatus} detail={premiumWrapperLabel} tone={premiumWrapperTone} />
                    {webActionCount ? <RuntimeTile label="web actions" value={webActionCount} detail={staleWebActionCount ? `${staleWebActionCount} stale` : 'running'} tone="warn" /> : null}
                  </div>
                  <div className="runtime-policy-row">
                    <span className="runtime-policy-label">policy</span>
                    {policyFlags.length ? policyFlags.map(flag => <Pill key={flag} tone="cyan">{flag}</Pill>) : <Pill tone="green">recon default</Pill>}
                    {premiumWrapperAvailable ? <Pill tone="cyan">Claude/GPT wrapper</Pill> : null}
                    <Pill tone="yellow">PoC gated</Pill>
                    <Pill tone="red">DoS forbidden</Pill>
                  </div>
                  {blockerRows.length ? (
                    <div className="runtime-blockers">
                      {blockerRows.map((item, index) => (
                        <div key={`${item.summary}:${index}`} className="runtime-blocker">
                          <span className="runtime-blocker-title">{item.summary}</span>
                          {item.detail && <span className="runtime-blocker-detail">{item.detail}</span>}
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>

                <div className="runtime-section">
                  <div className="runtime-section-head">
                    <div>
                      <span className="runtime-section-title">{contMode ? 'Continuous Ticks' : 'Run Now'}</span>
                      <span className="runtime-section-sub">
                        {contMode
                          ? `${persistedContinuous ? 'Server loop active' : 'Ready to start'} · one bounded tick every ${boundedInterval()}s.`
                          : 'One bounded orchestration tick.'}
                      </span>
                    </div>
                  </div>
                  {contMode ? (
                    <div className="runtime-command-grid">
                      <Field label="continuous interval (s)">
                        <input className="input" type="number" min="2" value={interval} onChange={e => updateIntervalDraft(e.target.value)} />
                      </Field>
                      <button className="btn primary runtime-command" onClick={() => setContinuousTicks(true)} disabled={!!runtimeBusy || (persistedContinuous && !runtimeDraftDirty)}>
                        {runtimeBusy === 'start-continuous' || runtimeBusy === 'mode-intent' ? 'STARTING TICKS' : persistedContinuous && !runtimeDraftDirty ? 'CONTINUOUS TICKS RUNNING' : 'START CONTINUOUS TICKS'}
                      </button>
                      <button className="btn danger runtime-command" onClick={() => setContinuousTicks(false)} disabled={!!runtimeBusy || !persistedContinuous}>
                        {runtimeBusy === 'stop-continuous' ? 'STOPPING TICKS' : 'STOP CONTINUOUS TICKS'}
                      </button>
                      <button className="btn ghost runtime-command" onClick={stopActiveWork} disabled={!!runtimeBusy}>
                        {runtimeBusy === 'stop-work' ? 'STOPPING WORK' : 'STOP ACTIVE WORK'}
                      </button>
                    </div>
                  ) : (
                    <div className="runtime-command-grid">
                      <Field label="max executions">
                        <input className="input" type="number" min="1" value={maxExec} onChange={e => setMaxExec(Math.max(1, Number(e.target.value) || 1))} />
                      </Field>
                      <button className="btn primary runtime-command" onClick={runTickNow} disabled={!!runtimeBusy}>
                        {runtimeBusy === 'tick' ? 'RUNNING TICK' : 'RUN TICK NOW'}
                      </button>
                      <button className="btn danger runtime-command" onClick={stopActiveWork} disabled={!!runtimeBusy}>
                        {runtimeBusy === 'stop-work' ? 'STOPPING WORK' : 'STOP ACTIVE WORK'}
                      </button>
                    </div>
                  )}
                </div>

                <div className="runtime-section">
                  <div className="runtime-section-head">
                    <div>
                      <span className="runtime-section-title">Mode & Intent</span>
                      <span className="runtime-section-sub">Scheduler cadence and active Operator Intent.</span>
                    </div>
                  </div>
                  <div className="runtime-settings-grid">
                    <Field label="operator intent">
                      <select className="input" value={intent} onChange={e => updateIntentDraft(e.target.value)}>
                        {intentOptions.length ? intentOptions.map(item => (
                          <option key={item.id} value={item.id}>{item.label || item.id}</option>
                        )) : <option value={intent}>{intent}</option>}
                      </select>
                    </Field>
                    <Field label="execution mode">
                      <select className="input" value={contMode ? 'cont' : 'tick'} onChange={e => updateExecutionModeDraft(e.target.value)}>
                        <option value="tick">Tick mode</option>
                        <option value="cont">Continuous ticks</option>
                      </select>
                    </Field>
                    <Field label="continuous interval (s)">
                      <input className="input" type="number" min="2" value={interval} disabled={!contMode} onChange={e => updateIntervalDraft(e.target.value)} />
                    </Field>
                  </div>
                  <div className="runtime-actions">
                    <button className="btn primary sm" onClick={saveModeAndIntent} disabled={!!runtimeBusy}>
                      {runtimeBusy === 'mode-intent' ? 'SAVING MODE' : 'SAVE MODE AND INTENT'}
                    </button>
                  </div>
                </div>

                <div className="runtime-section">
                  <div className="runtime-section-head">
                    <div>
                      <span className="runtime-section-title">Resource Limits</span>
                      <span className="runtime-section-sub">Worker timeouts and memory reserves.</span>
                    </div>
                  </div>
                  <div className="runtime-settings-grid">
                    <Field label="GPU AI timeout (s)">
                      <input className="input" type="number" min={tuningMinimums.gpu_ai_timeout_seconds || 1} value={tuning.gpu_ai_timeout_seconds || 120} onChange={e => updateTuning('gpu_ai_timeout_seconds', e.target.value)} />
                      <RuntimeHint>{tuningHint('gpu_ai_timeout_seconds', 's')}</RuntimeHint>
                    </Field>
                    <Field label="CPU AI timeout (s)">
                      <input className="input" type="number" min={tuningMinimums.cpu_ai_timeout_seconds || 1} value={tuning.cpu_ai_timeout_seconds || 300} onChange={e => updateTuning('cpu_ai_timeout_seconds', e.target.value)} />
                      <RuntimeHint>{tuningHint('cpu_ai_timeout_seconds', 's')}</RuntimeHint>
                    </Field>
                    <Field label="stale run timeout (s)">
                      <input className="input" type="number" min={tuningMinimums.stale_run_timeout_seconds || 1} value={tuning.stale_run_timeout_seconds || 3600} onChange={e => updateTuning('stale_run_timeout_seconds', e.target.value)} />
                      <RuntimeHint>{tuningHint('stale_run_timeout_seconds', 's')}</RuntimeHint>
                    </Field>
                    <Field label="CPU RAM reserve (MB)">
                      <input className="input" type="number" min={tuningMinimums.min_free_cpu_ram_mb || 0} value={tuning.min_free_cpu_ram_mb || 2048} onChange={e => updateTuning('min_free_cpu_ram_mb', e.target.value)} />
                      <RuntimeHint>{tuningHint('min_free_cpu_ram_mb', 'MB')}</RuntimeHint>
                    </Field>
                    <Field label="GPU RAM reserve (MB)">
                      <input className="input" type="number" min={tuningMinimums.min_free_gpu_ram_mb || 0} value={tuning.min_free_gpu_ram_mb || 368} onChange={e => updateTuning('min_free_gpu_ram_mb', e.target.value)} />
                      <RuntimeHint>{tuningHint('min_free_gpu_ram_mb', 'MB')}</RuntimeHint>
                    </Field>
                  </div>
                  <div className="runtime-actions">
                    <button className="btn primary sm" onClick={saveRuntimeSettings} disabled={!!runtimeBusy}>
                      {runtimeBusy === 'runtime-settings' ? 'SAVING LIMITS' : 'SAVE RESOURCE LIMITS'}
                    </button>
                  </div>
                </div>

                <div className="runtime-section">
                  <div className="runtime-section-head">
                    <div>
                      <span className="runtime-section-title">Maintenance</span>
                      <span className="runtime-section-sub">Runtime housekeeping actions.</span>
                    </div>
                  </div>
                  <div className="runtime-action-grid">
                    <button className="btn sm" onClick={() => runMaintenance('compact', {}, 'Memory compaction complete.')} disabled={!!runtimeBusy}>COMPACT MEMORY</button>
                    <button className="btn sm" onClick={() => runMaintenance('process-queues', {}, 'External queues processed.')} disabled={!!runtimeBusy}>PROCESS QUEUES</button>
                    <button className="btn ghost sm" onClick={() => runMaintenance('warm-models', { keep_alive: '8h' }, 'Model lanes warmed.')} disabled={!!runtimeBusy}>WARM MODELS</button>
                    <button className="btn ghost sm" onClick={() => runMaintenance('clear-models', {}, 'Model lanes cleared.')} disabled={!!runtimeBusy}>CLEAR MODELS</button>
                    <button className="btn ghost sm" onClick={() => runMaintenance('clear-stale-web-actions', {}, 'Stale web action records cleared.')} disabled={!!runtimeBusy}>CLEAR STALE WEB ACTIONS</button>
                    <button className="btn danger sm" onClick={stopServer} disabled={!!runtimeBusy}>
                      {runtimeBusy === 'server-stop' ? 'STOPPING SERVER' : 'STOP SERVER'}
                    </button>
                  </div>
                </div>
              </div>
            )}
            {tab === 'models' && (
              <div className="col gap-8">
                <div className="banner">
                  <label className="row gap-6" style={{ alignItems: 'center', flex: 1 }}>
                    <input
                      type="checkbox"
                      checked={!!wrapperOnlyDraft}
                      onChange={e => {
                        setWrapperDraftDirty(true);
                        setWrapperOnlyDraft(e.target.checked);
                      }}
                    />
                    <span className="strong">Use only wrapper</span>
                  </label>
                  <Pill tone={wrapperOnlyDraft ? 'cyan' : 'gray'}>{wrapperOnlyDraft ? 'WRAPPER' : 'LOCAL'}</Pill>
                  <select
                    className="input"
                    style={{ maxWidth: 190 }}
                    value={wrapperPresetDraft}
                    onChange={e => {
                      setWrapperDraftDirty(true);
                      setWrapperPresetDraft(e.target.value);
                    }}
                  >
                    {wrapperPresetOptions.map(option => (
                      <option key={option.id} value={option.id}>{option.label}</option>
                    ))}
                  </select>
                  <span className="dim mono">{wrapperMode.local_chat_wrapper || 'agent_chat_api'} · {wrapperMode.display_label || wrapperMode.model_label || wrapperMode.provider || 'provider'}</span>
                </div>
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
                    <tr key={`${row.profile}:${row.handle}`}>
                      <td><span className="strong">{row.handle}</span><div className="dim mono">{row.status}</div></td>
                      <td>{row.profile}</td><td>{row.ip || '—'}</td><td>{row.assets}</td>
                      <td className="dim">{row.evidence} ev · {row.findings} fnd</td>
                      <td className="row gap-4"><button className="btn ghost sm" onClick={() => editTarget(row)}>EDIT</button><button className="btn danger sm" onClick={() => API.delete?.(`/api/targets/${encodeURIComponent(row.handle)}?profile=${encodeURIComponent(row.profile)}`)}>DELETE</button></td>
                    </tr>
                  ))}</tbody>
                </table>
                <div className="col gap-8" style={{ padding: 10, border: '1px solid var(--line)', borderRadius: 4, background: 'var(--bg-deep)' }}>
                  <div>
                    <div className="upper" style={{ color: 'var(--txt-strong)', marginBottom: 4 }}>Target scope editor</div>
                    <div className="dim mono" style={{ fontSize: 10.5 }}>The target record anchors evidence, tasks, notes, guidance, and active IP history.</div>
                  </div>
                  {targetFeedback && (
                    <div className={`banner ${targetFeedback.tone === 'red' ? 'red' : targetFeedback.tone === 'green' ? 'green' : ''}`}>
                      {targetFeedback.message}
                    </div>
                  )}
                  <Field label="Target / domain">
                    <input className="input" placeholder="target.example" value={targetDraft.handle || ''} onChange={e => setTargetDraft(d => ({ ...d, handle: e.target.value }))} />
                    <span className="dim mono" style={{ fontSize: 10.5 }}>Durable target key. Use the hostname when it exists.</span>
                  </Field>
                  <Field label="Current IP">
                    <input className="input" placeholder="203.0.113.10" value={targetDraft.active_ip || ''} onChange={e => setTargetDraft(d => ({ ...d, active_ip: e.target.value }))} />
                    <span className="dim mono" style={{ fontSize: 10.5 }}>Operator-confirmed live address. Saving it also adds an IP scope asset.</span>
                  </Field>
                  <Field label="Scope profile">
                    <select className="input" value={targetProfile} onChange={e => setTargetDraft(d => ({ ...d, profile: e.target.value }))}>
                      {scopeProfileOptions.map(profile => (
                        <option key={profile.id} value={profile.id}>{profile.label || profile.id}</option>
                      ))}
                    </select>
                    <span className="dim mono" style={{ fontSize: 10.5 }}>
                      {(selectedScopeProfile.description || 'Scope defaults for this target.')} Operator Intent still gates actions.
                    </span>
                  </Field>
                  <Field label="Display name">
                    <input className="input" placeholder={targetDraft.handle || 'target.example'} value={targetDraft.display_name || ''} onChange={e => setTargetDraft(d => ({ ...d, display_name: e.target.value }))} />
                    <span className="dim mono" style={{ fontSize: 10.5 }}>Optional label. Blank uses the target / domain.</span>
                  </Field>
                  <label className="row gap-6 mono" style={{ fontSize: 11, alignItems: 'center' }}>
                    <input type="checkbox" checked={targetDraft.in_scope !== false} onChange={e => setTargetDraft(d => ({ ...d, in_scope: e.target.checked }))} />
                    in scope for active runtime planning
                  </label>
                  <div className="col gap-6" style={{ borderTop: '1px dashed var(--line)', paddingTop: 8 }}>
                    <button className="btn ghost sm" type="button" onClick={() => setTargetAdvancedOpen(v => !v)} style={{ alignSelf: 'flex-start' }}>
                      {targetAdvancedOpen ? 'HIDE ADVANCED ASSETS' : 'ADVANCED ASSETS'}
                    </button>
                    {targetAdvancedOpen && (
                      <Field label="Extra scope assets">
                        <textarea className="input" rows="4" placeholder="https://target.example/\ntarget.example" value={targetDraft.assets || ''} onChange={e => setTargetDraft(d => ({ ...d, assets: e.target.value }))} />
                        <span className="dim mono" style={{ fontSize: 10.5 }}>Optional hostnames, URLs, or IPs beyond the target and current IP.</span>
                      </Field>
                    )}
                  </div>
                  <button className="btn primary sm" onClick={saveTarget} disabled={targetSaving}>
                    {targetSaving ? 'SAVING' : 'SAVE TARGET'}
                  </button>
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
              <div className="grid" style={{ gridTemplateColumns: 'minmax(240px, 0.85fr) minmax(0, 1.15fr)', gap: 10 }}>
                <div className="col gap-8">
                  {integrationRows.map(i => {
                    const selected = activeIntegration?.service === i.service;
                    return (
                      <button
                        key={i.service}
                        type="button"
                        aria-pressed={selected}
                        onClick={() => {
                          setIntegrationSelected(i.service);
                          setSelectedCredentialKey(credentialGroup(i.service)?.fields?.[0]?.[0] || '');
                          setCredentialFeedback(null);
                        }}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          gap: 10,
                          padding: '8px 10px',
                          border: `1px solid ${selected ? 'var(--cyan)' : 'var(--line)'}`,
                          borderRadius: 4,
                          background: selected ? 'var(--elev-1)' : 'var(--bg-deep)',
                          color: 'var(--txt)',
                          cursor: 'pointer',
                          font: 'inherit',
                          textAlign: 'left',
                          width: '100%',
                        }}
                      >
                        <div style={{ minWidth: 0 }}>
                          <div className="strong" style={{ fontWeight: 600 }}>{i.n}</div>
                          <div className="dim mono" style={{ fontSize: 10.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{i.d}</div>
                        </div>
                        <Pill tone={i.tone}>{i.s.toUpperCase()}</Pill>
                      </button>
                    );
                  })}
                </div>
                <div className="col gap-8" style={{ padding: 10, border: '1px solid var(--line)', borderRadius: 4, background: 'var(--bg-deep)', minWidth: 0 }}>
                  <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <div style={{ minWidth: 0 }}>
                      <div className="strong" style={{ fontWeight: 700 }}>{activeIntegration?.n}</div>
                      <div className="dim" style={{ fontSize: 11 }}>{activeIntegration?.detail}</div>
                    </div>
                    <Pill tone={activeIntegration?.tone || 'gray'}>{(activeIntegration?.s || 'missing').toUpperCase()}</Pill>
                  </div>
                  {credentialFeedback && (
                    <div className={`banner ${credentialFeedback.tone === 'red' ? 'red' : 'green'}`}>
                      <Dot tone={credentialFeedback.tone === 'red' ? 'red' : 'green'} />
                      <span>{credentialFeedback.message}</span>
                    </div>
                  )}
                  {activeCredentialGroup ? (
                    <>
                      {activeCredentialGroup.service === 'caido' && (
                        <div className="banner">
                          <Dot tone={caidoState.tone} />
                          <span style={{ flex: 1 }}>
                            {caidoState.label.toUpperCase()}: {caidoState.detail}
                          </span>
                          <button className="btn ghost sm" onClick={refreshCaidoHealth} disabled={caidoHealthBusy}>
                            {caidoHealthBusy ? 'CHECKING' : 'HEALTH CHECK'}
                          </button>
                        </div>
                      )}
                      <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 8 }}>
                        {activeCredentialGroup.fields.map(([key, label, placeholder]) => {
                          const status = credentialStatus(activeCredentialGroup.service, key);
                          const selected = selectedCredentialField === key;
                          return (
                            <button
                              key={key}
                              type="button"
                              aria-label={`Edit ${activeCredentialGroup.n} ${label}`}
                              onClick={() => setSelectedCredentialKey(key)}
                              style={{
                                padding: '7px 8px',
                                border: `1px solid ${selected ? 'var(--cyan)' : 'var(--line)'}`,
                                borderRadius: 4,
                                minWidth: 0,
                                background: selected ? 'var(--elev-1)' : 'var(--bg)',
                                color: 'var(--txt)',
                                cursor: 'pointer',
                                font: 'inherit',
                                textAlign: 'left',
                              }}
                            >
                              <div className="row" style={{ justifyContent: 'space-between', gap: 8, alignItems: 'center' }}>
                                <span className="dim" style={{ fontSize: 10 }}>{label}</span>
                                <Pill tone={status.configured ? 'green' : 'gray'}>{status.configured ? 'SAVED' : 'MISSING'}</Pill>
                              </div>
                              <div className="mono strong" style={{ marginTop: 4, fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {status.configured ? credentialFieldHint(activeCredentialGroup.service, key, placeholder) : 'missing'}
                              </div>
                              {status.source && <div className="dim mono" style={{ marginTop: 3, fontSize: 9.5 }}>{credentialSourceLabel(status.source)}</div>}
                            </button>
                          );
                        })}
                      </div>
                      <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 8 }}>
                        {activeCredentialGroup.fields.map(([key, label, placeholder]) => (
                          <Field key={key} label={label}>
                            <input
                              className="input"
                              type={credentialInputType(key)}
                              placeholder={credentialFieldHint(activeCredentialGroup.service, key, placeholder)}
                              value={credentialDraft[activeCredentialGroup.service]?.[key] || ''}
                              onChange={e => setCredentialValue(activeCredentialGroup.service, key, e.target.value)}
                              onFocus={() => setSelectedCredentialKey(key)}
                              style={{
                                borderColor: selectedCredentialField === key ? 'var(--cyan)' : undefined,
                                boxShadow: selectedCredentialField === key ? '0 0 0 1px var(--cyan-soft)' : undefined,
                              }}
                            />
                          </Field>
                        ))}
                      </div>
                      <div className="row gap-4">
                        <button className="btn primary sm" onClick={() => saveCredentials(activeCredentialGroup.service)}>SAVE CREDENTIALS</button>
                        <button className="btn ghost sm" onClick={() => clearCredentials(activeCredentialGroup.service)}>CLEAR</button>
                      </div>
                    </>
                  ) : (
                    <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 8 }}>
                      <div style={{ padding: '7px 8px', border: '1px solid var(--line)', borderRadius: 4 }}>
                        <div className="dim" style={{ fontSize: 10 }}>Endpoint</div>
                        <div className="mono strong" style={{ marginTop: 4 }}>{activeIntegration?.d}</div>
                      </div>
                      <div style={{ padding: '7px 8px', border: '1px solid var(--line)', borderRadius: 4 }}>
                        <div className="dim" style={{ fontSize: 10 }}>Stored credentials</div>
                        <div className="mono strong" style={{ marginTop: 4 }}>not required</div>
                      </div>
                    </div>
                  )}
                </div>
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
                    <td><span className="strong">{t.kind}</span>{t.grouped_count ? <div className="dim mono">{t.grouped_count} grouped</div> : null}</td>
                    <td>{t.title}{t.hint ? <div className="dim mono" style={{ marginTop: 3 }}>{t.hint}</div> : null}</td>
                    <td>{t.target}</td>
                    <td className="dim">
                      {t.route} · {t.model || 'unassigned'}
                      {t.remote_premium_local_wrapper ? (
                        <div className="row gap-4" style={{ marginTop: 3, flexWrap: 'wrap' }}>
                          <Pill tone="cyan">{t.wrapper_label || (t.local_chat_wrapper === 'agent_chat_api' ? 'agent_chat_api wrapper' : `${t.local_chat_wrapper || 'agent_chat_api'} wrapper`)}</Pill>
                        </div>
                      ) : null}
                    </td>
                    <td className="dim">{t.ms ? `${(t.ms / 1000).toFixed(1)}s` : '—'}</td>
                    <td>
                      <button
                        className="btn ghost sm"
                        onClick={() => API.openInspector?.(t.grouped ? 'group' : 'task', t.id, { title: `Inspect ${t.kind}` })}
                      >
                        {t.grouped ? 'INSPECT GROUP' : 'INSPECT'}
                      </button>
                    </td>
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
            actions={<button className="btn ghost sm" onClick={() => API.command?.('queue-all-approvals', { target: firstTarget })}>QUEUE ALL</button>}
            className="fill"
          >
            <div className="col" style={{ gap: 8 }}>
              {approvalFeedback && (
                <div className={`banner ${approvalFeedback.tone === 'red' ? 'red' : approvalFeedback.tone === 'green' ? 'green' : ''}`}>
                  {approvalFeedback.message}
                </div>
              )}
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
                    <button className="btn primary sm" disabled={approvalBusy === (a.task || a.id)} onClick={() => resolveApproval(a, 'approve')}>
                      {approvalBusy === (a.task || a.id) ? 'WORKING' : 'APPROVE'}
                    </button>
                    <button className="btn danger sm" disabled={approvalBusy === (a.task || a.id)} onClick={() => resolveApproval(a, 'reject')}>
                      {approvalBusy === (a.task || a.id) ? 'WORKING' : 'DENY'}
                    </button>
                    <button className="btn ghost sm" onClick={() => API.command?.('defer-approval', { task_id: a.task || a.id, target: a.target, title: `Defer ${a.title}` })}>DEFER</button>
                    <button className="btn ghost sm" style={{ marginLeft: 'auto' }} onClick={() => API.command?.('open-approval-chat', { task_id: a.task || a.id, target: a.target, title: `Open chat for ${a.title}` })}>OPEN IN CHAT →</button>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* events */}
          <Panel
            title="Audit Stream"
            sub="control-plane events"
            actions={<button className="btn ghost sm" onClick={() => API.command?.('clear-audit-view', { title: 'Clear audit stream view' })}>CLEAR</button>}
            className="fill"
            bodyClass="tight"
          >
            <div className="log">
              {D.events.map((e, i) => (
                <div className="log-row" key={i}>
                  <span className="log-t">{e.t}</span>
                  <span className={`log-lvl ${e.lvl}`}>{e.lvl}</span>
                  <span className="log-msg">{e.msg}</span>
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
