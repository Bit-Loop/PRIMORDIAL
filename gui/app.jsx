/* global React, ReactDOM, DashboardMode, TraceMode, ChatMode, PlanMode, NotesMode, InterestsMode, CaidoMode, Rail */
const { useState: useStateApp, useEffect: useEffectApp, useMemo: useMemoApp, useCallback: useCallbackApp } = React;

const TWEAKS = /*EDITMODE-BEGIN*/{
  "accent": "cyan",
  "density": "compact",
  "contrast": "extra",
  "monoFont": "JetBrains Mono",
  "showGlobe": true,
  "cyberpunk": true
}/*EDITMODE-END*/;

const EMPTY_PD_DATA = {
  mode: 'real',
  runtime: {
    autonomy: 'assisted', intent: 'recon_only', health: 'LOADING', uptime: 'live',
    cpu: 0, gpu: 0, mem: 0, diskWrites: 0, netIn: '0 B/s', netOut: '0 B/s',
    activeTasks: 0, queued: 0, approvals: 0,
    gpuMemory: { percent: 0, used_label: 'unavailable', free_label: 'unavailable' },
    executionMode: { mode: 'tick', interval_seconds: 30, available_modes: ['tick', 'continuous'] },
    runtimeTuning: {
      gpu_ai_timeout_seconds: 120, cpu_ai_timeout_seconds: 300, stale_run_timeout_seconds: 3600,
      min_free_cpu_ram_mb: 2048, min_free_gpu_ram_mb: 368,
    },
    operatorIntent: { active: { id: 'recon_only', label: 'Recon Only', policy: {} }, intents: [] },
    workStatus: { counts: { active: 0, queued: 0, waiting: 0 }, summary: 'Loading runtime state.' },
  },
  models: [],
  modelPayload: { available_models: [], roles: [], role_metrics: {}, eval_history: [], ollama: {} },
  tasks: [],
  approvals: [],
  events: [],
  scope: [],
  scopePayload: { targets: [], totals: {} },
  scopeProfiles: { profiles: [] },
  graph: { nodes: [], edges: [] },
  traces: [{ id: 'tr_root', kind: 'workflow.runtime', status: 'queued', time: 'live', summary: 'No trace data yet.', children: [] }],
  traceMeta: { selectedTarget: '', targetOptions: [{ id: '', label: 'All targets' }], grouped: true, defaultLimit: 40 },
  geo: { pins: [], traces: [], asns: [] },
  plan: {
    methodology: { id: 'runtime', label: 'Runtime', description: '', phases: [] },
    intent: { id: 'recon_only', label: 'Recon Only', flags: {} },
    autonomy: 'assisted',
    autonomyModes: ['assisted', 'supervised', 'supervised_auto', 'high_autonomy'],
    pinnedAssets: [],
    playbooks: [],
    skills: [],
    criticalThinking: [],
  },
  notes: { targets: [], syncStatus: { ok: false, lastSync: 'never', pendingJobs: 0, failedJobs: 0 }, folders: [], pages: {} },
  interests: { surfaces: [], findings: [], pocs: [], artifacts: [] },
  caido: { connection: { configured: false, ok: false }, requests: [], replays: [], savedFilters: [] },
  approvalChat: [],
  inquiryChat: [],
  signals: [],
  credentials: { services: {} },
  selfTest: null,
};

function mergePDData(payload) {
  const next = { ...EMPTY_PD_DATA, ...(payload || {}) };
  next.runtime = { ...EMPTY_PD_DATA.runtime, ...(payload?.runtime || {}) };
  next.runtime.executionMode = { ...EMPTY_PD_DATA.runtime.executionMode, ...(payload?.runtime?.executionMode || {}) };
  next.runtime.runtimeTuning = { ...EMPTY_PD_DATA.runtime.runtimeTuning, ...(payload?.runtime?.runtimeTuning || {}) };
  next.runtime.operatorIntent = { ...EMPTY_PD_DATA.runtime.operatorIntent, ...(payload?.runtime?.operatorIntent || {}) };
  next.runtime.workStatus = { ...EMPTY_PD_DATA.runtime.workStatus, ...(payload?.runtime?.workStatus || {}) };
  next.graph = { ...EMPTY_PD_DATA.graph, ...(payload?.graph || {}) };
  next.geo = { ...EMPTY_PD_DATA.geo, ...(payload?.geo || {}) };
  next.traceMeta = { ...EMPTY_PD_DATA.traceMeta, ...(payload?.traceMeta || {}) };
  next.plan = { ...EMPTY_PD_DATA.plan, ...(payload?.plan || {}) };
  next.plan.methodology = { ...EMPTY_PD_DATA.plan.methodology, ...(payload?.plan?.methodology || {}) };
  next.plan.intent = { ...EMPTY_PD_DATA.plan.intent, ...(payload?.plan?.intent || {}) };
  next.notes = { ...EMPTY_PD_DATA.notes, ...(payload?.notes || {}) };
  next.notes.syncStatus = { ...EMPTY_PD_DATA.notes.syncStatus, ...(payload?.notes?.syncStatus || {}) };
  next.interests = { ...EMPTY_PD_DATA.interests, ...(payload?.interests || {}) };
  next.caido = { ...EMPTY_PD_DATA.caido, ...(payload?.caido || {}) };
  return next;
}

async function apiRequest(path, options = {}) {
  const init = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  };
  if (init.body && typeof init.body !== 'string') init.body = JSON.stringify(init.body);
  const response = await fetch(path, init);
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (!response.ok) throw new Error(payload.error || `${response.status} ${response.statusText}`);
  return payload;
}

function App() {
  const [mode, setMode] = useStateApp('trace');
  const [tweaks, setTweak] = window.useTweaks ? window.useTweaks(TWEAKS) : [TWEAKS, () => {}];
  const [data, setData] = useStateApp(() => mergePDData(window.__PD_BOOTSTRAP));
  const [error, setError] = useStateApp('');
  const [busy, setBusy] = useStateApp('');

  const loadReal = useCallbackApp(async () => {
    setBusy('refresh');
    try {
      const payload = await apiRequest('/api/control-plane');
      const merged = mergePDData(payload);
      window.PD_DATA = merged;
      setData(merged);
      setError('');
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }, []);

  useEffectApp(() => {
    loadReal();
  }, [loadReal]);

  const api = useMemoApp(() => ({
    busy,
    refresh: () => loadReal(),
    request: apiRequest,
    action: async (name, body = {}) => {
      setBusy(name);
      try {
        const payload = await apiRequest(`/api/actions/${name}`, { method: 'POST', body });
        await loadReal();
        return payload;
      } finally {
        setBusy('');
      }
    },
    post: async (path, body = {}) => {
      setBusy(path);
      try {
        const payload = await apiRequest(path, { method: 'POST', body });
        await loadReal();
        return payload;
      } finally {
        setBusy('');
      }
    },
    delete: async (path) => {
      setBusy(path);
      try {
        const payload = await apiRequest(path, { method: 'DELETE' });
        await loadReal();
        return payload;
      } finally {
        setBusy('');
      }
    },
    command: async (command, body = {}) => {
      setBusy(command);
      try {
        const payload = await apiRequest('/api/ui/commands', { method: 'POST', body: { ...body, command } });
        await loadReal();
        return payload;
      } finally {
        setBusy('');
      }
    },
  }), [busy, loadReal]);

  window.PD_DATA = data;
  window.PD_API = api;

  // apply accent live
  React.useEffect(() => {
    const root = document.documentElement;
    const map = {
      cyan: '#2aa198', blue: '#268bd2', violet: '#6c71c4', green: '#859900', yellow: '#b58900',
    };
    const c = map[tweaks.accent] || map.cyan;
    root.style.setProperty('--cyan', c);
    root.style.setProperty('--cyan-soft', c + '2a');
  }, [tweaks.accent]);

  React.useEffect(() => {
    document.body.classList.toggle('cyberpunk', !!tweaks.cyberpunk);
  }, [tweaks.cyberpunk]);

  React.useEffect(() => {
    const root = document.documentElement;
    if (tweaks.contrast === 'extra') {
      root.style.setProperty('--bg-deep', '#000d12');
      root.style.setProperty('--bg', '#001620');
      root.style.setProperty('--txt', '#a8b8b6');
      root.style.setProperty('--txt-strong', '#dde7e6');
      root.style.setProperty('--txt-hi', '#fdf6e3');
    } else if (tweaks.contrast === 'standard') {
      root.style.setProperty('--bg-deep', '#002b36');
      root.style.setProperty('--bg', '#073642');
      root.style.setProperty('--txt', '#839496');
      root.style.setProperty('--txt-strong', '#93a1a1');
      root.style.setProperty('--txt-hi', '#eee8d5');
    } else {
      root.style.setProperty('--bg-deep', '#001a22');
      root.style.setProperty('--bg', '#002b36');
      root.style.setProperty('--txt', '#93a1a1');
      root.style.setProperty('--txt-strong', '#c8d4d3');
      root.style.setProperty('--txt-hi', '#fdf6e3');
    }
  }, [tweaks.contrast]);

  return (
    <>
      <Rail mode={mode} setMode={setMode} />
      <div className="mode" data-screen-label={mode}>
        <div className="pd-live-switch">
          <button className="btn ghost sm" onClick={() => api.refresh()} disabled={!!busy}>{busy ? 'WORKING' : 'REFRESH'}</button>
          {error && <span className="pd-error mono">{error}</span>}
        </div>
        {mode === 'dashboard' && <DashboardMode tweaks={tweaks} />}
        {mode === 'trace'     && <TraceMode     tweaks={tweaks} />}
        {mode === 'chat'      && <ChatMode      tweaks={tweaks} />}
        {mode === 'pair'      && <PlanMode      tweaks={tweaks} />}
        {mode === 'notion'    && <NotesMode     tweaks={tweaks} />}
        {mode === 'interests' && <InterestsMode tweaks={tweaks} />}
        {mode === 'caido'     && <CaidoMode     tweaks={tweaks} />}
      </div>

      {window.TweaksPanel && (
        <window.TweaksPanel title="Tweaks">
          <window.TweakSection label="Theme">
            <window.TweakRadio
              label="Contrast"
              value={tweaks.contrast}
              options={['standard', 'high', 'extra']}
              onChange={v => setTweak('contrast', v)}
            />
            <window.TweakRadio
              label="Accent"
              value={tweaks.accent}
              options={['cyan', 'blue', 'violet', 'green', 'yellow']}
              onChange={v => setTweak('accent', v)}
            />
            <window.TweakToggle
              label="Cyberpunk flare"
              value={tweaks.cyberpunk}
              onChange={v => setTweak('cyberpunk', v)}
            />
          </window.TweakSection>
          <window.TweakSection label="Layout">
            <window.TweakRadio
              label="Mode"
              value={mode}
              options={['dashboard', 'trace', 'chat', 'pair', 'notion', 'interests', 'caido']}
              onChange={v => setMode(v)}
            />
            <window.TweakToggle
              label="Show globe"
              value={tweaks.showGlobe}
              onChange={v => setTweak('showGlobe', v)}
            />
          </window.TweakSection>
        </window.TweaksPanel>
      )}
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
