const state = {
  dashboard: null,
  scope: null,
  audit: null,
  records: null,
  credentials: null,
  caido: null,
  skills: null,
  models: null,
  executionMode: null,
  operatorIntent: null,
  workStatus: null,
  runtimeTuning: null,
  chat: null,
  selectedTaskId: null,
  refreshTimer: null,
  continuousTimer: null,
  continuousInFlight: false,
  continuousScheduleKey: null,
};

const elements = {
  healthPill: document.getElementById("health-pill"),
  runtimeMeta: document.getElementById("runtime-meta"),
  cpuLoadText: document.getElementById("cpu-load-text"),
  cpuLoadBar: document.getElementById("cpu-load-bar"),
  gpuLoadText: document.getElementById("gpu-load-text"),
  gpuLoadBar: document.getElementById("gpu-load-bar"),
  countsGrid: document.getElementById("counts-grid"),
  currentWorkSummary: document.getElementById("current-work-summary"),
  currentWorkList: document.getElementById("current-work-list"),
  scopeCards: document.getElementById("scope-cards"),
  targetForm: document.getElementById("target-form"),
  targetHandle: document.getElementById("target-handle"),
  targetDisplayName: document.getElementById("target-display-name"),
  targetProfile: document.getElementById("target-profile"),
  targetAssets: document.getElementById("target-assets"),
  targetActiveIp: document.getElementById("target-active-ip"),
  htbTargetUpdate: document.getElementById("htb-target-update"),
  scopeImportForm: document.getElementById("scope-import-form"),
  scopeImportProfile: document.getElementById("scope-import-profile"),
  scopeImportFile: document.getElementById("scope-import-file"),
  scopeImportText: document.getElementById("scope-import-text"),
  tasksBody: document.getElementById("tasks-body"),
  detailBody: document.getElementById("detail-body"),
  detailCaption: document.getElementById("detail-caption"),
  eventsList: document.getElementById("events-list"),
  tracesList: document.getElementById("traces-list"),
  checkpointsList: document.getElementById("checkpoints-list"),
  signalsList: document.getElementById("signals-list"),
  notificationsList: document.getElementById("notifications-list"),
  syncJobsList: document.getElementById("sync-jobs-list"),
  evidenceList: document.getElementById("evidence-list"),
  notesList: document.getElementById("notes-list"),
  interestsList: document.getElementById("interests-list"),
  findingsList: document.getElementById("findings-list"),
  memoryList: document.getElementById("memory-list"),
  artifactsList: document.getElementById("artifacts-list"),
  primitivesList: document.getElementById("primitives-list"),
  credentialsStatus: document.getElementById("credentials-status"),
  integrationStatus: document.getElementById("integration-status"),
  modelsForm: document.getElementById("models-form"),
  notionForm: document.getElementById("notion-form"),
  notionApiKey: document.getElementById("notion-api-key"),
  notionParentPageId: document.getElementById("notion-parent-page-id"),
  notionVersion: document.getElementById("notion-version"),
  clearNotionButton: document.getElementById("clear-notion-button"),
  discordForm: document.getElementById("discord-form"),
  discordWebhookUrl: document.getElementById("discord-webhook-url"),
  clearDiscordButton: document.getElementById("clear-discord-button"),
  labForm: document.getElementById("lab-form"),
  labUsername: document.getElementById("lab-username"),
  labPassword: document.getElementById("lab-password"),
  labDomain: document.getElementById("lab-domain"),
  clearLabButton: document.getElementById("clear-lab-button"),
  caidoForm: document.getElementById("caido-form"),
  caidoGraphqlUrl: document.getElementById("caido-graphql-url"),
  caidoApiToken: document.getElementById("caido-api-token"),
  clearCaidoButton: document.getElementById("clear-caido-button"),
  checkCaidoButton: document.getElementById("check-caido-button"),
  chatForm: document.getElementById("chat-form"),
  chatMessage: document.getElementById("chat-message"),
  chatTarget: document.getElementById("chat-target"),
  chatMessages: document.getElementById("chat-messages"),
  guidanceForm: document.getElementById("guidance-form"),
  guidanceTarget: document.getElementById("guidance-target"),
  guidanceBody: document.getElementById("guidance-body"),
  loadGuidanceButton: document.getElementById("load-guidance-button"),
  actionLog: document.getElementById("action-log"),
  maxExecutions: document.getElementById("max-executions"),
  executionMode: document.getElementById("execution-mode"),
  operatorIntent: document.getElementById("operator-intent"),
  operatorIntentApply: document.getElementById("operator-intent-apply"),
  continuousInterval: document.getElementById("continuous-interval"),
  modeToggleButton: document.getElementById("mode-toggle-button"),
  refreshButton: document.getElementById("refresh-button"),
  tickButton: document.getElementById("tick-button"),
  compactButton: document.getElementById("compact-button"),
  queuesButton: document.getElementById("queues-button"),
  warmModelsButton: document.getElementById("warm-models-button"),
  clearModelsButton: document.getElementById("clear-models-button"),
  stopWorkButton: document.getElementById("stop-work-button"),
  runtimeSettingsForm: document.getElementById("runtime-settings-form"),
  gpuAiTimeout: document.getElementById("gpu-ai-timeout"),
  cpuAiTimeout: document.getElementById("cpu-ai-timeout"),
  staleRunTimeout: document.getElementById("stale-run-timeout"),
  minFreeCpuRam: document.getElementById("min-free-cpu-ram"),
  minFreeGpuRam: document.getElementById("min-free-gpu-ram"),
};

function setText(element, value) {
  if (element) {
    element.textContent = value == null ? "" : String(value);
  }
}

function statusClass(value) {
  return String(value || "unknown").replace(/[^a-z0-9_-]/gi, "_").toLowerCase();
}

function syncInputIfIdle(element, value) {
  if (!element) return;
  if (document.activeElement === element) return;
  element.value = value == null ? "" : String(value);
}

function clampPercent(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(100, numeric));
}

async function fetchJson(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  let payload = {};
  try {
    payload = await response.json();
  } catch (_error) {
    payload = { error: `Request failed: ${response.status}` };
  }
  if (!response.ok) {
    const message = payload.error || `Request failed: ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function setActionLog(value) {
  if (typeof value === "string") {
    setText(elements.actionLog, value);
  } else {
    setText(elements.actionLog, JSON.stringify(value, null, 2));
  }
}

async function loadHealth() {
  const health = await fetchJson("/api/health");
  setText(elements.healthPill, health.status);
  elements.healthPill.dataset.status = health.status;
  setText(
    elements.runtimeMeta,
    `${health.runtime_dir} | active modules: ${health.active_modules.join(", ") || "none"}`,
  );
}

async function loadRuntimeState() {
  const [dashboard, scope, audit, records, credentials, chat, caido, skills, models, executionMode, operatorIntent, workStatus] = await Promise.all([
    fetchJson("/api/dashboard"),
    fetchJson("/api/scope"),
    fetchJson("/api/audit?limit=24"),
    fetchJson("/api/records?limit=24"),
    fetchJson("/api/credentials"),
    fetchJson("/api/chat?limit=20"),
    fetchJson("/api/integrations/caido"),
    fetchJson("/api/skills"),
    fetchJson("/api/models"),
    fetchJson("/api/execution-mode"),
    fetchJson("/api/operator-intent"),
    fetchJson("/api/work-status"),
  ]);

  state.dashboard = dashboard;
  state.scope = scope;
  state.audit = audit;
  state.records = records;
  state.credentials = credentials;
  state.chat = chat;
  state.caido = caido;
  state.skills = skills;
  state.models = models;
  state.executionMode = executionMode;
  state.operatorIntent = operatorIntent;
  state.workStatus = workStatus;
  state.runtimeTuning = dashboard.runtime_tuning || state.runtimeTuning;

  renderDashboard();
  renderSystemMetrics();
  renderRuntimeTuning();
  renderExecutionMode();
  renderOperatorIntent();
  renderWorkStatus();
  renderScope();
  renderAudit();
  renderRecords();
  renderCredentials();
  renderIntegrations();
  renderModels();
  renderChat();
  if (state.selectedTaskId) {
    await loadTaskDetail(state.selectedTaskId);
  }
}

function renderDashboard() {
  const dashboard = state.dashboard;
  if (!dashboard) return;
  if (dashboard.execution_mode) {
    state.executionMode = dashboard.execution_mode;
    renderExecutionMode();
  }
  if (dashboard.operator_intent) {
    state.operatorIntent = dashboard.operator_intent;
    renderOperatorIntent();
  }
  if (dashboard.runtime_tuning) {
    state.runtimeTuning = dashboard.runtime_tuning;
    renderRuntimeTuning();
  }
  if (dashboard.work_status) {
    state.workStatus = dashboard.work_status;
    renderWorkStatus();
  }
  renderSystemMetrics();

  elements.countsGrid.replaceChildren(
    ...Object.entries(dashboard.counts).map(([key, value]) => {
      const card = document.createElement("article");
      card.className = "count-card";
      const label = document.createElement("span");
      label.textContent = key.replaceAll("_", " ");
      const count = document.createElement("strong");
      count.textContent = value;
      card.append(label, count);
      return card;
    }),
  );

  elements.tasksBody.replaceChildren(
    ...dashboard.tasks.map((task) => {
      const row = document.createElement("tr");
      row.dataset.taskId = task.id;
      if (task.id === state.selectedTaskId) {
        row.classList.add("selected-row");
      }
      row.addEventListener("click", async (event) => {
        if (event.target.closest("button")) return;
        await loadTaskDetail(task.id);
      });
      row.append(
        tableCell(chip(task.status, task.status)),
        tableCell(task.kind),
        tableCell(task.provider_route || "n/a"),
        tableCell(task.provider_model || "n/a"),
        tableCell(task.title),
        tableCell(taskActions(task)),
      );
      return row;
    }),
  );
}

function renderWorkStatus() {
  if (!elements.currentWorkList) return;
  const payload = state.workStatus || { summary: "No work status loaded.", active: [], queued: [], waiting: [], recent: [], web_actions: [] };
  setText(elements.currentWorkSummary, payload.summary || "No work status loaded.");

  const sections = [];
  const webActions = payload.web_actions || [];
  if (webActions.length) {
    sections.push(workSection("Web Actions", webActions, formatWebAction));
  }
  sections.push(workSection("Active", payload.active || [], formatWorkItem));
  sections.push(workSection("Queued", payload.queued || [], formatWorkItem));
  sections.push(workSection("Waiting / Approval", payload.waiting || [], formatWorkItem));
  sections.push(workSection("Recent", payload.recent || [], formatWorkItem));
  elements.currentWorkList.replaceChildren(...sections);
}

function renderSystemMetrics() {
  const metrics = state.dashboard?.system_metrics || {};
  const cpu = metrics.cpu || {};
  const gpu = metrics.gpu || {};
  const cpuPercent = clampPercent(cpu.percent);
  const gpuPercent = clampPercent(gpu.percent);
  if (elements.cpuLoadBar) {
    elements.cpuLoadBar.style.width = `${cpuPercent}%`;
  }
  if (elements.gpuLoadBar) {
    elements.gpuLoadBar.style.width = `${gpuPercent}%`;
  }
  const cpuText = cpu.available === false
    ? "CPU unavailable"
    : `util ${cpuPercent.toFixed(1)}% | RAM avail ${Number(cpu.memory_available_mb || 0).toFixed(0)}/${Number(cpu.memory_total_mb || 0).toFixed(0)} MB | load1 ${Number(cpu.load_1 || 0).toFixed(2)} / ${cpu.cpu_count || "?"} cores`;
  setText(elements.cpuLoadText, cpuText);
  const gpuText = gpu.available === false
    ? (gpu.error || "GPU unavailable")
    : `util ${gpuPercent.toFixed(1)}% | VRAM free ${Number(gpu.memory_free_mb || 0).toFixed(0)} MB (${Number(gpu.memory_used_mb || 0).toFixed(0)}/${Number(gpu.memory_total_mb || 0).toFixed(0)} MB used)`;
  setText(elements.gpuLoadText, gpuText);
}

function renderRuntimeTuning() {
  const tuning = state.runtimeTuning || state.dashboard?.runtime_tuning;
  if (!tuning) return;
  syncInputIfIdle(elements.gpuAiTimeout, tuning.gpu_ai_timeout_seconds ?? 120);
  syncInputIfIdle(elements.cpuAiTimeout, tuning.cpu_ai_timeout_seconds ?? 300);
  syncInputIfIdle(elements.staleRunTimeout, tuning.stale_run_timeout_seconds ?? 3600);
  syncInputIfIdle(elements.minFreeCpuRam, tuning.min_free_cpu_ram_mb ?? 2048);
  syncInputIfIdle(elements.minFreeGpuRam, tuning.min_free_gpu_ram_mb ?? 368);
}

function workSection(titleText, items, formatter) {
  const card = document.createElement("article");
  card.className = "mini-card work-status-card";
  const title = document.createElement("h3");
  title.textContent = titleText;
  card.append(title);
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "none";
    card.append(empty);
    return card;
  }
  const list = document.createElement("ul");
  list.className = "work-list";
  for (const item of items.slice(0, 8)) {
    const row = document.createElement("li");
    row.textContent = formatter(item);
    list.append(row);
  }
  card.append(list);
  return card;
}

function formatWorkItem(item) {
  const status = item.status || "unknown";
  const target = item.target || "global";
  const agent = item.agent || "unknown-agent";
  const model = item.model || "unknown-model";
  const route = item.route || "unknown-route";
  const title = item.title || item.summary || "untitled";
  return `${status} | ${target} | ${agent} | ${model} | ${route} | ${title}`;
}

function formatWebAction(item) {
  return `${item.status || "running"} | ${item.label || "web action"} | started=${item.started_at || "unknown"}`;
}

function renderExecutionMode() {
  const payload = state.executionMode || { mode: "tick", interval_seconds: 30 };
  const mode = payload.mode || "tick";
  const interval = payload.interval_seconds || 30;
  const scheduleKey = `${mode}:${interval}`;
  elements.executionMode.value = mode;
  syncInputIfIdle(elements.continuousInterval, interval);
  elements.modeToggleButton.textContent = mode === "continuous" ? "Switch To Tick Mode" : "Enable Continuous Mode";
  elements.modeToggleButton.className = mode === "continuous" ? "danger-button" : "ghost-button";
  elements.tickButton.className = mode === "continuous" ? "muted-stop-button" : "";
  elements.tickButton.disabled = mode === "continuous";
  elements.stopWorkButton.className = "danger-button";
  elements.stopWorkButton.disabled = false;
  if (state.continuousScheduleKey !== scheduleKey) {
    state.continuousScheduleKey = scheduleKey;
    scheduleContinuousLoop();
  }
}

function renderOperatorIntent() {
  if (!elements.operatorIntent) return;
  const payload = state.operatorIntent || state.dashboard?.operator_intent;
  if (!payload) return;
  const active = payload.active?.id || payload.default || "recon_only";
  const options = (payload.intents || []).map((intent) => {
    const option = document.createElement("option");
    option.value = intent.id;
    option.textContent = intent.label || intent.id;
    return option;
  });
  if (options.length) {
    elements.operatorIntent.replaceChildren(...options);
  }
  elements.operatorIntent.value = active;
}

function tableCell(content) {
  const cell = document.createElement("td");
  if (content instanceof Node) {
    cell.append(content);
  } else {
    cell.textContent = String(content ?? "");
  }
  return cell;
}

function chip(text, status) {
  const item = document.createElement("span");
  item.className = `status-chip status-${statusClass(status)}`;
  item.textContent = text;
  return item;
}

function taskActions(task) {
  const wrapper = document.createElement("div");
  wrapper.className = "approval-actions";
  if (task.status === "needs_approval") {
    const approve = document.createElement("button");
    approve.type = "button";
    approve.textContent = "Approve";
    approve.addEventListener("click", async () => runAction("/api/actions/approve", { task_id: task.id }));
    const deny = document.createElement("button");
    deny.type = "button";
    deny.className = "ghost-button";
    deny.textContent = "Deny";
    deny.addEventListener("click", async () => runAction("/api/actions/deny", { task_id: task.id }));
    wrapper.append(approve, deny);
    return wrapper;
  }
  const inspect = document.createElement("button");
  inspect.type = "button";
  inspect.className = "ghost-button";
  inspect.textContent = "Inspect";
  inspect.addEventListener("click", async () => loadTaskDetail(task.id));
  wrapper.append(inspect);
  return wrapper;
}

function renderScope() {
  const scope = state.scope;
  if (!scope) return;

  elements.scopeCards.replaceChildren(
    ...scope.targets.map((entry) => {
      const card = document.createElement("article");
      card.className = "scope-card";

      const head = document.createElement("div");
      head.className = "scope-card-head";
      const titleBlock = document.createElement("div");
      const title = document.createElement("h3");
      title.textContent = entry.target.display_name;
      const meta = document.createElement("p");
      meta.className = "muted";
      meta.textContent = `${entry.target.handle} | ${entry.target.profile}`;
      titleBlock.append(title, meta);
      head.append(titleBlock, chip(entry.target.in_scope ? "in_scope" : "out_of_scope", entry.target.in_scope ? "succeeded" : "blocked"));

      const counts = document.createElement("p");
      counts.className = "scope-counts";
      counts.textContent =
        `assets=${entry.counts.assets} tasks=${entry.counts.tasks} evidence=${entry.counts.evidence} ` +
        `notes=${entry.counts.notes} interests=${entry.counts.interests} findings=${entry.counts.findings}`;

      const actions = document.createElement("div");
      actions.className = "scope-actions";
      const edit = document.createElement("button");
      edit.type = "button";
      edit.className = "ghost-button";
      edit.textContent = "Load In Form";
      edit.addEventListener("click", () => loadTargetIntoForm(entry));
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "ghost-button";
      remove.textContent = "Remove Target";
      remove.addEventListener("click", async () => removeTarget(entry.target.handle, entry.target.profile));
      actions.append(edit, remove);

      const assets = document.createElement("ul");
      assets.className = "asset-list";
      for (const asset of entry.assets) {
        const item = document.createElement("li");
        const type = document.createElement("strong");
        type.textContent = asset.asset_type;
        item.append(type, ` ${asset.asset}`);
        assets.append(item);
      }

      card.append(head, counts, actions, assets);
      return card;
    }),
  );
}

function loadTargetIntoForm(entry) {
  elements.targetHandle.value = entry.target.handle || "";
  elements.targetDisplayName.value = entry.target.display_name || "";
  elements.targetProfile.value = entry.target.profile || "hackerone";
  elements.targetAssets.value = (entry.assets || []).map((asset) => asset.asset).join(", ");
  elements.targetActiveIp.value = entry.target.metadata?.active_ip || "";
}

function collectTargetPayload() {
  const handle = elements.targetHandle.value.trim();
  const activeIp = elements.targetActiveIp.value.trim();
  const assets = elements.targetAssets.value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (handle && !assets.includes(handle)) {
    assets.unshift(handle);
  }
  if (activeIp && !assets.includes(activeIp)) {
    assets.push(activeIp);
  }
  return {
    handle,
    display_name: elements.targetDisplayName.value.trim() || undefined,
    profile: elements.targetProfile.value,
    assets,
    active_ip: activeIp || undefined,
    in_scope: true,
    metadata: { source: "web_target_form" },
  };
}

async function submitTargetUpdate() {
  try {
    const payload = await fetchJson("/api/targets", {
      method: "POST",
      body: JSON.stringify(collectTargetPayload()),
    });
    elements.targetForm.reset();
    elements.targetProfile.value = "hackerone";
    applyActionPayload(payload);
  } catch (error) {
    setActionLog(`Target update failed: ${error.message}`);
  }
}

async function removeTarget(handle, profile) {
  if (!window.confirm(`Remove ${handle} and all linked runtime records?`)) {
    return;
  }
  try {
    const payload = await fetchJson(
      `/api/targets/${encodeURIComponent(handle)}?profile=${encodeURIComponent(profile)}`,
      { method: "DELETE" },
    );
    applyActionPayload(payload);
    if (state.selectedTaskId && !state.dashboard.tasks.some((task) => task.id === state.selectedTaskId)) {
      state.selectedTaskId = null;
      setText(elements.detailCaption, "No task selected.");
      setEmptyDetail();
    }
  } catch (error) {
    setActionLog(`Target removal failed: ${error.message}`);
  }
}

function renderAudit() {
  const audit = state.audit;
  if (!audit) return;
  renderLogList(elements.eventsList, audit.recent_events, (item) =>
    `${item.created_at} | ${item.type} | ${item.summary}`,
  );
  renderLogList(elements.tracesList, audit.recent_traces, (item) =>
    `${item.created_at} | ${item.role} | ${item.status} | ${item.summary}`,
  );
  renderLogList(elements.checkpointsList, audit.recent_checkpoints, (item) =>
    `${item.created_at} | ${item.summary} | ${item.path}`,
  );
  renderLogList(elements.signalsList, audit.recent_runtime_events, (item) =>
    `${item.created_at} | ${item.signal} | ${JSON.stringify(item.payload)}`,
  );
  renderLogList(elements.notificationsList, audit.recent_notifications, (item) =>
    `${item.created_at} | ${item.status} | ${item.urgency} | ${item.summary}`,
  );
  renderLogList(elements.syncJobsList, audit.recent_sync_jobs, (item) =>
    `${item.created_at} | ${item.kind} | ${item.status} | ${item.summary}${item.last_error ? ` | ${item.last_error}` : ""}`,
  );
}

function renderLogList(element, items, formatter) {
  if (!element) return;
  element.replaceChildren(
    ...(items && items.length
      ? items.map((item) => {
          const row = document.createElement("li");
          row.textContent = formatter(item);
          return row;
        })
      : [emptyListItem("No records yet.")]),
  );
}

function emptyListItem(message) {
  const item = document.createElement("li");
  item.className = "muted";
  item.textContent = message;
  return item;
}

function renderRecords() {
  const records = state.records;
  if (!records) return;
  renderRecordCards(elements.evidenceList, records.evidence, (item) => ({
    title: `${item.type}: ${item.title}`,
    meta: `${item.verification_status} | confidence=${item.confidence} | freshness=${item.freshness}`,
    body: item.summary,
  }));
  renderRecordCards(elements.notesList, records.notes, (item) => ({
    title: item.title,
    meta: `confidence=${item.confidence} | freshness=${item.freshness}`,
    body: item.body,
  }));
  renderRecordCards(elements.interestsList, records.interests, (item) => ({
    title: item.title,
    meta: `${item.status} | confidence=${item.confidence} | evidence=${item.evidence_refs.length}`,
    body: item.summary,
  }));
  renderRecordCards(elements.findingsList, records.findings, (item) => ({
    title: `${item.severity}: ${item.title}`,
    meta: `${item.verification_status} | confidence=${item.confidence}`,
    body: item.summary,
  }));
  renderRecordCards(elements.memoryList, records.memory_entries, (item) => ({
    title: `${item.layer}: ${item.title}`,
    meta: `${item.status} | confidence=${item.confidence} | freshness=${item.freshness}`,
    body: item.summary,
  }));
  renderRecordCards(elements.artifactsList, records.artifacts, (item) => ({
    title: `${item.kind}: ${item.id}`,
    meta: `${item.size_bytes} bytes | sha256=${item.sha256}`,
    body: item.path,
  }));
  renderRecordCards(elements.primitivesList, records.primitives, (item) => ({
    title: `${item.name} ${item.version}`,
    meta: `${item.runtime} | risk=${item.risk_tier} | side_effect=${item.side_effect_level}`,
    body: `${item.description} | capabilities=${item.capability_tags.join(", ")}`,
  }));
}

function renderRecordCards(element, items, formatter) {
  if (!element) return;
  element.replaceChildren(
    ...(items && items.length
      ? items.map((item) => {
          const formatted = formatter(item);
          const card = document.createElement("article");
          card.className = "mini-card";
          const title = document.createElement("h3");
          title.textContent = formatted.title;
          const meta = document.createElement("p");
          meta.className = "muted mono";
          meta.textContent = formatted.meta;
          const body = document.createElement("p");
          body.textContent = formatted.body;
          card.append(title, meta, body);
          return card;
        })
      : [emptyListItem("No records yet.")]),
  );
}

function renderCredentials() {
  const credentials = state.credentials;
  if (!credentials) return;
  const services = credentials.services || {};
  const cards = Object.entries(services).map(([service, fields]) => {
    const card = document.createElement("article");
    card.className = "mini-card";
    const title = document.createElement("h3");
    title.textContent = service;
    card.append(title);
    for (const [key, status] of Object.entries(fields)) {
      const line = document.createElement("p");
      line.className = "mono";
      const configured = status.configured ? "configured" : "missing";
      line.textContent = `${key}: ${configured} (${status.source}) ${status.hint || ""}`;
      card.append(line);
    }
    return card;
  });
  elements.credentialsStatus.replaceChildren(...cards);
}

function renderIntegrations() {
  if (!elements.integrationStatus) return;
  const caido = state.caido || {};
  const skills = state.skills?.skills || [];
  const caidoCard = document.createElement("article");
  caidoCard.className = "mini-card";
  const caidoTitle = document.createElement("h3");
  caidoTitle.textContent = "Caido";
  const caidoMeta = document.createElement("p");
  caidoMeta.className = "mono";
  caidoMeta.textContent = `configured=${Boolean(caido.configured)} ok=${caido.ok === undefined ? "not checked" : caido.ok}`;
  const caidoBody = document.createElement("p");
  caidoBody.textContent = caido.error || caido.graphql_url || "No Caido endpoint configured.";
  caidoCard.append(caidoTitle, caidoMeta, caidoBody);

  const skillsCard = document.createElement("article");
  skillsCard.className = "mini-card";
  const skillsTitle = document.createElement("h3");
  skillsTitle.textContent = "Runtime Skills";
  const skillsMeta = document.createElement("p");
  skillsMeta.className = "mono";
  skillsMeta.textContent = `${skills.length} loaded`;
  const skillsBody = document.createElement("p");
  skillsBody.textContent = skills.map((skill) => skill.id).join(", ") || "No skills loaded.";
  skillsCard.append(skillsTitle, skillsMeta, skillsBody);

  elements.integrationStatus.replaceChildren(caidoCard, skillsCard);
}

function renderModels() {
  if (!elements.modelsForm) return;
  const models = state.models || {};
  const available = models.available_models || [];
  const roleCards = (models.roles || []).map((role) => {
    const card = document.createElement("article");
    card.className = "credential-form";
    const title = document.createElement("h3");
    title.textContent = role.label;
    const description = document.createElement("p");
    description.className = "muted";
    const gpuNote = role.num_gpu === 0 ? "CPU enforced with Ollama num_gpu=0" : "GPU/default Ollama runtime";
    description.textContent = `${role.description} Processor: ${role.processor.toUpperCase()} (${gpuNote}). Default model: ${role.default_model}. Default processor: ${role.default_processor}.`;
    const modelLabel = document.createElement("label");
    modelLabel.className = "field";
    const modelSpan = document.createElement("span");
    modelSpan.textContent = `${role.label} Model`;
    const select = document.createElement("select");
    select.dataset.role = role.role;
    for (const model of available) {
      const option = document.createElement("option");
      option.value = model;
      option.textContent = model;
      if (model === role.selected_model) {
        option.selected = true;
      }
      select.append(option);
    }
    modelLabel.append(modelSpan, select);

    const processorLabel = document.createElement("label");
    processorLabel.className = "field";
    const processorSpan = document.createElement("span");
    processorSpan.textContent = `${role.label} Processor`;
    const processorSelect = document.createElement("select");
    processorSelect.dataset.processorRole = role.role;
    for (const processor of role.processor_options || ["gpu", "cpu"]) {
      const option = document.createElement("option");
      option.value = processor;
      option.textContent = processor === "cpu" ? "CPU (force num_gpu=0)" : "GPU / Ollama default";
      if (processor === role.processor) {
        option.selected = true;
      }
      processorSelect.append(option);
    }
    processorLabel.append(processorSpan, processorSelect);
    card.append(title, description, modelLabel, processorLabel);
    return card;
  });
  const actions = document.createElement("div");
  actions.className = "approval-actions";
  const save = document.createElement("button");
  save.type = "submit";
  save.textContent = "Apply Model Roles";
  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.className = "ghost-button";
  refresh.textContent = "Refresh Ollama Models";
  refresh.addEventListener("click", async () => {
    state.models = await fetchJson("/api/models");
    renderModels();
  });
  actions.append(save, refresh);
  elements.modelsForm.replaceChildren(...roleCards, actions);
}

function renderChat() {
  if (!elements.chatMessages) return;
  const messages = state.chat?.messages || [];
  elements.chatMessages.replaceChildren(
    ...(messages.length
      ? messages.map((message) => chatMessageCard(message))
      : [emptyChatMessage("No operator messages yet.")]),
  );
  elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
}

function emptyChatMessage(message) {
  const card = document.createElement("article");
  card.className = "chat-message";
  const body = document.createElement("p");
  body.className = "muted";
  body.textContent = message;
  card.append(body);
  return card;
}

function chatMessageCard(message) {
  const card = document.createElement("article");
  card.className = "chat-message";
  card.dataset.role = message.role || "operator";

  const head = document.createElement("div");
  head.className = "chat-message-head";
  const left = document.createElement("strong");
  left.textContent = message.role === "assistant" ? "Primordial AI" : "Operator";
  const right = document.createElement("span");
  right.className = "muted mono";
  right.textContent = [message.model, message.created_at].filter(Boolean).join(" | ");
  head.append(left, right);

  const body = document.createElement("p");
  body.textContent = message.body;
  card.append(head, body);
  return card;
}

async function submitChatMessage() {
  const message = elements.chatMessage.value.trim();
  const target = elements.chatTarget.value.trim();
  if (!message) {
    setActionLog("Operator AI message is required.");
    return;
  }
  setActionLog("Operator AI is building a bounded runtime answer...");
  try {
    const result = await fetchJson("/api/chat", {
      method: "POST",
      body: JSON.stringify({ message, target: target || undefined }),
    });
    if (result.result?.chat) {
      state.chat = result.result.chat.chat || result.result.chat;
    }
    elements.chatMessage.value = "";
    applyActionPayload(result);
  } catch (error) {
    setActionLog(`Operator AI failed: ${error.message}`);
  }
}

async function loadTaskDetail(taskId) {
  state.selectedTaskId = taskId;
  const detail = await fetchJson(`/api/tasks/${encodeURIComponent(taskId)}?limit=20`);
  setText(elements.detailCaption, `${detail.task.kind} | ${detail.task.status}`);
  elements.detailBody.replaceChildren(
    detailSection(detail.task.title, detail.task.summary, detail.task.metadata),
    detailSection("Runs", "", detail.runs),
    detailSection("Traces", "", detail.traces),
    detailSection("Checkpoints", "", detail.checkpoints),
    detailSection("Handoffs", "", detail.handoffs),
    detailSection("Events", "", detail.events),
  );
  renderDashboard();
}

function detailSection(titleText, paragraphText, payload) {
  const section = document.createElement("section");
  section.className = "detail-section";
  const title = document.createElement("h3");
  title.textContent = titleText;
  section.append(title);
  if (paragraphText) {
    const paragraph = document.createElement("p");
    paragraph.textContent = paragraphText;
    section.append(paragraph);
  }
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(payload, null, 2);
  section.append(pre);
  return section;
}

function setEmptyDetail() {
  const paragraph = document.createElement("p");
  paragraph.className = "muted";
  paragraph.textContent = "Select a task to inspect runs, traces, checkpoints, and handoffs.";
  elements.detailBody.replaceChildren(paragraph);
}

async function runAction(path, payload = {}) {
  try {
    const result = await fetchJson(path, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    applyActionPayload(result);
    if (state.selectedTaskId) {
      await loadTaskDetail(state.selectedTaskId);
    }
  } catch (error) {
    setActionLog(`Action failed: ${error.message}`);
  }
}

function applyActionPayload(payload) {
  applyActionState(payload, { log: true });
}

function applyActionState(payload, options = { log: true }) {
  state.dashboard = payload.dashboard;
  state.scope = payload.scope;
  state.audit = payload.audit;
  if (payload.credentials) {
    state.credentials = payload.credentials;
  }
  if (payload.caido) {
    state.caido = payload.caido;
  }
  if (payload.skills) {
    state.skills = payload.skills;
  }
  if (payload.models) {
    state.models = payload.models;
  }
  if (payload.execution_mode) {
    state.executionMode = payload.execution_mode;
  }
  if (payload.operator_intent) {
    state.operatorIntent = payload.operator_intent;
  }
  if (payload.work_status) {
    state.workStatus = payload.work_status;
  }
  if (payload.dashboard?.runtime_tuning) {
    state.runtimeTuning = payload.dashboard.runtime_tuning;
  }
  if (payload.result?.runtime_tuning) {
    state.runtimeTuning = payload.result.runtime_tuning;
  }
  if (payload.result?.execution_mode) {
    state.executionMode = payload.result.execution_mode;
  }
  if (payload.result?.operator_intent) {
    state.operatorIntent = payload.result.operator_intent;
  }
  if (payload.result?.chat) {
    state.chat = payload.result.chat.chat || payload.result.chat;
  }
  if (options.log !== false) {
    setActionLog(payload.result);
  }
  renderDashboard();
  renderSystemMetrics();
  renderRuntimeTuning();
  renderWorkStatus();
  renderScope();
  renderAudit();
  renderCredentials();
  renderIntegrations();
  renderModels();
  renderExecutionMode();
  renderOperatorIntent();
  renderChat();
  loadRuntimeState().catch((error) => setActionLog(`Refresh failed: ${error.message}`));
}

async function updateExecutionMode(mode) {
  try {
    await runAction("/api/execution-mode", {
      mode,
      interval_seconds: Number(elements.continuousInterval.value || 30),
    });
  } catch (error) {
    setActionLog(`Execution mode update failed: ${error.message}`);
  }
}

function scheduleContinuousLoop() {
  if (state.continuousTimer) {
    clearTimeout(state.continuousTimer);
    state.continuousTimer = null;
  }
  if ((state.executionMode?.mode || "tick") !== "continuous") {
    state.continuousScheduleKey = `${state.executionMode?.mode || "tick"}:${state.executionMode?.interval_seconds || 30}`;
    return;
  }
  const interval = Math.max(2, Number(state.executionMode?.interval_seconds || elements.continuousInterval.value || 30));
  state.continuousTimer = setTimeout(runContinuousTick, interval * 1000);
}

async function runContinuousTick() {
  state.continuousTimer = null;
  if ((state.executionMode?.mode || "tick") !== "continuous" || state.continuousInFlight) {
    scheduleContinuousLoop();
    return;
  }
  state.continuousInFlight = true;
  try {
    const result = await fetchJson("/api/actions/tick", {
      method: "POST",
      body: JSON.stringify({
        max_executions: Number(elements.maxExecutions.value || 3),
      }),
    });
    if (isNoopTickPayload(result)) {
      applyActionState(result, { log: false });
    } else {
      applyActionPayload(result);
    }
  } finally {
    state.continuousInFlight = false;
    scheduleContinuousLoop();
  }
}

function isNoopTickPayload(payload) {
  if (payload?.action !== "tick") return false;
  const report = payload.result?.report;
  if (!report) return false;
  return String(report.summary || "").includes("created_tasks=0")
    && String(report.summary || "").includes("completed_runs=0");
}

async function saveCredentials(path, payload, form) {
  try {
    const result = await fetchJson(path, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    state.credentials = result.credentials || result.result.credentials;
    form.reset();
    applyActionPayload(result);
  } catch (error) {
    setActionLog(`Credential update failed: ${error.message}`);
  }
}

async function clearCredentials(service) {
  try {
    const result = await fetchJson(`/api/credentials/${encodeURIComponent(service)}`, { method: "DELETE" });
    state.credentials = result.credentials || result.result.credentials;
    applyActionPayload(result);
  } catch (error) {
    setActionLog(`Credential clear failed: ${error.message}`);
  }
}

async function loadGuidance() {
  const target = elements.guidanceTarget.value.trim();
  if (!target) {
    setActionLog("Guidance target is required.");
    return;
  }
  try {
    const payload = await fetchJson(`/api/findings-context?target=${encodeURIComponent(target)}&include_guidance=1`);
    elements.guidanceBody.value = payload.workspace?.guidance || "";
    setActionLog(`Loaded guidance for ${target} from ${payload.workspace?.guidance_path || "local findings context"}.`);
  } catch (error) {
    setActionLog(`Guidance load failed: ${error.message}`);
  }
}

async function saveGuidance() {
  const target = elements.guidanceTarget.value.trim();
  if (!target) {
    setActionLog("Guidance target is required.");
    return;
  }
  try {
    const payload = await fetchJson("/api/findings-context/guidance", {
      method: "POST",
      body: JSON.stringify({
        target,
        guidance: elements.guidanceBody.value,
      }),
    });
    applyActionPayload(payload);
  } catch (error) {
    setActionLog(`Guidance save failed: ${error.message}`);
  }
}

async function readScopeImportText() {
  const file = elements.scopeImportFile.files?.[0];
  if (file) {
    return {
      source: file.name,
      text: await file.text(),
    };
  }
  return {
    source: "web textarea import",
    text: elements.scopeImportText.value,
  };
}

function parseScopeImport(text, profile) {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("scope JSON, file, or line-based assets are required");
  }
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      return { profile, targets: parsed };
    }
    if (parsed && typeof parsed === "object") {
      return { profile, ...parsed };
    }
  } catch (_error) {
    // Fall through to line-based scope import.
  }
  const targets = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => ({
      handle: line,
      display_name: line,
      in_scope: true,
      assets: [line],
    }));
  return { profile, targets };
}

async function initialize() {
  elements.refreshButton.addEventListener("click", async () => {
    try {
      await loadHealth();
      await loadRuntimeState();
    } catch (error) {
      setActionLog(`Refresh failed: ${error.message}`);
    }
  });
  elements.tickButton.addEventListener("click", async () => {
    if (elements.tickButton.disabled) return;
    await runAction("/api/actions/tick", {
      max_executions: Number(elements.maxExecutions.value || 3),
    });
  });
  elements.modeToggleButton.addEventListener("click", async () => {
    const current = state.executionMode?.mode || elements.executionMode.value || "tick";
    await updateExecutionMode(current === "continuous" ? "tick" : "continuous");
  });
  elements.executionMode.addEventListener("change", async () => {
    await updateExecutionMode(elements.executionMode.value);
  });
  elements.compactButton.addEventListener("click", async () => runAction("/api/actions/compact"));
  elements.queuesButton.addEventListener("click", async () => runAction("/api/actions/process-queues"));
  elements.warmModelsButton.addEventListener("click", async () => runAction("/api/actions/warm-models", { keep_alive: "8h" }));
  elements.clearModelsButton.addEventListener("click", async () => runAction("/api/actions/clear-models"));
  elements.stopWorkButton.addEventListener("click", async () => {
    await runAction("/api/actions/stop-work");
  });
  elements.runtimeSettingsForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await runAction("/api/runtime-settings", {
      gpu_ai_timeout_seconds: Number(elements.gpuAiTimeout.value || 120),
      cpu_ai_timeout_seconds: Number(elements.cpuAiTimeout.value || 300),
      stale_run_timeout_seconds: Number(elements.staleRunTimeout.value || 3600),
      min_free_cpu_ram_mb: Number(elements.minFreeCpuRam.value || 2048),
      min_free_gpu_ram_mb: Number(elements.minFreeGpuRam.value || 368),
    });
  });
  elements.modelsForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const roles = {};
    const processors = {};
    for (const select of elements.modelsForm.querySelectorAll("select[data-role]")) {
      roles[select.dataset.role] = select.value;
    }
    for (const select of elements.modelsForm.querySelectorAll("select[data-processor-role]")) {
      processors[select.dataset.processorRole] = select.value;
    }
    await runAction("/api/models", { roles, processors });
  });

  elements.targetForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitTargetUpdate();
  });
  elements.htbTargetUpdate.addEventListener("click", async () => {
    elements.targetProfile.value = "hack_the_box";
    await submitTargetUpdate();
  });
  elements.operatorIntentApply.addEventListener("click", async () => {
    await runAction("/api/operator-intent", { intent_id: elements.operatorIntent.value });
  });
  elements.scopeImportForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const { source, text } = await readScopeImportText();
      const profile = elements.scopeImportProfile.value;
      const scope = parseScopeImport(text, profile);
      const payload = await fetchJson("/api/scope/import", {
        method: "POST",
        body: JSON.stringify({ profile, source, scope }),
      });
      elements.scopeImportForm.reset();
      elements.scopeImportProfile.value = profile;
      applyActionPayload(payload);
    } catch (error) {
      setActionLog(`Scope import failed: ${error.message}`);
    }
  });

  elements.notionForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await saveCredentials(
      "/api/credentials/notion",
      {
        api_key: elements.notionApiKey.value.trim(),
        parent_page_id: elements.notionParentPageId.value.trim(),
        version: elements.notionVersion.value.trim(),
      },
      elements.notionForm,
    );
  });
  elements.clearNotionButton.addEventListener("click", async () => clearCredentials("notion"));
  elements.discordForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await saveCredentials(
      "/api/credentials/discord",
      { webhook_url: elements.discordWebhookUrl.value.trim() },
      elements.discordForm,
    );
  });
  elements.clearDiscordButton.addEventListener("click", async () => clearCredentials("discord"));
  elements.labForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await saveCredentials(
      "/api/credentials/lab",
      {
        username: elements.labUsername.value.trim(),
        password: elements.labPassword.value,
        domain: elements.labDomain.value.trim(),
      },
      elements.labForm,
    );
  });
  elements.clearLabButton.addEventListener("click", async () => clearCredentials("lab"));
  elements.caidoForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await saveCredentials(
      "/api/credentials/caido",
      {
        graphql_url: elements.caidoGraphqlUrl.value.trim(),
        api_token: elements.caidoApiToken.value,
      },
      elements.caidoForm,
    );
  });
  elements.clearCaidoButton.addEventListener("click", async () => clearCredentials("caido"));
  elements.checkCaidoButton.addEventListener("click", async () => {
    try {
      state.caido = await fetchJson("/api/integrations/caido?check_health=1");
      renderIntegrations();
      setActionLog(state.caido);
    } catch (error) {
      setActionLog(`Caido check failed: ${error.message}`);
    }
  });
  elements.chatForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitChatMessage();
  });
  elements.loadGuidanceButton.addEventListener("click", async () => loadGuidance());
  elements.guidanceForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await saveGuidance();
  });

  try {
    await loadHealth();
    await loadRuntimeState();
  } catch (error) {
    setActionLog(`Initialization failed: ${error.message}`);
  }

  state.refreshTimer = window.setInterval(async () => {
    try {
      await loadHealth();
      await loadRuntimeState();
    } catch (_error) {}
  }, 7000);
}

initialize().catch((error) => {
  setActionLog(`Initialization failed: ${error.message}`);
});
