const state = {
  user: null,
  instances: [],
  serverGroups: {
    stunServers: [],
    httpServers: [],
    quicServers: [],
  },
  serverGroupsDirty: false,
  poller: null,
  checkPoller: null,
  checkRunInFlight: false,
  filter: "all",
  search: "",
  copiedAddressKey: null,
  initialChecked: new Set(),
  activeLogInstanceId: "",
};

const el = {
  login: document.querySelector("#login"),
  app: document.querySelector("#app"),
  loginForm: document.querySelector("#loginForm"),
  loginError: document.querySelector("#loginError"),
  logoutBtn: document.querySelector("#logoutBtn"),
  newBtn: document.querySelector("#newBtn"),
  instanceList: document.querySelector("#instanceList"),
  searchInput: document.querySelector("#searchInput"),
  filterTabs: document.querySelectorAll(".filter-tab"),
  pageSummary: document.querySelector("#pageSummary"),
  pageError: document.querySelector("#pageError"),
  modal: document.querySelector("#configModal"),
  modalTitle: document.querySelector("#modalTitle"),
  modalMark: document.querySelector("#modalMark"),
  modalCloseBtn: document.querySelector("#modalCloseBtn"),
  modalCancelBtn: document.querySelector("#modalCancelBtn"),
  deleteConfigBtn: document.querySelector("#deleteConfigBtn"),
  form: document.querySelector("#configForm"),
  formScroll: document.querySelector(".form-scroll"),
  formNavItems: document.querySelectorAll(".form-nav-item"),
  formError: document.querySelector("#formError"),
  httpFields: document.querySelector("#httpFields"),
  stunCustomFields: document.querySelector("#stunCustomFields"),
  stunGroupFields: document.querySelector("#stunGroupFields"),
  keepAliveGroupFields: document.querySelector("#keepAliveGroupFields"),
  keepAliveSourceLabel: document.querySelector("#keepAliveSourceLabel"),
  keepAliveGroupButton: document.querySelector("#keepAliveGroupButton"),
  keepAliveGroupTitle: document.querySelector("#keepAliveGroupTitle"),
  keepAliveGroupHint: document.querySelector("#keepAliveGroupHint"),
  probeTimingRow: document.querySelector("#probeTimingRow"),
  httpHostLabel: document.querySelector("#httpHostLabel"),
  httpPortLabel: document.querySelector("#httpPortLabel"),
  keepAliveSecondsField: document.querySelector("#keepAliveSecondsField"),
  protocolSegments: document.querySelectorAll(".segment[data-protocol]"),
  sourceSegments: document.querySelectorAll(".segment[data-source-field]"),
  scriptVarButtons: document.querySelectorAll("[data-script-var]"),
  notifyTestBtn: document.querySelector("#notifyTestBtn"),
  notifyTestPanel: document.querySelector("#notifyTestPanel"),
  notifyTestStatus: document.querySelector("#notifyTestStatus"),
  notifyTestMeta: document.querySelector("#notifyTestMeta"),
  notifyTestOutput: document.querySelector("#notifyTestOutput"),
  logModal: document.querySelector("#logModal"),
  logTitle: document.querySelector("#logTitle"),
  logSubtitle: document.querySelector("#logSubtitle"),
  logList: document.querySelector("#logList"),
  logCloseBtn: document.querySelector("#logCloseBtn"),
  confirmModal: document.querySelector("#confirmModal"),
  confirmTitle: document.querySelector("#confirmTitle"),
  confirmMessage: document.querySelector("#confirmMessage"),
  confirmOkBtn: document.querySelector("#confirmOkBtn"),
  confirmCancelBtn: document.querySelector("#confirmCancelBtn"),
};

function emptyConfig() {
  return {
    id: "",
    name: "New Mapping",
    enabled: false,
    protocol: "tcp",
    bindPort: "0",
    stunMode: "custom",
    stunGroupId: "",
    stunHost: "",
    stunPort: 0,
    keepAliveMode: "custom",
    keepAliveGroupId: "",
    httpHost: "qq.com",
    httpPort: 80,
    interface: "",
    keepAliveSeconds: 30,
    mappingConfirmations: 3,
    notifyScript: "",
    fwMark: 0,
  };
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  let data = null;
  const text = await response.text();
  if (text) {
    data = JSON.parse(text);
  }

  if (response.status === 401) {
    showLogin();
    throw new Error(data?.error || "需要登录");
  }
  if (!response.ok) {
    throw new Error(data?.error || `HTTP ${response.status}`);
  }
  return data;
}

function showLogin() {
  el.login.classList.remove("hidden");
  el.app.classList.add("hidden");
  closeModal();
  closeLogModal();
  if (state.poller) {
    clearInterval(state.poller);
    state.poller = null;
  }
  if (state.checkPoller) {
    clearInterval(state.checkPoller);
    state.checkPoller = null;
  }
}

function showApp() {
  el.login.classList.add("hidden");
  el.app.classList.remove("hidden");
  if (!state.poller) {
    state.poller = setInterval(() => loadInstances().catch(() => {}), 1000);
  }
  if (!state.checkPoller) {
    state.checkPoller = setInterval(() => runVisibleTCPChecks().catch(() => {}), 30000);
  }
}

async function boot() {
  try {
    state.user = await api("/api/me");
    showApp();
    await loadServerGroups();
    await loadInstances();
  } catch (_) {
    showLogin();
  }
}

async function loadServerGroups() {
  state.serverGroups = normalizeServerGroupsState(await api("/api/server-groups"));
  populateServerGroupControls();
}

async function loadInstances() {
  state.instances = await api("/api/instances");
  render();
  triggerInitialChecks();
}

function render() {
  renderSummary();
  renderList();
  refreshOpenLogModal();
}

function renderSummary() {
  const total = state.instances.length;
  const running = state.instances.filter((item) => item.runtime.state === "running").length;
  const errors = state.instances.filter((item) => item.runtime.state === "error").length;
  const notes = [`${total} 个实例`, `${running} 个运行中`];
  if (errors > 0) {
    notes.push(`${errors} 个异常`);
  }
  el.pageSummary.textContent = notes.join(" / ");
}

function renderList() {
  el.instanceList.innerHTML = "";
  const items = filteredInstances();
  if (items.length === 0) {
    const empty = document.createElement("div");
    empty.className = "instance-empty";
    empty.textContent = state.instances.length === 0 ? "暂无实例，创建一个映射开始使用" : "没有匹配的实例";
    el.instanceList.append(empty);
    return;
  }

  const table = document.createElement("div");
  table.className = "instance-table";
  table.setAttribute("role", "table");

  const header = document.createElement("div");
  header.className = "instance-row table-head";
  header.setAttribute("role", "row");
  ["实例", "绑定端口", "协议", "公网地址", "保活链路", "TCP检测", "操作"].forEach((label) => {
    const cell = document.createElement("div");
    cell.className = "table-cell";
    cell.setAttribute("role", "columnheader");
    cell.textContent = label;
    header.append(cell);
  });
  table.append(header);

  items.forEach((item) => {
    const runtimeState = item.runtime.state || "stopped";
    const row = document.createElement("div");
    row.className = "instance-row";
    row.classList.add(item.config.enabled ? "enabled" : "disabled");
    row.classList.add(`runtime-${runtimeState}`);
    row.setAttribute("role", "row");

    const publicText = item.runtime.publicAddress
      ? `${item.runtime.publicAddress}:${item.runtime.publicPort}`
      : "-";
    const check = item.config.protocol === "tcp" ? item.runtime.portCheck : null;
    const nameCell = document.createElement("div");
    nameCell.className = "table-cell instance-identity";
    nameCell.setAttribute("role", "cell");
    const avatar = document.createElement("div");
    avatar.className = "instance-avatar";
    avatar.classList.add("line-avatar");
    avatar.innerHTML = lineIconSvg("server");
    const identityText = document.createElement("div");
    identityText.className = "instance-copy";
    const name = document.createElement("div");
    name.className = "instance-name";
    name.textContent = item.config.name || "NATCat";
    identityText.append(name);
    nameCell.append(avatar, identityText);

    const bindCell = document.createElement("div");
    bindCell.className = "table-cell bind-cell";
    bindCell.setAttribute("role", "cell");
    bindCell.append(createBindCard(item.config, item.runtime));

    const protocolCell = document.createElement("div");
    protocolCell.className = "table-cell protocol-cell";
    protocolCell.setAttribute("role", "cell");
    const protocolBadge = document.createElement("span");
    protocolBadge.className = `protocol-badge ${item.config.protocol}`;
    protocolBadge.textContent = item.config.protocol.toUpperCase();
    protocolCell.append(protocolBadge);

    const publicCell = document.createElement("div");
    publicCell.className = "table-cell address-cell";
    publicCell.setAttribute("role", "cell");
    publicCell.append(
      createAddressCard(
        publicText,
        item.runtime.publicAddress ? item.runtime.publicUpdatedAt : null,
        item.config.id,
      ),
    );

    const keepCell = document.createElement("div");
    keepCell.className = "table-cell keepalive-cell";
    keepCell.setAttribute("role", "cell");
    const keep = ["running", "starting", "error"].includes(runtimeState) ? item.runtime.keepAlive : null;
    keepCell.append(createKeepAliveCard(item.config, keep));

    const checkCell = document.createElement("div");
    checkCell.className = "table-cell check-cell";
    checkCell.setAttribute("role", "cell");
    checkCell.append(createTCPCheckCard(item, check));

    const actionCell = document.createElement("div");
    actionCell.className = "table-cell row-actions";
    actionCell.setAttribute("role", "cell");
    const enabledSwitch = document.createElement("button");
    enabledSwitch.className = `enable-switch ${item.config.enabled ? "on" : "off"}`;
    enabledSwitch.type = "button";
    enabledSwitch.setAttribute("role", "switch");
    enabledSwitch.setAttribute("aria-checked", item.config.enabled ? "true" : "false");
    enabledSwitch.setAttribute("aria-label", item.config.enabled ? "禁用实例" : "启用实例");
    enabledSwitch.title = item.config.enabled ? "禁用实例" : "启用实例";
    enabledSwitch.disabled = runtimeState === "stopping";
    enabledSwitch.append(document.createElement("span"));
    enabledSwitch.onclick = (event) => {
      event.stopPropagation();
      setInstanceEnabled(item, !item.config.enabled).catch(showPageError);
    };
    const edit = createIconButton("edit", "编辑实例");
    edit.onclick = (event) => {
      event.stopPropagation();
      editInstance(item.config.id);
    };
    const logs = createIconButton("logs", "查看日志");
    logs.onclick = (event) => {
      event.stopPropagation();
      openLogModal(item);
    };
    const duplicate = createIconButton("copy", "复制实例");
    duplicate.onclick = (event) => {
      event.stopPropagation();
      duplicateInstance(item).catch(showPageError);
    };
    const remove = createIconButton("trash", "删除实例", "delete");
    remove.onclick = (event) => {
      event.stopPropagation();
      deleteInstance(item).catch(showPageError);
    };
    actionCell.append(enabledSwitch, logs, edit, duplicate, remove);

    row.append(nameCell, bindCell, protocolCell, publicCell, keepCell, checkCell, actionCell);
    table.append(row);
  });

  el.instanceList.append(table);
}

function createBindCard(cfg, runtime = {}) {
  const card = document.createElement("div");
  card.className = "bind-card";
  const actualPort = runtime.privatePort > 0 ? String(runtime.privatePort) : "";
  const configuredPort = cfg.bindPort || "0";
  const displayPort = actualPort || configuredPort;
  card.title = actualPort && actualPort !== configuredPort ? `${configuredPort} -> :${actualPort}` : `:${displayPort}`;

  const port = document.createElement("span");
  port.className = "bind-port";
  port.textContent = `:${displayPort}`;
  const label = document.createElement("span");
  label.className = "bind-label";
  label.textContent = "PORT";

  card.append(label, port);
  return card;
}

function createAddressCard(value, updatedAt, instanceId) {
  if (!value || value === "-") {
    const empty = document.createElement("span");
    empty.className = "address-empty";
    empty.textContent = "-";
    return empty;
  }

  const button = document.createElement("button");
  button.className = "address-card";
  button.type = "button";
  button.title = value;
  button.setAttribute("aria-label", `复制公网地址 ${value}`);
  button.dataset.value = value;
  const copyKey = `${instanceId || ""}:${value}`;
  const copied = state.copiedAddressKey === copyKey;
  if (copied) {
    button.classList.add("copied");
  }

  const main = document.createElement("span");
  main.className = "address-main";
  const kicker = document.createElement("span");
  kicker.className = "address-kicker";
  kicker.textContent = "PUBLIC";
  const text = document.createElement("span");
  text.className = "address-text";
  text.textContent = value;
  main.append(kicker, text);
  const updatedText = updatedAt ? `上次更新 ${absoluteTimeText(updatedAt)}` : "";
  if (updatedText) {
    const meta = document.createElement("span");
    meta.className = "address-meta";
    meta.textContent = updatedText;
    main.append(meta);
  }
  const hint = document.createElement("span");
  hint.className = "address-hint";
  hint.textContent = copied ? "已复制" : "复制";
  button.append(main, hint);

  button.onclick = async (event) => {
    event.stopPropagation();
    try {
      await copyText(value);
      state.copiedAddressKey = copyKey;
      renderList();
    } catch (error) {
      showPageError(error);
    }
  };

  return button;
}

function createKeepAliveCard(cfg, keep) {
  const target = keepAliveTarget(keep);
  const card = document.createElement("div");
  card.className = `keepalive-card ${keep?.state || "unknown"}`.trim();
  if (keep?.message || target) {
    card.title = [target, keep?.message].filter(Boolean).join(" · ");
  }

  const top = document.createElement("span");
  top.className = "keepalive-top";
  const protocol = document.createElement("span");
  protocol.className = `keepalive-protocol ${cfg.protocol === "udp" ? "quic" : "http"}`;
  protocol.textContent = cfg.protocol === "udp" ? "QUIC" : "HTTP";
  const status = document.createElement("span");
  status.className = "keepalive-status";
  status.textContent = keepAliveStateLabel(keep);
  top.append(protocol, status);

  const bottom = document.createElement("span");
  bottom.className = "keepalive-target";
  const targetText = document.createElement("span");
  targetText.className = "keepalive-target-text";
  targetText.textContent = target || keepAliveMeta(keep);
  const metrics = document.createElement("span");
  metrics.className = "keepalive-metrics";
  const latency = keepAliveLatency(keep);
  if (latency) {
    const latencyPill = document.createElement("span");
    latencyPill.className = "keepalive-metric latency";
    latencyPill.textContent = latency;
    metrics.append(latencyPill);
  }
  const age = keepAliveAge(keep);
  if (age) {
    const agePill = document.createElement("span");
    agePill.className = "keepalive-metric age";
    agePill.textContent = age;
    metrics.append(agePill);
  }
  bottom.append(targetText, metrics);
  card.append(top, bottom);

  return card;
}

function createTCPCheckCard(item, check) {
  if (item.config.protocol !== "tcp") {
    const skipped = document.createElement("span");
    skipped.className = "check-skip";
    skipped.textContent = "-";
    skipped.title = "UDP 不做 TCP 连通检测";
    return skipped;
  }

  const card = document.createElement("div");
  card.className = `check-card ${check?.state || "unknown"}`.trim();
  if (check?.message) {
    card.title = check.message;
  }

  const main = document.createElement("span");
  main.className = "check-main";
  const dot = document.createElement("span");
  dot.className = "check-dot";
  const text = document.createElement("span");
  text.className = "check-text";
  text.textContent = portCheckSummary(check);
  main.append(dot, text);

  const refresh = createIconButton("refresh", "刷新 TCP 检测");
  refresh.classList.add("check-refresh");
  refresh.disabled = item.runtime.state !== "running" || !item.runtime.publicAddress || !item.runtime.publicPort;
  refresh.onclick = (event) => {
    event.stopPropagation();
    runTCPCheck(item.config.id).catch(showPageError);
  };

  const meta = document.createElement("span");
  meta.className = "check-meta";
  meta.textContent = validTime(check?.checkedAt) ? absoluteTimeText(check.checkedAt) : "-";

  card.append(main, refresh, meta);
  return card;
}

function keepAliveTarget(keep) {
  if (!keep?.address || !keep?.port) {
    return "";
  }
  return `${keep.address}:${keep.port}`;
}

function portCheckSummary(check) {
  if (!check || !check.state) {
    return "未检测";
  }
  const label = {
    open: "连通",
    closed: "不可达",
    timeout: "超时",
    unknown: "未检测",
  }[check.state] || check.state;
  if (check.state === "open" && Number.isFinite(check.latencyMs) && check.latencyMs > 0) {
    return `${label} · ${check.latencyMs}ms`;
  }
  return label;
}

function validTime(value) {
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && date.getFullYear() > 2001;
}

function absoluteTimeText(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  const time = [date.getHours(), date.getMinutes(), date.getSeconds()]
    .map((item) => String(item).padStart(2, "0"))
    .join(":");
  const day = [
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, "0"),
    String(date.getDate()).padStart(2, "0"),
  ].join("-");
  return `${day} ${time}`;
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.left = "-9999px";
  document.body.append(input);
  input.select();
  const ok = document.execCommand("copy");
  input.remove();
  if (!ok) {
    throw new Error("复制失败");
  }
}

function createIconButton(icon, label, tone = "") {
  const button = document.createElement("button");
  button.className = `icon-button ${tone}`.trim();
  button.type = "button";
  button.title = label;
  button.setAttribute("aria-label", label);
  button.innerHTML = iconSvg(icon);
  return button;
}

function iconSvg(icon) {
  const paths = {
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
    logs: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h6"/>',
    copy: '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    refresh: '<path d="M21 12a9 9 0 0 1-15.4 6.4L3 16"/><path d="M3 21v-5h5"/><path d="M3 12A9 9 0 0 1 18.4 5.6L21 8"/><path d="M21 3v5h-5"/>',
    trash: '<path d="M3 6h18"/><path d="M8 6V4c0-1 .9-2 2-2h4c1.1 0 2 .9 2 2v2"/><path d="M19 6l-1 14c-.1 1.1-1 2-2.1 2H8.1C7 22 6.1 21.1 6 20L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/>',
  };
  return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[icon] || ""}</svg>`;
}

function triggerInitialChecks() {
  const targets = state.instances.filter((item) => {
    if (item.config.protocol !== "tcp" || item.runtime.state !== "running") {
      return false;
    }
    if (!item.runtime.publicAddress || !item.runtime.publicPort) {
      return false;
    }
    return !state.initialChecked.has(portCheckKey(item));
  });
  targets.forEach((item) => {
    const key = portCheckKey(item);
    state.initialChecked.add(key);
    runTCPCheck(item.config.id, { silent: true }).catch(() => {
      state.initialChecked.delete(key);
    });
  });
}

async function runVisibleTCPChecks() {
  if (state.checkRunInFlight) {
    return;
  }
  const targets = state.instances.filter((item) => {
    return (
      item.config.protocol === "tcp" &&
      item.runtime.state === "running" &&
      item.runtime.publicAddress &&
      item.runtime.publicPort
    );
  });
  if (targets.length === 0) {
    return;
  }
  state.checkRunInFlight = true;
  try {
    await Promise.allSettled(
      targets.map((item) =>
        api(`/api/instances/${item.config.id}/check`, {
          method: "POST",
          body: "{}",
        }),
      ),
    );
    await loadInstances();
  } finally {
    state.checkRunInFlight = false;
  }
}

function portCheckKey(item) {
  return [
    item.config.id,
    item.runtime.publicAddress || "",
    item.runtime.publicPort || 0,
    item.runtime.publicUpdatedAt || "",
    item.runtime.startedAt || "",
  ].join(":");
}

function clearInitialCheckKeys(id) {
  for (const key of [...state.initialChecked]) {
    if (key.startsWith(`${id}:`)) {
      state.initialChecked.delete(key);
    }
  }
}

function lockPageScroll() {
  const scrollbarWidth = Math.max(0, window.innerWidth - document.documentElement.clientWidth);
  if (scrollbarWidth > 0) {
    document.body.style.paddingRight = `${scrollbarWidth}px`;
  }
  document.body.classList.add("modal-open");
}

function unlockPageScrollIfIdle() {
  const formOpen = el.modal && !el.modal.classList.contains("hidden");
  const logOpen = el.logModal && !el.logModal.classList.contains("hidden");
  const confirmOpen = el.confirmModal && !el.confirmModal.classList.contains("hidden");
  if (formOpen || logOpen || confirmOpen) {
    return;
  }
  document.body.classList.remove("modal-open");
  document.body.style.paddingRight = "";
}

function openLogModal(item) {
  closeModal();
  state.activeLogInstanceId = item?.config?.id || "";
  renderLogModal(item);
  el.logModal.classList.remove("hidden");
  lockPageScroll();
}

function refreshOpenLogModal() {
  if (!state.activeLogInstanceId || el.logModal?.classList.contains("hidden")) {
    return;
  }
  const item = state.instances.find((entry) => entry.config.id === state.activeLogInstanceId);
  if (item) {
    renderLogModal(item);
  }
}

function closeLogModal() {
  state.activeLogInstanceId = "";
  el.logModal?.classList.add("hidden");
  unlockPageScrollIfIdle();
}

function renderLogModal(item) {
  if (!el.logModal || !item) {
    return;
  }
  const logs = Array.isArray(item.runtime?.logs) ? [...item.runtime.logs] : [];
  el.logTitle.textContent = item.config.name || "NATCat";
  el.logSubtitle.textContent = `Runtime Log · ${item.config.protocol.toUpperCase()} · ${logs.length} 条`;
  el.logList.innerHTML = "";

  if (logs.length === 0) {
    const empty = document.createElement("div");
    empty.className = "log-empty";
    empty.textContent = "暂无日志";
    el.logList.append(empty);
    return;
  }

  logs
    .slice()
    .reverse()
    .forEach((entry) => {
      const row = document.createElement("div");
      row.className = `log-entry ${entry.level || "info"}`.trim();

      const time = document.createElement("span");
      time.className = "log-time";
      const parts = logTimeParts(entry.at);
      const timeClock = document.createElement("span");
      timeClock.className = "log-clock";
      timeClock.textContent = parts.time;
      const timeDate = document.createElement("span");
      timeDate.className = "log-date";
      timeDate.textContent = parts.date;
      time.append(timeClock, timeDate);

      const level = document.createElement("span");
      level.className = "log-level";
      level.textContent = entry.level || "info";

      const message = document.createElement("span");
      message.className = "log-message";
      message.textContent = entry.message || "";

      const body = document.createElement("span");
      body.className = "log-body";
      body.append(level, message);

      row.append(time, body);
      el.logList.append(row);
    });
}

function logTimeParts(value) {
  const text = validTime(value) ? absoluteTimeText(value) : "-";
  const [date = "-", time = "-"] = text.split(" ");
  return { date, time };
}

async function runTCPCheck(id, options = {}) {
  if (!options.silent) {
    clearPageError();
  }
  await api(`/api/instances/${id}/check`, {
    method: "POST",
    body: "{}",
  });
  await loadInstances();
}

async function setInstanceEnabled(item, enabled) {
  clearPageError();
  await api(`/api/instances/${item.config.id}`, {
    method: "PUT",
    body: JSON.stringify({ ...item.config, enabled }),
  });
  clearInitialCheckKeys(item.config.id);
  await loadInstances();
}

async function duplicateInstance(item) {
  clearPageError();
  const cfg = {
    ...item.config,
    id: "",
    name: `${item.config.name || "NATCat"} 副本`,
    enabled: false,
  };
  const saved = await api("/api/instances", {
    method: "POST",
    body: JSON.stringify(cfg),
  });
  await loadInstances();
}

async function deleteInstance(item) {
  clearPageError();
  const ok = await confirmAction({
    title: "删除实例",
    message: `确定删除「${item.config.name || "NATCat"}」吗？此操作不会保留该实例配置。`,
    confirmText: "删除",
  });
  if (!ok) {
    return;
  }
  await api(`/api/instances/${item.config.id}`, { method: "DELETE" });
  await loadInstances();
}

function confirmAction(options = {}) {
  if (!el.confirmModal) {
    return Promise.resolve(false);
  }
  if (el.confirmTitle) {
    el.confirmTitle.textContent = options.title || "确认操作";
  }
  if (el.confirmMessage) {
    el.confirmMessage.textContent = options.message || "请确认是否继续。";
  }
  if (el.confirmOkBtn) {
    el.confirmOkBtn.textContent = options.confirmText || "确认";
  }
  if (el.confirmCancelBtn) {
    el.confirmCancelBtn.textContent = options.cancelText || "取消";
  }
  el.confirmModal.classList.remove("hidden");
  lockPageScroll();

  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      el.confirmModal.classList.add("hidden");
      unlockPageScrollIfIdle();
      resolve(value);
    };
    const onKey = (event) => {
      if (event.key === "Escape") {
        finish(false);
      }
    };
    const onConfirm = () => finish(true);
    const onCancel = () => finish(false);
    const cleanup = () => {
      document.removeEventListener("keydown", onKey);
      el.confirmOkBtn?.removeEventListener("click", onConfirm);
      el.confirmCancelBtn?.removeEventListener("click", onCancel);
      el.confirmModal.querySelector("[data-confirm-action='cancel']")?.removeEventListener("click", onCancel);
    };
    document.addEventListener("keydown", onKey);
    el.confirmOkBtn?.addEventListener("click", onConfirm);
    el.confirmCancelBtn?.addEventListener("click", onCancel);
    el.confirmModal.querySelector("[data-confirm-action='cancel']")?.addEventListener("click", onCancel);
    setTimeout(() => el.confirmOkBtn?.focus(), 0);
  });
}

function editInstance(id) {
  const item = state.instances.find((entry) => entry.config.id === id);
  if (!item) {
    return;
  }
  openModal(item.config);
}

function openNewModal() {
  openModal(emptyConfig());
}

function openModal(cfg) {
  el.modalTitle.textContent = cfg.id ? "编辑实例" : "创建实例";
  if (el.modalMark) {
    el.modalMark.innerHTML = lineIconSvg(cfg.id ? "edit" : "plus");
  }
  fillForm(cfg);
  resetNotifyTestPanel();
  el.deleteConfigBtn.classList.toggle("hidden", !cfg.id);
  el.modal.classList.remove("hidden");
  lockPageScroll();
  el.formScroll?.scrollTo({ top: 0 });
  setActiveFormNav("section-basic");
  requestAnimationFrame(syncServerEditorLineNumbers);
  setTimeout(() => el.form.elements.name?.focus(), 0);
}

function closeModal() {
  el.modal?.classList.add("hidden");
  unlockPageScrollIfIdle();
  el.formError.textContent = "";
  state.serverGroupsDirty = false;
  populateServerGroupControls();
  resetNotifyTestPanel();
}

function filteredInstances() {
  const keyword = state.search.trim().toLowerCase();
  return state.instances.filter((item) => {
    const runtimeState = item.runtime.state || "stopped";
    const filterMatched =
      state.filter === "all" ||
      (state.filter === "pending" && (runtimeState === "starting" || runtimeState === "stopping")) ||
      runtimeState === state.filter;
    if (!filterMatched) {
      return false;
    }
    if (!keyword) {
      return true;
    }
    const haystack = [
      item.config.name,
      item.config.protocol,
      item.config.bindPort,
      item.config.httpHost,
      serverListText(state.serverGroups.stunServers),
      serverListText(item.config.protocol === "udp" ? state.serverGroups.quicServers : state.serverGroups.httpServers),
      item.runtime.publicAddress,
      item.runtime.privateAddress,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(keyword);
  });
}

function keepAliveStateLabel(keep) {
  if (!keep || !keep.state) {
    return "Idle";
  }
  if (keep.state === "connected") {
    return "Online";
  }
  return {
    reconnecting: "Reconnecting",
    disconnected: "Offline",
    unknown: "Idle",
  }[keep.state] || keep.state;
}

function keepAliveLatency(keep) {
  if (!keep || keep.state !== "connected") {
    return "";
  }
  return Number.isFinite(keep.latencyMs) && keep.latencyMs > 0 ? `${keep.latencyMs}ms` : "";
}

function keepAliveAge(keep) {
  if (!keep || keep.state !== "connected") {
    return "";
  }
  const connectedSeconds = secondsSince(keep.connectedAt);
  return connectedSeconds > 0 ? formatShortDuration(connectedSeconds) : "";
}

function keepAliveMeta(keep) {
  if (!keep || !keep.state) {
    return "waiting";
  }
  const target = keep.address && keep.port ? `${keep.address}:${keep.port}` : "";
  if (keep.state === "connected") {
    return target || "link active";
  }
  if (keep.lastSeenAt) {
    return `last ${absoluteTimeText(keep.lastSeenAt)}`;
  }
  return target || "waiting";
}

function formatShortDuration(totalSeconds) {
  if (totalSeconds < 60) {
    return `${totalSeconds}s`;
  }
  const minutes = Math.floor(totalSeconds / 60);
  if (minutes < 60) {
    return `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h`;
  }
  return `${Math.floor(hours / 24)}d`;
}

function secondsSince(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return 0;
  }
  return Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
}

function instanceInitials(value) {
  const cleaned = String(value || "NC").trim();
  if (!cleaned) {
    return "NC";
  }
  const parts = cleaned
    .split(/[\s_-]+/)
    .filter(Boolean)
    .slice(0, 2);
  const source = parts.length > 1 ? parts.map((part) => part[0]).join("") : cleaned.slice(0, 2);
  return source.toUpperCase();
}

function lineIconSvg(name) {
  const icons = {
    server: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="5" width="14" height="5" rx="1.4"></rect><rect x="5" y="14" width="14" height="5" rx="1.4"></rect><path d="M8 7.5h.1"></path><path d="M8 16.5h.1"></path><path d="M11 7.5h5"></path><path d="M11 16.5h5"></path></svg>',
    edit: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 19h4.2L18.6 9.6a2 2 0 0 0 0-2.8l-.4-.4a2 2 0 0 0-2.8 0L6 15.8 5 19Z"></path><path d="M14.2 7.8l2 2"></path><path d="M12 19h7"></path></svg>',
    plus: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14"></path><path d="M5 12h14"></path></svg>',
  };
  return icons[name] || icons.server;
}

function fillForm(cfg) {
  const f = el.form.elements;
  populateServerGroupControls();
  f.id.value = cfg.id || "";
  f.name.value = cfg.name || "";
  f.enabled.checked = !!cfg.enabled;
  setProtocol(cfg.protocol || "tcp");
  f.bindPort.value = cfg.bindPort || "0";
  f.stunMode.value = cfg.stunMode || "custom";
  f.stunGroupId.value = "stun";
  f.stunHost.value = cfg.stunHost || "";
  f.stunPort.value = cfg.stunPort || "";
  f.keepAliveMode.value = cfg.keepAliveMode || "custom";
  f.keepAliveGroupId.value = (cfg.protocol || "tcp") === "udp" ? "quic" : "http";
  f.httpHost.value = cfg.httpHost || "";
  f.httpPort.value = cfg.httpPort || ((cfg.protocol || "tcp") === "udp" ? 443 : 80);
  f.interface.value = cfg.interface || "";
  f.keepAliveSeconds.value = cfg.keepAliveSeconds || 30;
  f.mappingConfirmations.value = cfg.mappingConfirmations || 3;
  f.notifyScript.value = cfg.notifyScript || "";
  f.fwMark.value = cfg.fwMark || 0;
  el.formError.textContent = "";
  setSourceMode("stunMode", f.stunMode.value, { silent: true });
  setSourceMode("keepAliveMode", f.keepAliveMode.value, { silent: true });
  toggleConditionalFields();
}

function readForm() {
  const f = el.form.elements;
  return {
    id: f.id.value,
    name: f.name.value.trim(),
    enabled: f.enabled.checked,
    protocol: f.protocol.value,
    bindPort: f.bindPort.value.trim() || "0",
    stunMode: f.stunMode.value || "custom",
    stunGroupId: "stun",
    stunHost: f.stunHost.value.trim(),
    stunPort: numberValue(f.stunPort.value, 0),
    keepAliveMode: f.keepAliveMode.value || "custom",
    keepAliveGroupId: f.protocol.value === "udp" ? "quic" : "http",
    httpHost: f.httpHost.value.trim(),
    httpPort: numberValue(f.httpPort.value, f.protocol.value === "udp" ? 443 : 80),
    interface: f.interface.value.trim(),
    keepAliveSeconds: numberValue(f.keepAliveSeconds.value, 30),
    mappingConfirmations: numberValue(f.mappingConfirmations.value, 3),
    notifyScript: f.notifyScript.value.trim(),
    fwMark: numberValue(f.fwMark.value, 0),
  };
}

function numberValue(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeServerGroupsState(value = {}) {
  const legacyKeepAliveGroups = Array.isArray(value.keepAliveGroups) ? value.keepAliveGroups : [];
  return {
    stunServers: Array.isArray(value.stunServers)
      ? normalizeEndpointArray(value.stunServers, 3478)
      : flattenLegacyGroups(value.stunGroups, 3478),
    httpServers: Array.isArray(value.httpServers)
      ? normalizeEndpointArray(value.httpServers, 80)
      : flattenLegacyGroups(legacyKeepAliveGroups.filter((group) => !legacyGroupIsQUIC(group)), 80),
    quicServers: Array.isArray(value.quicServers)
      ? normalizeEndpointArray(value.quicServers, 443)
      : flattenLegacyGroups(legacyKeepAliveGroups.filter(legacyGroupIsQUIC), 443),
  };
}

function populateServerGroupControls() {
  const f = el.form?.elements;
  if (!f) {
    return;
  }
  f.stunGroupId.value = "stun";
  f.keepAliveGroupId.value = f.protocol.value === "udp" ? "quic" : "http";
  if (!state.serverGroupsDirty) {
    f.stunServersText.value = formatServerEndpoints(state.serverGroups.stunServers);
    f.httpServersText.value = formatServerEndpoints(state.serverGroups.httpServers);
    f.quicServersText.value = formatServerEndpoints(state.serverGroups.quicServers);
  }
  syncServerEditorLineNumbers();
}

function serverGroupTextareas() {
  const f = el.form?.elements;
  return [f?.stunServersText, f?.httpServersText, f?.quicServersText].filter(Boolean);
}

function syncServerEditorLineNumbers() {
  serverGroupTextareas().forEach(syncServerEditor);
}

function setupServerEditorLineNumbers() {
  serverGroupTextareas().forEach((input) => {
    input.addEventListener("scroll", () => updateServerEditorLineNumbers(input));
    setupServerEditorDragScroll(input);
    if ("ResizeObserver" in window) {
      new ResizeObserver(() => updateServerEditorLineNumbers(input)).observe(input);
    }
  });
  syncServerEditorLineNumbers();
}

function setupServerEditorDragScroll(input) {
  if (input.dataset.dragScrollReady === "1") {
    return;
  }
  input.dataset.dragScrollReady = "1";
  let selecting = false;
  let lastClientX = 0;
  let edgeTimer = 0;

  const stop = () => {
    selecting = false;
    if (edgeTimer) {
      window.clearInterval(edgeTimer);
      edgeTimer = 0;
    }
  };

  const edgeDelta = () => {
    const rect = input.getBoundingClientRect();
    const edge = 24;
    if (lastClientX < rect.left + edge) {
      return -12;
    }
    if (lastClientX > rect.right - edge) {
      return 12;
    }
    return 0;
  };

  const ensureTimer = () => {
    if (edgeTimer) {
      return;
    }
    edgeTimer = window.setInterval(() => {
      if (!selecting) {
        stop();
        return;
      }
      input.scrollLeft += edgeDelta();
    }, 24);
  };

  input.addEventListener("mousedown", (event) => {
    if (event.button !== 0) {
      return;
    }
    selecting = true;
    lastClientX = event.clientX;
  });
  window.addEventListener("mousemove", (event) => {
    if (!selecting || event.buttons !== 1) {
      stop();
      return;
    }
    lastClientX = event.clientX;
    if (edgeDelta()) {
      ensureTimer();
      return;
    }
    if (edgeTimer) {
      window.clearInterval(edgeTimer);
      edgeTimer = 0;
    }
  });
  window.addEventListener("mouseup", stop);
  input.addEventListener("blur", stop);
}

function updateServerEditorLineNumbers(input) {
  const rail = input.closest(".server-editor-shell")?.querySelector(".server-editor-rail");
  if (!rail) {
    return;
  }
  let track = rail.querySelector(".server-editor-rail-track");
  if (!track) {
    track = document.createElement("div");
    track.className = "server-editor-rail-track";
    rail.append(track);
  }
  const style = getComputedStyle(input);
  const fontSize = parseFloat(style.fontSize) || 12;
  const lineHeight = parseFloat(style.lineHeight) || fontSize * 1.48;
  const paddingTop = parseFloat(style.paddingTop) || 0;
  const paddingBottom = parseFloat(style.paddingBottom) || 0;
  const textLines = Math.max(1, input.value.split(/\r\n|\r|\n/).length);
  const lineCount = textLines;

  rail.style.paddingTop = `${paddingTop}px`;
  rail.style.paddingBottom = `${paddingBottom}px`;
  rail.style.setProperty("--line-number-height", `${lineHeight}px`);
  if (track.dataset.lineCount !== String(lineCount)) {
    track.replaceChildren(
      ...Array.from({ length: lineCount }, (_, index) => {
        const item = document.createElement("span");
        item.textContent = String(index + 1).padStart(2, "0");
        return item;
      }),
    );
    track.dataset.lineCount = String(lineCount);
  }
  track.style.transform = `translateY(${-input.scrollTop}px)`;
}

function syncServerEditor(input) {
  if (!input) {
    return;
  }
  syncServerEditorSize(input);
  updateServerEditorLineNumbers(input);
}

function syncServerEditorSize(input) {
  const shell = input.closest(".server-editor-shell");
  if (!shell) {
    return;
  }
  const style = getComputedStyle(input);
  const fontSize = parseFloat(style.fontSize) || 12;
  const lineHeight = parseFloat(style.lineHeight) || fontSize * 1.48;
  const paddingTop = parseFloat(style.paddingTop) || 0;
  const paddingBottom = parseFloat(style.paddingBottom) || 0;
  const lines = Math.max(1, input.value.split(/\r\n|\r|\n/).length);
  const visibleLines = Math.min(10, Math.max(3, lines));
  const targetHeight = Math.ceil(lineHeight * visibleLines + paddingTop + paddingBottom);

  input.style.height = `${targetHeight}px`;
  input.style.maxHeight = `${Math.ceil(lineHeight * 10 + paddingTop + paddingBottom)}px`;
  input.style.overflowY = lines > 10 ? "auto" : "hidden";
  shell.style.height = `${targetHeight}px`;
  shell.style.setProperty("--server-editor-max-height", `${input.style.maxHeight}`);
}

function formatServerEndpoints(servers) {
  return (servers || []).map((server) => `${server.host}:${server.port}`).join("\n");
}

function readServerGroupsFromForm() {
  const f = el.form.elements;
  return {
    stunServers: parseServerEndpoints(f.stunServersText.value, 3478, "STUN 组"),
    httpServers: parseServerEndpoints(f.httpServersText.value, 80, "HTTP 组"),
    quicServers: parseServerEndpoints(f.quicServersText.value, 443, "QUIC 组"),
  };
}

function parseServerEndpoints(text, defaultPort, label) {
  const parts = text
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
  if (!parts.length) {
    throw new Error(`${label} 至少需要一个服务器`);
  }
  return parts.map((item) => parseServerEndpoint(item, defaultPort, label));
}

function parseServerEndpoint(value, defaultPort, label) {
  let clean = value.trim().replace(/^https?:\/\//i, "").replace(/\/+$/, "");
  if (!clean) {
    throw new Error(`${label} 服务器不能为空`);
  }
  let host = clean;
  let port = defaultPort;
  const colon = clean.lastIndexOf(":");
  if (colon > 0 && colon < clean.length - 1) {
    const parsed = Number(clean.slice(colon + 1));
    if (!Number.isFinite(parsed)) {
      throw new Error(`${label} 服务器端口错误：${value}`);
    }
    host = clean.slice(0, colon);
    port = parsed;
  }
  if (!host || port <= 0 || port > 65535) {
    throw new Error(`${label} 服务器格式错误：${value}`);
  }
  return { host, port };
}

function normalizeEndpointArray(servers, defaultPort) {
  const seen = new Set();
  const out = [];
  (servers || []).forEach((server) => {
    const host = String(server.host || "").trim();
    const port = Number(server.port || defaultPort);
    if (!host || !Number.isFinite(port) || port <= 0 || port > 65535) {
      return;
    }
    const key = `${host.toLowerCase()}:${port}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    out.push({ host, port });
  });
  return out;
}

function flattenLegacyGroups(groups, defaultPort) {
  const servers = [];
  (groups || []).forEach((group) => {
    servers.push(...normalizeEndpointArray(group.servers || [], defaultPort));
  });
  return normalizeEndpointArray(servers, defaultPort);
}

function legacyGroupIsQUIC(group) {
  const key = `${group?.id || ""} ${group?.name || ""}`.toLowerCase();
  return key.includes("quic") || key.includes("udp");
}

function serverListText(servers) {
  return (servers || []).map((server) => `${server.host}:${server.port}`).join(" ");
}

async function saveServerGroups(options = {}) {
  const groups = readServerGroupsFromForm();
  const saved = await api("/api/server-groups", {
    method: "PUT",
    body: JSON.stringify(groups),
  });
  state.serverGroups = normalizeServerGroupsState(saved);
  state.serverGroupsDirty = false;
  populateServerGroupControls();
  if (!options.skipReload) {
    await loadInstances();
  }
  return saved;
}

function toggleConditionalFields() {
  const f = el.form.elements;
  const protocol = f.protocol.value;
  const isUDP = protocol === "udp";
  syncKeepAliveGroupLabels(protocol);
  el.httpFields.classList.remove("hidden");
  el.httpHostLabel.textContent = isUDP ? "QUIC 主机" : "HTTP 主机";
  el.httpPortLabel.textContent = isUDP ? "QUIC 端口" : "HTTP 端口";
  f.httpHost.placeholder = isUDP ? "zhuanlan.zhihu.com" : "qq.com";
  if (!f.httpPort.value || (isUDP && f.httpPort.value === "80")) {
    f.httpPort.value = isUDP ? "443" : "80";
  }
  const stunUsesGroup = f.stunMode.value === "group";
  const keepAliveUsesGroup = f.keepAliveMode.value === "group";
  el.stunCustomFields.classList.toggle("hidden", stunUsesGroup);
  el.stunGroupFields.classList.toggle("hidden", !stunUsesGroup);
  el.httpFields.classList.toggle("hidden", keepAliveUsesGroup);
  el.keepAliveGroupFields.classList.toggle("hidden", !keepAliveUsesGroup);
  el.probeTimingRow?.classList.toggle("udp", isUDP);
}

function syncKeepAliveGroupLabels(protocol) {
  const isUDP = protocol === "udp";
  const groupName = isUDP ? "QUIC 组" : "HTTP 组";
  if (el.form?.elements?.keepAliveGroupId) {
    el.form.elements.keepAliveGroupId.value = isUDP ? "quic" : "http";
  }
  if (el.keepAliveSourceLabel) {
    el.keepAliveSourceLabel.textContent = groupName;
  }
  if (el.keepAliveGroupButton) {
    el.keepAliveGroupButton.textContent = groupName;
  }
  if (el.keepAliveGroupTitle) {
    el.keepAliveGroupTitle.textContent = `使用 ${groupName}`;
  }
  if (el.keepAliveGroupHint) {
    el.keepAliveGroupHint.textContent = isUDP ? "UDP 使用 QUIC 组" : "TCP 使用 HTTP 组";
  }
}

function setProtocol(protocol) {
  const value = protocol === "udp" ? "udp" : "tcp";
  const previous = el.form.elements.protocol.value;
  el.form.elements.protocol.value = value;
  el.protocolSegments.forEach((button) => {
    button.classList.toggle("active", button.dataset.protocol === value);
  });
  toggleConditionalFields();
  if (previous !== value) {
    const host = el.form.elements.httpHost.value.trim();
    if (value === "udp" && ["", "qq.com", "223.5.5.5"].includes(host)) {
      el.form.elements.httpHost.value = "zhuanlan.zhihu.com";
    }
    if (value === "tcp" && ["", "cloudflare.com", "zhuanlan.zhihu.com"].includes(host)) {
      el.form.elements.httpHost.value = "qq.com";
    }
    if (!el.form.elements.keepAliveSeconds.value.trim()) {
      el.form.elements.keepAliveSeconds.value = "30";
    }
  }
}

function setSourceMode(fieldName, value, options = {}) {
  const mode = value === "group" ? "group" : "custom";
  el.form.elements[fieldName].value = mode;
  el.sourceSegments.forEach((button) => {
    if (button.dataset.sourceField === fieldName) {
      button.classList.toggle("active", button.dataset.sourceValue === mode);
    }
  });
  if (!options.silent) {
    toggleConditionalFields();
  }
}

function insertNotifyScriptVariable(value) {
  const input = el.form.elements.notifyScript;
  if (!input || !value) {
    return;
  }
  const start = typeof input.selectionStart === "number" ? input.selectionStart : input.value.length;
  const end = typeof input.selectionEnd === "number" ? input.selectionEnd : start;
  input.value = `${input.value.slice(0, start)}${value}${input.value.slice(end)}`;
  const cursor = start + value.length;
  input.focus();
  input.setSelectionRange(cursor, cursor);
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

function resetNotifyTestPanel() {
  el.notifyTestPanel?.classList.add("hidden");
  el.notifyTestPanel?.classList.remove("success", "error", "running");
  if (el.notifyTestStatus) {
    el.notifyTestStatus.textContent = "待运行";
  }
  if (el.notifyTestMeta) {
    el.notifyTestMeta.textContent = "";
  }
  if (el.notifyTestOutput) {
    el.notifyTestOutput.textContent = "";
  }
  if (el.notifyTestBtn) {
    el.notifyTestBtn.disabled = false;
  }
}

function setNotifyTestState(stateName, status, meta = "", output = "") {
  el.notifyTestPanel?.classList.remove("hidden", "success", "error", "running");
  el.notifyTestPanel?.classList.add(stateName);
  if (el.notifyTestStatus) {
    el.notifyTestStatus.textContent = status;
  }
  if (el.notifyTestMeta) {
    el.notifyTestMeta.textContent = meta;
  }
  if (el.notifyTestOutput) {
    el.notifyTestOutput.textContent = output;
  }
}

async function runNotifyScriptTest() {
  const f = el.form.elements;
  const id = f.id.value;
  const script = f.notifyScript.value.trim();
  if (!id) {
    setNotifyTestState("error", "无法测试", "", "请先保存实例，再运行通知脚本测试。");
    return;
  }
  if (!script) {
    setNotifyTestState("error", "脚本为空", "", "请输入通知脚本或脚本路径。");
    return;
  }
  el.notifyTestBtn.disabled = true;
  setNotifyTestState("running", "运行中", "等待脚本返回", "");
  try {
    const result = await api(`/api/instances/${id}/notify-test`, {
      method: "POST",
      body: JSON.stringify({ script, config: readForm() }),
    });
    const meta = `exit ${result.exitCode} · ${result.durationMs || 0}ms`;
    const output = result.output || "脚本没有输出。";
    setNotifyTestState(result.ok ? "success" : "error", result.ok ? "运行成功" : "运行失败", meta, output);
  } catch (error) {
    setNotifyTestState("error", "运行失败", "", error.message || String(error));
  } finally {
    el.notifyTestBtn.disabled = false;
  }
}

function setActiveFormNav(id) {
  el.formNavItems.forEach((item) => {
    const target = item.getAttribute("href")?.slice(1);
    item.classList.toggle("active", target === id);
  });
}

function syncFormNav() {
  if (!el.formScroll) {
    return;
  }
  const sections = [...el.form.querySelectorAll(".form-section")];
  const scrollTop = el.formScroll.scrollTop;
  const current = sections.reduce((active, section) => {
    if (section.offsetTop - el.formScroll.offsetTop <= scrollTop + 72) {
      return section;
    }
    return active;
  }, sections[0]);
  if (current?.id) {
    setActiveFormNav(current.id);
  }
}

function showPageError(error) {
  el.pageError.textContent = error.message || String(error);
}

function clearPageError() {
  el.pageError.textContent = "";
}

el.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  el.loginError.textContent = "";
  const body = Object.fromEntries(new FormData(el.loginForm).entries());
  try {
    state.user = await api("/api/login", {
      method: "POST",
      body: JSON.stringify(body),
    });
    showApp();
    await loadServerGroups();
    await loadInstances();
  } catch (error) {
    el.loginError.textContent = error.message;
  }
});

el.logoutBtn.addEventListener("click", async () => {
  await api("/api/logout", { method: "POST", body: "{}" }).catch(() => {});
  showLogin();
});

el.newBtn.addEventListener("click", openNewModal);

el.searchInput.addEventListener("input", () => {
  state.search = el.searchInput.value;
  renderList();
});

el.filterTabs.forEach((button) => {
  button.addEventListener("click", () => {
    state.filter = button.dataset.filter || "all";
    el.filterTabs.forEach((item) => item.classList.toggle("active", item === button));
    renderList();
  });
});

el.modalCloseBtn.addEventListener("click", closeModal);
el.modalCancelBtn.addEventListener("click", closeModal);
el.modal.querySelectorAll("[data-close-modal]").forEach((item) => {
  item.addEventListener("click", closeModal);
});

el.logCloseBtn?.addEventListener("click", closeLogModal);
el.logModal?.querySelectorAll("[data-close-log-modal]").forEach((item) => {
  item.addEventListener("click", closeLogModal);
});

el.formNavItems.forEach((item) => {
  item.addEventListener("click", (event) => {
    event.preventDefault();
    const id = item.getAttribute("href")?.slice(1);
    const section = id ? document.getElementById(id) : null;
    if (!section || !el.formScroll) {
      return;
    }
    setActiveFormNav(id);
    el.formScroll.scrollTo({
      top: section.offsetTop - el.formScroll.offsetTop,
      behavior: "smooth",
    });
  });
});

el.formScroll?.addEventListener("scroll", syncFormNav);

document.addEventListener(
  "pointerdown",
  (event) => {
    if (!state.copiedAddressKey) {
      return;
    }
    if (event.target.closest(".address-card")) {
      return;
    }
    state.copiedAddressKey = null;
    renderList();
  },
  true,
);

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
    return;
  }
  if (el.confirmModal && !el.confirmModal.classList.contains("hidden")) {
    return;
  }
  if (el.logModal && !el.logModal.classList.contains("hidden")) {
    closeLogModal();
    return;
  }
  if (!el.modal.classList.contains("hidden")) {
    closeModal();
  }
});

el.form.addEventListener("input", toggleConditionalFields);

el.protocolSegments.forEach((button) => {
  button.addEventListener("click", () => {
    setProtocol(button.dataset.protocol);
  });
});

el.sourceSegments.forEach((button) => {
  button.addEventListener("click", () => {
    setSourceMode(button.dataset.sourceField, button.dataset.sourceValue);
  });
});

el.scriptVarButtons.forEach((button) => {
  button.addEventListener("pointerdown", (event) => {
    event.preventDefault();
  });
  button.addEventListener("click", () => {
    insertNotifyScriptVariable(button.dataset.scriptVar || "");
  });
});

el.notifyTestBtn?.addEventListener("click", () => {
  runNotifyScriptTest().catch((error) => {
    setNotifyTestState("error", "运行失败", "", error.message || String(error));
    el.notifyTestBtn.disabled = false;
  });
});

[el.form.elements.stunServersText, el.form.elements.httpServersText, el.form.elements.quicServersText]
  .filter(Boolean)
  .forEach((input) => {
    input.addEventListener("input", () => {
      state.serverGroupsDirty = true;
      syncServerEditor(input);
    });
  });

el.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  el.formError.textContent = "";
  clearPageError();
  const cfg = readForm();
  const isUpdate = !!cfg.id;
  try {
    if (state.serverGroupsDirty) {
      await saveServerGroups({ skipReload: true });
    }
    const saved = await api(isUpdate ? `/api/instances/${cfg.id}` : "/api/instances", {
      method: isUpdate ? "PUT" : "POST",
      body: JSON.stringify(cfg),
    });
    clearInitialCheckKeys(saved?.config?.id || cfg.id);
    closeModal();
    await loadInstances();
  } catch (error) {
    el.formError.textContent = error.message;
  }
});

el.deleteConfigBtn.addEventListener("click", async () => {
  const cfg = readForm();
  if (!cfg.id) {
    return;
  }
  const ok = await confirmAction({
    title: "删除实例",
    message: `确定删除「${cfg.name || "NATCat"}」吗？此操作不会保留该实例配置。`,
    confirmText: "删除",
  });
  if (!ok) {
    return;
  }
  try {
    await api(`/api/instances/${cfg.id}`, { method: "DELETE" });
    closeModal();
    await loadInstances();
  } catch (error) {
    el.formError.textContent = error.message;
  }
});

setupServerEditorLineNumbers();

boot();
