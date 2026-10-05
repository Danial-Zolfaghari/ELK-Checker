let config = { monitors: [] };
let availableServers = [];
let statusPoll = null;
let currentUser = null;
let alertActivityOpen = false;
let alertActivityPoll = null;

function showSecurityWarning(text) {
    const modal = document.getElementById("securityWarningModal");
    const p = document.getElementById("securityWarningText");
    if (p) p.textContent = text || "Suspicious login activity was detected.";
    if (modal) {
        modal.classList.add("active");
        modal.setAttribute("aria-hidden", "false");
    }
}

async function ackSecurityWarning() {
    try {
        const res = await fetch("/api/auth/security-warning/ack", { method: "POST" });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            showToast(data.message || "Could not confirm warning", "error");
            return;
        }
        const modal = document.getElementById("securityWarningModal");
        if (modal) {
            modal.classList.remove("active");
            modal.setAttribute("aria-hidden", "true");
        }
    } catch (e) {
        showToast("Could not confirm warning", "error");
    }
}

async function load() {
    try {
        const sessionRes = await fetch("/api/auth/session");
        const sessionData = await sessionRes.json().catch(() => ({}));
        if (!sessionData.authenticated) {
            window.location.href = "/login";
            return;
        }
        currentUser = sessionData.user || null;
        const mgmt = document.getElementById("btn-management");
        const chgpw = document.getElementById("btn-change-password");
        if (mgmt) {
            mgmt.style.display = currentUser?.role === "superuser" ? "inline-flex" : "none";
        }
        if (chgpw) {
            chgpw.style.display = currentUser?.role === "superuser" ? "none" : "inline-flex";
        }
        if (currentUser?.role === "superuser" && sessionData.security_warning?.required) {
            showSecurityWarning(sessionData.security_warning.message || "");
        }

        const res = await fetch("/api/config");
        const cfg = await res.json().catch(() => ({}));
        if (!res.ok) {
            showToast(cfg.message || "Failed to load config", "error");
            return;
        }
        config = cfg;
        try {
            const srvRes = await fetch("/api/servers");
            const srvData = await srvRes.json().catch(() => ({}));
            availableServers = srvRes.ok ? srvData.servers || [] : [];
        } catch {
            availableServers = [];
        }
        const baleHint = document.getElementById("bale-url-hint");
        if (baleHint) {
            const configured = cfg._meta && cfg._meta.bale_bot_url_configured;
            baleHint.classList.toggle("hidden", !!configured);
        }
        render();
        startStatusPoll();
        if (alertActivityOpen) loadAlertHistory();
    } catch (e) {
        showToast("Unexpected error loading dashboard", "error");
        console.error(e);
    }
}

function timeAgo(ts) {
    if (!ts) return "never";
    const now = Date.now() / 1000;
    const diff = now - ts;
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

function openMonitorById(monitorId) {
    const m = (config.monitors || []).find((x) => x.id === monitorId);
    openMonitorModal(m || null);
}

function openMonitorModal(monitor = null) {
    try {
        const form = document.getElementById("monitorForm");
        if (form) form.reset();
        const kicker = document.getElementById("monitorModalKicker");
        const titleEl = document.getElementById("monitorModalTitle");
        if (monitor?.id) {
            if (kicker) kicker.textContent = "Edit monitor";
            if (titleEl) titleEl.textContent = monitor.name?.trim() || "Unnamed monitor";
        } else {
            if (kicker) kicker.textContent = "New monitor";
            if (titleEl) titleEl.textContent = "Create a monitor";
        }
        document.getElementById("monitor_id").value = monitor?.id || "";
        document.getElementById("name").value = monitor?.name || "";
        document.getElementById("enabled").checked = monitor?.enabled ?? true;
        const serverSelect = document.getElementById("server_id");
        if (serverSelect) {
            const options = ['<option value="">Manual host/credentials</option>'].concat(
                (availableServers || []).map(
                    (s) =>
                        `<option value="${String(s.id).replace(/"/g, "&quot;")}">${String(s.name || s.hostname || "")} : ${String(s.hostname || "")}</option>`
                )
            );
            serverSelect.innerHTML = options.join("");
            serverSelect.value = monitor?.server_id || "";
        }
        document.getElementById("host").value = monitor?.host || "";
        document.getElementById("index").value = monitor?.index || "";
        document.getElementById("username").value = monitor?.username || "";
        document.getElementById("password").value = monitor?.password || "";
        document.getElementById("query_mode").value = monitor?.query_mode || "json";
        document.getElementById("query_json").value = monitor?.query_json || '{"query":{"match_all":{}}}';
        document.getElementById("query_kql").value = monitor?.query_kql || "";
        document.getElementById("timestamp_field").value = monitor?.timestamp_field || "@timestamp";
        document.getElementById("check_interval").value = monitor?.check_interval || 60;
        document.getElementById("window_seconds").value = monitor?.window_seconds || 60;
        document.getElementById("alert_cooldown").value = monitor?.alert_cooldown || 300;
        document.getElementById("rule_no_hit_enabled").checked = monitor?.rules?.no_hit?.enabled ?? true;
        document.getElementById("rule_no_hit_recovery_notify").checked =
            !!monitor?.rules?.no_hit?.notify_on_recovery;
        document.getElementById("rule_reverse_hit_enabled").checked = monitor?.rules?.reverse_hit?.enabled ?? false;
        document.getElementById("rule_reverse_hit_recovery_notify").checked =
            !!monitor?.rules?.reverse_hit?.notify_on_recovery;
        document.getElementById("rule_count_threshold_enabled").checked = monitor?.rules?.count_threshold?.enabled ?? false;
        document.getElementById("rule_count_threshold_operator").value = monitor?.rules?.count_threshold?.operator || "gt";
        document.getElementById("rule_count_threshold_value").value = monitor?.rules?.count_threshold?.value ?? 0;
        document.getElementById("rule_volatility_enabled").checked = monitor?.rules?.volatility?.enabled ?? false;
        document.getElementById("rule_volatility_percent").value = monitor?.rules?.volatility?.percent ?? 30;
        const winEl = document.getElementById("rule_volatility_window_minutes");
        if (winEl) winEl.value = monitor?.rules?.volatility?.window_minutes ?? 5;
        const ee = monitor?.rules?.error_escalation || {};
        document.getElementById("rule_error_escalation_enabled").checked = !!ee.enabled;
        document.getElementById("rule_error_sms_after").value = ee.sms_after_failures ?? 0;
        document.getElementById("rule_error_call_after").value = ee.call_after_failures ?? 0;
        document.getElementById("rule_error_bale_after").value = ee.bale_after_failures ?? 0;
        const n = monitor?.notifications || {};
        const rec = n.recovery || {};
        const sms = n.sms || {};
        const call = n.call || {};
        document.getElementById("recovery_sms_enabled").checked = !!rec?.sms?.enabled;
        document.getElementById("recovery_sms_message").value = rec?.sms?.message || "";
        document.getElementById("recovery_call_enabled").checked = !!rec?.call?.enabled;
        document.getElementById("recovery_call_message").value = rec?.call?.message || "";
        document.getElementById("recovery_bale_enabled").checked = !!rec?.bale?.enabled;
        document.getElementById("recovery_bale_message").value = rec?.bale?.message || "";
        const recoveryMenuToggle = document.getElementById("recovery_message_menu_toggle");
        if (recoveryMenuToggle) {
            const hasRecoveryConfig =
                !!rec?.sms?.enabled ||
                !!rec?.call?.enabled ||
                !!rec?.bale?.enabled ||
                !!(rec?.sms?.message || "").trim() ||
                !!(rec?.call?.message || "").trim() ||
                !!(rec?.bale?.message || "").trim();
            recoveryMenuToggle.checked = hasRecoveryConfig;
        }
        document.getElementById("kavenegar_api_key").value = n.kavenegar_api_key || "";
        document.getElementById("sms_sender").value = n.sms_sender || "";
        document.getElementById("sms_enabled").checked = sms.enabled !== false;
        const smsLines = (sms.recipients || []).length ? sms.recipients : monitor?.contacts || [];
        document.getElementById("sms_recipients").value = (smsLines || []).join("\n");
        document.getElementById("sms_message").value = sms.message || "";
        document.getElementById("call_enabled").checked = !!call.enabled;
        document.getElementById("call_recipients").value = (call.recipients || []).join("\n");
        document.getElementById("call_message").value = call.message || "";
        const bale = n.bale || {};
        document.getElementById("bale_enabled").checked = !!bale.enabled;
        document.getElementById("bale_token").value = bale.token || "";
        document.getElementById("bale_script_name").value = bale.script_name || "";
        const baleMsg = document.getElementById("bale_message");
        if (baleMsg) baleMsg.value = bale.message || "";
        const brid = document.getElementById("bale_requester_id");
        if (brid) {
            brid.value =
                bale.requester_id != null && bale.requester_id !== ""
                    ? String(bale.requester_id)
                    : "";
        }
        toggleQueryMode();
        applyServerSelection();
        toggleRecoveryMessageBoxes();
        document.getElementById("monitorModal").classList.add("active");
    } catch (e) {
        showToast("Could not open monitor form", "error");
        console.error(e);
    }
}

function applyServerSelection() {
    const sid = document.getElementById("server_id")?.value || "";
    const server = (availableServers || []).find((x) => x.id === sid);
    const hostInput = document.getElementById("host");
    const userInput = document.getElementById("username");
    const passInput = document.getElementById("password");
    const hint = document.getElementById("server-hint");
    if (!hostInput || !userInput || !passInput) return;
    if (!server) {
        hostInput.readOnly = false;
        userInput.readOnly = false;
        passInput.readOnly = false;
        if (hint) {
            hint.textContent = "";
            hint.classList.add("hidden");
        }
        return;
    }
    hostInput.value = server.hostname || "";
    userInput.value = server.username || "";
    passInput.value = "********";
    hostInput.readOnly = true;
    userInput.readOnly = true;
    passInput.readOnly = true;
    if (hint) {
        hint.textContent = `Using saved server: ${server.hostname}`;
        hint.classList.remove("hidden");
    }
}

function toggleRecoveryMessageBoxes() {
    const isOpen = document.getElementById("recovery_message_menu_toggle")?.checked;
    const box = document.getElementById("recovery-message-boxes");
    if (box) box.classList.toggle("hidden", !isOpen);
}

function textEl(tag, cls, text) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    el.textContent = text;
    return el;
}

function render() {
    const list = document.getElementById("monitorList");
    const total = document.getElementById("total-monitors");
    const monitors = config.monitors || [];
    if (!list || !total) return;
    total.textContent = String(monitors.length);
    list.innerHTML = "";
    if (!monitors.length) {
        const empty = document.createElement("div");
        empty.className = "empty-state-card";
        empty.innerHTML = '<i class="fas fa-inbox"></i><p>No monitors yet.</p>';
        list.appendChild(empty);
        return;
    }
    monitors.forEach((m) => {
        const art = document.createElement("article");
        art.className = "monitor-card";
        art.dataset.monitorId = m.id;

        const header = document.createElement("div");
        header.className = "monitor-card-header";
        const titleBlock = document.createElement("div");
        const h3 = document.createElement("h3");
        h3.className = "monitor-name";
        h3.textContent = m.name || "Unnamed";
        const hostP = document.createElement("p");
        hostP.className = "monitor-host";
        hostP.textContent = m.host || "";
        titleBlock.appendChild(h3);
        titleBlock.appendChild(hostP);
        const pill = document.createElement("span");
        pill.className = `status-pill ${m.enabled ? "state-healthy" : "state-inactive"}`;
        pill.textContent = m.enabled ? "Enabled" : "Disabled";
        header.appendChild(titleBlock);
        header.appendChild(pill);
        art.appendChild(header);

        const metrics = document.createElement("div");
        metrics.className = "monitor-metrics";
        metrics.appendChild(metricRow("Index", m.index || "—", true));
        metrics.appendChild(metricRow("Query", (m.query_mode || "json").toUpperCase(), false));
        metrics.appendChild(metricRow("Last check", "—", false, `js-lc-${m.id}`));
        metrics.appendChild(metricRow("API / ES", "—", false, `js-api-${m.id}`));
        metrics.appendChild(metricRow("Log count", "—", false, `js-cnt-${m.id}`));
        metrics.appendChild(metricRow("Alert count", "0", false, `js-alertcnt-${m.id}`));
        metrics.appendChild(metricRow("Last alert", "never", false, `js-la-${m.id}`));
        metrics.appendChild(metricRow("State", "—", false, `js-st-${m.id}`));
        art.appendChild(metrics);

        const actions = document.createElement("div");
        actions.className = "monitor-actions-row";
        const edit = document.createElement("button");
        edit.type = "button";
        edit.className = "btn btn-secondary action-btn";
        edit.textContent = "Edit";
        edit.addEventListener("click", () => openMonitorById(m.id));
        const dup = document.createElement("button");
        dup.type = "button";
        dup.className = "btn btn-secondary action-btn";
        dup.textContent = "Duplicate";
        dup.addEventListener("click", () => duplicateMonitor(m.id));
        const del = document.createElement("button");
        del.type = "button";
        del.className = "btn btn-danger action-btn";
        del.textContent = "Delete";
        del.addEventListener("click", () => removeMonitor(m.id));
        actions.appendChild(edit);
        actions.appendChild(dup);
        actions.appendChild(del);
        art.appendChild(actions);

        list.appendChild(art);
    });
}

function metricRow(label, value, mono, id) {
    const row = document.createElement("div");
    row.className = "metric";
    const lab = document.createElement("span");
    lab.textContent = label;
    const val = document.createElement("strong");
    if (mono) val.className = "mono";
    if (id) val.id = id;
    val.textContent = value;
    row.appendChild(lab);
    row.appendChild(val);
    return row;
}

function startStatusPoll() {
    if (statusPoll) clearInterval(statusPoll);
    const tick = async () => {
        try {
            const res = await fetch("/api/status");
            if (res.status === 401) {
                if (statusPoll) {
                    clearInterval(statusPoll);
                    statusPoll = null;
                }
                window.location.href = "/login";
                return;
            }
            const status = await res.json().catch(() => ({}));
            const states = status.states || {};
            (config.monitors || []).forEach((m) => {
                const st = states[m.id] || {};
                const set = (id, text) => {
                    const el = document.getElementById(id);
                    if (el) el.textContent = text;
                };
                set(`js-lc-${m.id}`, st.last_check ? timeAgo(st.last_check) : "—");
                if (st.connection_ok === true) set(`js-api-${m.id}`, "OK");
                else if (st.connection_ok === false) set(`js-api-${m.id}`, "Error");
                else set(`js-api-${m.id}`, m.enabled ? "—" : "n/a");
                set(`js-cnt-${m.id}`, st.last_count != null ? String(st.last_count) : "—");
                set(`js-alertcnt-${m.id}`, String(st.alert_count ?? 0));
                set(`js-la-${m.id}`, st.last_alert ? timeAgo(st.last_alert) : "never");
                set(`js-st-${m.id}`, st.status || "—");
            });
        } catch (e) {
            console.error("Status poll failed:", e);
        }
    };
    tick();
    statusPoll = setInterval(tick, 3000);
}

function closeMonitorModal() {
    const el = document.getElementById("monitorModal");
    if (el) el.classList.remove("active");
}

function toggleQueryMode() {
    const mode = document.getElementById("query_mode")?.value || "json";
    document.querySelector(".query-json")?.classList.toggle("hidden", mode !== "json");
    document.querySelector(".query-kql")?.classList.toggle("hidden", mode !== "kql");
}

function buildMonitorPayload() {
    const id = document.getElementById("monitor_id").value || generateId();
    const serverId = document.getElementById("server_id")?.value?.trim() || "";
    const hostValue = document.getElementById("host").value.trim();
    const userValue = document.getElementById("username").value.trim();
    const passValue = document.getElementById("password").value.trim();
    return {
        id,
        name: document.getElementById("name").value.trim(),
        enabled: document.getElementById("enabled").checked,
        server_id: serverId,
        host: serverId ? "" : hostValue,
        index: document.getElementById("index").value.trim(),
        username: serverId ? "" : userValue,
        password: serverId ? "" : passValue,
        query_mode: document.getElementById("query_mode").value,
        query_json: document.getElementById("query_json").value.trim(),
        query_kql: document.getElementById("query_kql").value.trim(),
        timestamp_field: document.getElementById("timestamp_field").value.trim(),
        check_interval: Number(document.getElementById("check_interval").value || 60),
        window_seconds: Number(document.getElementById("window_seconds").value || 60),
        alert_cooldown: Number(document.getElementById("alert_cooldown").value || 300),
        contacts: [],
        notifications: {
            kavenegar_api_key: document.getElementById("kavenegar_api_key").value.trim(),
            sms_sender: document.getElementById("sms_sender").value.trim(),
            bale: (() => {
                const ridRaw = document.getElementById("bale_requester_id")?.value?.trim() || "";
                let requester_id = null;
                if (ridRaw !== "") {
                    const n = Number(ridRaw);
                    if (!Number.isNaN(n)) requester_id = n;
                }
                return {
                    enabled: document.getElementById("bale_enabled").checked,
                    token: document.getElementById("bale_token").value.trim(),
                    script_name: document.getElementById("bale_script_name").value.trim(),
                    message: document.getElementById("bale_message")?.value?.trim() || "",
                    requester_id,
                };
            })(),
            recovery: {
                sms: {
                    enabled: document.getElementById("recovery_sms_enabled").checked,
                    message: document.getElementById("recovery_sms_message").value.trim(),
                },
                call: {
                    enabled: document.getElementById("recovery_call_enabled").checked,
                    message: document.getElementById("recovery_call_message").value.trim(),
                },
                bale: {
                    enabled: document.getElementById("recovery_bale_enabled").checked,
                    message: document.getElementById("recovery_bale_message").value.trim(),
                },
            },
            sms: {
                enabled: document.getElementById("sms_enabled").checked,
                message: document.getElementById("sms_message").value.trim(),
                recipients: document
                    .getElementById("sms_recipients")
                    .value.split("\n")
                    .map((x) => x.trim())
                    .filter(Boolean),
            },
            call: {
                enabled: document.getElementById("call_enabled").checked,
                message: document.getElementById("call_message").value.trim(),
                recipients: document
                    .getElementById("call_recipients")
                    .value.split("\n")
                    .map((x) => x.trim())
                    .filter(Boolean),
            },
        },
        rules: {
            no_hit: {
                enabled: document.getElementById("rule_no_hit_enabled").checked,
                notify_on_recovery: document.getElementById("rule_no_hit_recovery_notify").checked,
            },
            reverse_hit: {
                enabled: document.getElementById("rule_reverse_hit_enabled").checked,
                notify_on_recovery: document.getElementById("rule_reverse_hit_recovery_notify").checked,
            },
            count_threshold: {
                enabled: document.getElementById("rule_count_threshold_enabled").checked,
                operator: document.getElementById("rule_count_threshold_operator").value,
                value: Number(document.getElementById("rule_count_threshold_value").value || 0),
            },
            volatility: {
                enabled: document.getElementById("rule_volatility_enabled").checked,
                percent: Number(document.getElementById("rule_volatility_percent").value || 0),
                window_minutes: Math.max(
                    1,
                    Number(document.getElementById("rule_volatility_window_minutes")?.value || 5)
                ),
            },
            error_escalation: {
                enabled: document.getElementById("rule_error_escalation_enabled").checked,
                sms_after_failures: Math.max(0, Number(document.getElementById("rule_error_sms_after").value || 0)),
                call_after_failures: Math.max(0, Number(document.getElementById("rule_error_call_after").value || 0)),
                bale_after_failures: Math.max(0, Number(document.getElementById("rule_error_bale_after").value || 0)),
            },
        },
    };
}

async function saveMonitor() {
    let monitor;
    try {
        monitor = buildMonitorPayload();
        const n = monitor.notifications || {};
        const hasAnyMessageChannel =
            (n.sms?.enabled && !!(n.sms?.message || "").trim()) ||
            (n.call?.enabled && !!(n.call?.message || "").trim()) ||
            (n.bale?.enabled && !!(n.bale?.message || "").trim()) ||
            (n.recovery?.sms?.enabled && !!(n.recovery?.sms?.message || "").trim()) ||
            (n.recovery?.call?.enabled && !!(n.recovery?.call?.message || "").trim()) ||
            (n.recovery?.bale?.enabled && !!(n.recovery?.bale?.message || "").trim());
        if (!hasAnyMessageChannel) {
            showToast("No alert channel is configured. Enable at least one channel and set its message text.", "error");
            return;
        }
    } catch (e) {
        showToast("Invalid form data", "error");
        return;
    }
    try {
        const valRes = await fetch("/api/monitors/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(monitor),
        });
        const valData = await valRes.json().catch(() => ({}));
        if (!valRes.ok) {
            showToast(valData.message || "Query validation failed", "error");
            return;
        }
    } catch (e) {
        showToast("Validation request failed", "error");
        console.error(e);
        return;
    }
    try {
        const res = await fetch("/api/monitors", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(monitor),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.status !== "ok") {
            showToast(data.message || "Save failed", "error");
            return;
        }
        showToast("Monitor saved", "success");
        closeMonitorModal();
        await load();
        if (alertActivityOpen) loadAlertHistory();
    } catch (e) {
        showToast("Save request failed", "error");
        console.error(e);
    }
}

function generateId() {
    return `mon_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

async function duplicateMonitor(monitorId) {
    const m = (config.monitors || []).find((x) => x.id === monitorId);
    if (!m) return;
    let copy;
    try {
        copy = JSON.parse(JSON.stringify(m));
    } catch (e) {
        showToast("Could not duplicate monitor", "error");
        return;
    }
    copy.id = generateId();
    copy.enabled = false;
    const baseName = (m.name || "Unnamed").trim();
    copy.name = baseName ? `${baseName} (copy)` : "Unnamed (copy)";
    try {
        const valRes = await fetch("/api/monitors/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(copy),
        });
        const valData = await valRes.json().catch(() => ({}));
        if (!valRes.ok) {
            showToast(valData.message || "Duplicate validation failed", "error");
            return;
        }
    } catch (e) {
        showToast("Validation request failed", "error");
        console.error(e);
        return;
    }
    try {
        const res = await fetch("/api/monitors", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(copy),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.status !== "ok") {
            showToast(data.message || "Duplicate save failed", "error");
            return;
        }
        showToast("Monitor duplicated (disabled until you enable it)", "success");
        await load();
        if (alertActivityOpen) loadAlertHistory();
    } catch (e) {
        showToast("Duplicate save request failed", "error");
        console.error(e);
    }
}

async function removeMonitor(monitorId) {
    if (!monitorId) return;
    if (!confirm("Delete this monitor?")) return;
    try {
        const res = await fetch(`/api/monitors/${encodeURIComponent(monitorId)}`, { method: "DELETE" });
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            showToast(data.message || "Delete failed", "error");
            return;
        }
        await load();
    } catch (e) {
        showToast("Delete request failed", "error");
        console.error(e);
    }
}

async function logout() {
    try {
        await fetch("/api/auth/logout", { method: "POST" });
    } catch {
        /* ignore */
    }
    window.location.href = "/login";
}

function showToast(message, type = "info") {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.className = `toast toast-${type} active`;
    setTimeout(() => toast.classList.remove("active"), 2500);
}

function initAlertActivity() {
    document.getElementById("alert-activity-toggle")?.addEventListener("click", () => {
        alertActivityOpen = !alertActivityOpen;
        const panel = document.getElementById("alert-activity-panel");
        const btn = document.getElementById("alert-activity-toggle");
        if (!panel || !btn) return;
        panel.classList.toggle("hidden", !alertActivityOpen);
        btn.setAttribute("aria-expanded", alertActivityOpen ? "true" : "false");
        if (alertActivityOpen) {
            loadAlertHistory();
            if (!alertActivityPoll) {
                alertActivityPoll = setInterval(() => {
                    if (alertActivityOpen) loadAlertHistory();
                }, 12000);
            }
        } else if (alertActivityPoll) {
            clearInterval(alertActivityPoll);
            alertActivityPoll = null;
        }
    });
}

async function loadAlertHistory() {
    const panel = document.getElementById("alert-activity-panel");
    if (!panel || panel.classList.contains("hidden")) return;
    try {
        const res = await fetch("/api/alert-history?limit=100");
        const data = await res.json().catch(() => ({}));
        const entries = data.entries || [];
        panel.innerHTML = "";
        if (!entries.length) {
            const p = document.createElement("p");
            p.className = "ah-empty";
            p.textContent = "No alert attempts recorded yet.";
            panel.appendChild(p);
            return;
        }
        const head = document.createElement("div");
        head.className = "ah-row ah-head";
        ["Time (Tehran)", "Monitor", "Channel · kind", "Result"].forEach((t) => {
            const c = document.createElement("div");
            c.textContent = t;
            head.appendChild(c);
        });
        panel.appendChild(head);
        entries.forEach((row) => {
            const r = document.createElement("div");
            r.className = "ah-row";
            const t = document.createElement("div");
            t.className = "ah-time";
            t.textContent = row.time_local || row.time_utc || "";
            const m = document.createElement("div");
            m.className = "ah-monitor";
            m.textContent = row.monitor_name || "";
            const ch = document.createElement("div");
            ch.className = "ah-channel";
            ch.textContent = `${row.channel || "—"} · ${row.kind || ""}`;
            const st = document.createElement("div");
            const badge = document.createElement("span");
            const s = (row.status || "").toLowerCase();
            badge.className = "ah-badge " + (s === "success" ? "success" : s === "skipped" ? "skipped" : "failed");
            badge.textContent = row.status || "—";
            st.appendChild(badge);
            r.appendChild(t);
            r.appendChild(m);
            r.appendChild(ch);
            r.appendChild(st);
            if (row.detail) {
                const d = document.createElement("div");
                d.className = "ah-detail";
                d.textContent = row.detail;
                r.appendChild(d);
            }
            if (row.reasons && row.reasons.length) {
                const d2 = document.createElement("div");
                d2.className = "ah-detail";
                d2.textContent = "Rules: " + row.reasons.join(", ");
                r.appendChild(d2);
            }
            panel.appendChild(r);
        });
    } catch (e) {
        panel.innerHTML = "";
        const p = document.createElement("p");
        p.className = "ah-empty";
        p.textContent = "Could not load alert history.";
        panel.appendChild(p);
        console.error(e);
    }
}

initAlertActivity();
document.getElementById("server_id")?.addEventListener("change", applyServerSelection);
document.getElementById("recovery_message_menu_toggle")?.addEventListener("change", toggleRecoveryMessageBoxes);
document.getElementById("securityWarningAckBtn")?.addEventListener("click", ackSecurityWarning);
load();
