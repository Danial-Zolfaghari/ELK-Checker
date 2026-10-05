function showToast(message, type = "info") {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.className = `toast toast-${type} active`;
    setTimeout(() => toast.classList.remove("active"), 2800);
}

async function requireSession() {
    try {
        const res = await fetch("/api/auth/session");
        const data = await res.json();
        if (!data.authenticated) {
            window.location.href = "/login";
            return null;
        }
        if (data.user?.role !== "superuser") {
            window.location.href = "/dashboard";
            return null;
        }
        return data.user;
    } catch {
        window.location.href = "/login";
        return null;
    }
}

function closeAdminPasswordModal() {
    const m = document.getElementById("admin-password-modal");
    if (m) {
        m.classList.remove("active");
        m.setAttribute("aria-hidden", "true");
    }
    const msg = document.getElementById("admin-pw-msg");
    if (msg) msg.textContent = "";
}

function openAdminPasswordModal(userId, username) {
    const uid = document.getElementById("admin-pw-user-id");
    const un = document.getElementById("admin-pw-modal-user");
    const p1 = document.getElementById("admin-pw-new");
    const p2 = document.getElementById("admin-pw-confirm");
    if (uid) uid.value = userId;
    if (un) un.textContent = username || "";
    if (p1) p1.value = "";
    if (p2) p2.value = "";
    const m = document.getElementById("admin-password-modal");
    if (m) {
        m.classList.add("active");
        m.setAttribute("aria-hidden", "false");
    }
}

async function saveAdminPassword() {
    const msg = document.getElementById("admin-pw-msg");
    if (msg) msg.textContent = "";
    const userId = document.getElementById("admin-pw-user-id")?.value;
    const a = document.getElementById("admin-pw-new")?.value || "";
    const b = document.getElementById("admin-pw-confirm")?.value || "";
    if (a !== b) {
        if (msg) msg.textContent = "Passwords do not match.";
        return;
    }
    if (a.length < 4) {
        if (msg) msg.textContent = "Password must be at least 4 characters.";
        return;
    }
    try {
        const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: a }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (msg) msg.textContent = data.message || "Failed";
            showToast(data.message || "Failed", "error");
            return;
        }
        showToast("Password updated", "success");
        closeAdminPasswordModal();
        await loadUsers();
    } catch (e) {
        if (msg) msg.textContent = String(e);
        showToast(String(e), "error");
    }
}

async function toggleUserActive(userId, makeActive) {
    try {
        const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ active: makeActive }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            showToast(data.message || "Update failed", "error");
            return;
        }
        showToast(makeActive ? "Account enabled" : "Account disabled", "success");
        await loadUsers();
    } catch (e) {
        showToast(String(e), "error");
    }
}

async function unbanIp(ip) {
    if (!ip) return;
    if (!confirm(`Unban IP ${ip}?`)) return;
    try {
        const res = await fetch("/api/admin/security/unban-ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            showToast(data.message || "Unban failed", "error");
            return;
        }
        showToast("IP unbanned", "success");
        await loadSecurityStatus();
    } catch (e) {
        showToast(String(e), "error");
    }
}

async function loadSecurityStatus() {
    const bannedWrap = document.getElementById("banned-ip-list");
    const manualWrap = document.getElementById("blacklist-ip-list");
    const whiteWrap = document.getElementById("whitelist-ip-list");
    const wlBtn = document.getElementById("whitelist-toggle-btn");
    if (!bannedWrap && !manualWrap && !whiteWrap) return;
    try {
        const res = await fetch("/api/admin/security-status");
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            const msg = `<p class="mgmt-msg error">${escapeHtml(data.message || "Failed to load security status")}</p>`;
            if (bannedWrap) bannedWrap.innerHTML = msg;
            if (manualWrap) manualWrap.innerHTML = msg;
            if (whiteWrap) whiteWrap.innerHTML = msg;
            return;
        }
        const bannedRows = (data.banned_ips || [])
            .map(
                (b) => `
            <div class="user-row">
                <div class="user-row-main">
                    <strong>${escapeHtml(b.ip)}</strong>
                    <div class="storage-path-sub">${escapeHtml(b.reason || "")}</div>
                    <div class="storage-path-sub">Blocked: ${escapeHtml(b.banned_at || "—")} • Attempts: ${escapeHtml(String(b.attempts || 0))}</div>
                </div>
                <div class="user-row-actions">
                    <button type="button" class="btn btn-secondary btn-sm js-unban-ip" data-ip="${escapeAttr(b.ip)}">Unban</button>
                </div>
            </div>`
            )
            .join("");
        if (bannedWrap) {
            bannedWrap.innerHTML = bannedRows || "<p class=\"mgmt-msg\">No auto-blocked IPs.</p>";
            bannedWrap.querySelectorAll(".js-unban-ip").forEach((btn) => {
                btn.addEventListener("click", () => unbanIp(btn.getAttribute("data-ip")));
            });
        }

        const blackRows = (data.manual_blacklist || [])
            .map(
                (b) => `
            <div class="user-row">
                <div class="user-row-main">
                    <strong>${escapeHtml(b.ip)}</strong>
                    <div class="storage-path-sub">${escapeHtml(b.reason || "")}</div>
                    <div class="storage-path-sub">Added: ${escapeHtml(b.added_at || "—")}</div>
                </div>
                <div class="user-row-actions">
                    <button type="button" class="btn btn-secondary btn-sm js-unblack-ip" data-ip="${escapeAttr(b.ip)}">Remove</button>
                </div>
            </div>`
            )
            .join("");
        if (manualWrap) {
            manualWrap.innerHTML = blackRows || "<p class=\"mgmt-msg\">No blacklisted IPs.</p>";
            manualWrap.querySelectorAll(".js-unblack-ip").forEach((btn) => {
                btn.addEventListener("click", () => unblacklistIp(btn.getAttribute("data-ip")));
            });
        }

        const wl = data.whitelist_ips || [];
        if (wlBtn) wlBtn.textContent = data.whitelist_enabled ? "Disable whitelist" : "Enable whitelist";
        const whiteRows = wl
            .map(
                (ip) => `
            <div class="user-row">
                <div class="user-row-main"><strong>${escapeHtml(ip)}</strong></div>
                <div class="user-row-actions">
                    <button type="button" class="btn btn-secondary btn-sm js-white-remove" data-ip="${escapeAttr(ip)}">Remove</button>
                </div>
            </div>`
            )
            .join("");
        if (whiteWrap) {
            whiteWrap.innerHTML =
                `<p class="mgmt-msg">${data.whitelist_enabled ? "Whitelist is active" : "Whitelist is inactive"} · Your detected IP: ${escapeHtml(data.detected_ip || "unknown")}</p>` +
                (whiteRows || "<p class=\"mgmt-msg\">No whitelist IPs.</p>");
            whiteWrap.querySelectorAll(".js-white-remove").forEach((btn) => {
                btn.addEventListener("click", () => removeWhitelistIp(btn.getAttribute("data-ip")));
            });
        }
    } catch (e) {
        const msg = `<p class="mgmt-msg error">${escapeHtml(String(e))}</p>`;
        if (bannedWrap) bannedWrap.innerHTML = msg;
        if (manualWrap) manualWrap.innerHTML = msg;
        if (whiteWrap) whiteWrap.innerHTML = msg;
    }
}

async function addBlacklistIp(ip) {
    const res = await fetch("/api/admin/security/blacklist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
    });
    return res.json().catch(() => ({})).then((data) => ({ ok: res.ok, data }));
}

async function unblacklistIp(ip) {
    if (!ip) return;
    if (!confirm(`Remove ${ip} from blacklist?`)) return;
    const { ok, data } = await fetch("/api/admin/security/unblacklist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
    }).then(async (res) => ({ ok: res.ok, data: await res.json().catch(() => ({})) }));
    if (!ok) {
        showToast(data.message || "Failed", "error");
        return;
    }
    showToast("Blacklist updated", "success");
    await loadSecurityStatus();
}

async function addWhitelistIp(ip) {
    const res = await fetch("/api/admin/security/whitelist/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
    });
    return res.json().catch(() => ({})).then((data) => ({ ok: res.ok, data }));
}

async function removeWhitelistIp(ip) {
    if (!ip) return;
    if (!confirm(`Remove ${ip} from whitelist?`)) return;
    const { ok, data } = await fetch("/api/admin/security/whitelist/remove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
    }).then(async (res) => ({ ok: res.ok, data: await res.json().catch(() => ({})) }));
    if (!ok) {
        showToast(data.message || "Failed", "error");
        return;
    }
    showToast("Whitelist updated", "success");
    await loadSecurityStatus();
}

async function toggleWhitelistEnabled() {
    const btn = document.getElementById("whitelist-toggle-btn");
    if (!btn) return;
    const enable = btn.textContent.toLowerCase().includes("enable");
    const res = await fetch("/api/admin/security/whitelist/enable", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: enable }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        showToast(data.message || "Failed", "error");
        return;
    }
    showToast(enable ? "Whitelist enabled" : "Whitelist disabled", "success");
    await loadSecurityStatus();
}

async function loadUsers() {
    const wrap = document.getElementById("user-list");
    if (!wrap) return;
    try {
        const res = await fetch("/api/admin/users");
        const data = await res.json();
        if (!res.ok) {
            wrap.innerHTML = `<p class="mgmt-msg error">${data.message || "Failed to load users"}</p>`;
            return;
        }
        const rows = (data.users || [])
            .map((u) => {
                const active = u.active !== false;
                const inactiveBadge = active ? "" : `<span class="role-pill role-pill-inactive">Disabled</span>`;
                return `
            <div class="user-row" data-user-id="${escapeAttr(u.id)}">
                <div class="user-row-main">
                    <strong>${escapeHtml(u.username)}</strong>
                    <span class="role-pill">${escapeHtml(u.role)}</span>
                    ${inactiveBadge}
                    <div class="storage-path-sub">Last login: ${escapeHtml(u.last_login_local || "—")}</div>
                    <div class="storage-path-sub">Today's successful logins: ${escapeHtml(String(u.login_count_today || 0))}</div>
                </div>
                <div class="user-row-actions">
                    <button type="button" class="btn btn-secondary btn-sm js-set-password" data-user-id="${escapeAttr(u.id)}" data-username="${escapeAttr(u.username)}">Password</button>
                    <button type="button" class="btn btn-secondary btn-sm js-toggle-active" data-user-id="${escapeAttr(u.id)}" data-make-active="${active ? "0" : "1"}">${active ? "Disable" : "Enable"}</button>
                    <button type="button" class="btn btn-danger btn-sm js-delete" data-user-id="${escapeAttr(u.id)}">Delete</button>
                </div>
            </div>`;
            })
            .join("");
        wrap.innerHTML = rows || "<p>No users.</p>";
        wrap.querySelectorAll(".js-delete").forEach((btn) => {
            btn.addEventListener("click", () => deleteUser(btn.getAttribute("data-user-id")));
        });
        wrap.querySelectorAll(".js-set-password").forEach((btn) => {
            btn.addEventListener("click", () =>
                openAdminPasswordModal(btn.getAttribute("data-user-id"), btn.getAttribute("data-username"))
            );
        });
        wrap.querySelectorAll(".js-toggle-active").forEach((btn) => {
            btn.addEventListener("click", () => {
                const makeActive = btn.getAttribute("data-make-active") === "1";
                toggleUserActive(btn.getAttribute("data-user-id"), makeActive);
            });
        });
    } catch (e) {
        wrap.innerHTML = `<p class="mgmt-msg error">${String(e)}</p>`;
    }
}

async function loadServers() {
    const wrap = document.getElementById("server-list");
    if (!wrap) return;
    try {
        const res = await fetch("/api/admin/servers");
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            wrap.innerHTML = `<p class="mgmt-msg error">${escapeHtml(data.message || "Failed to load servers")}</p>`;
            return;
        }
        const rows = (data.servers || [])
            .map(
                (s) => `
            <div class="user-row">
                <div class="user-row-main">
                    <strong>${escapeHtml(s.name || "")}</strong>
                    <div class="storage-path-sub">${escapeHtml(s.hostname || "")}</div>
                </div>
                <div class="user-row-actions">
                    <button type="button" class="btn btn-secondary btn-sm js-edit-server" data-server-id="${escapeAttr(s.id)}" data-server-name="${escapeAttr(s.name || "")}" data-server-hostname="${escapeAttr(s.hostname || "")}" data-server-username="${escapeAttr(s.username || "")}">Edit</button>
                    <button type="button" class="btn btn-danger btn-sm js-delete-server" data-server-id="${escapeAttr(s.id)}">Delete</button>
                </div>
            </div>`
            )
            .join("");
        wrap.innerHTML = rows || "<p class=\"mgmt-msg\">No servers added yet.</p>";
        wrap.querySelectorAll(".js-edit-server").forEach((btn) => {
            btn.addEventListener("click", () => startEditServer(
                btn.getAttribute("data-server-id"),
                btn.getAttribute("data-server-name"),
                btn.getAttribute("data-server-hostname"),
                btn.getAttribute("data-server-username")
            ));
        });
        wrap.querySelectorAll(".js-delete-server").forEach((btn) => {
            btn.addEventListener("click", () => deleteServer(btn.getAttribute("data-server-id")));
        });
    } catch (e) {
        wrap.innerHTML = `<p class="mgmt-msg error">${escapeHtml(String(e))}</p>`;
    }
}

function startEditServer(id, name, hostname, username) {
    const idEl = document.getElementById("edit-server-id");
    const nameEl = document.getElementById("new-server-name");
    const hostEl = document.getElementById("new-server-hostname");
    const userEl = document.getElementById("new-server-username");
    const passEl = document.getElementById("new-server-password");
    const saveBtn = document.getElementById("save-server-btn");
    const cancelBtn = document.getElementById("cancel-server-edit");
    if (idEl) idEl.value = id || "";
    if (nameEl) nameEl.value = name || "";
    if (hostEl) hostEl.value = hostname || "";
    if (userEl) userEl.value = username || "";
    if (passEl) passEl.value = "";
    if (saveBtn) saveBtn.textContent = "Update server";
    if (cancelBtn) cancelBtn.style.display = "inline-flex";
}

function resetServerForm() {
    const form = document.getElementById("add-server-form");
    const idEl = document.getElementById("edit-server-id");
    const saveBtn = document.getElementById("save-server-btn");
    const cancelBtn = document.getElementById("cancel-server-edit");
    if (form) form.reset();
    if (idEl) idEl.value = "";
    if (saveBtn) saveBtn.textContent = "Save server";
    if (cancelBtn) cancelBtn.style.display = "none";
}

async function deleteServer(serverId) {
    if (!serverId) return;
    if (!confirm("Delete this server? Monitors linked to it will fail until updated.")) return;
    try {
        const res = await fetch(`/api/admin/servers/${encodeURIComponent(serverId)}`, { method: "DELETE" });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            showToast(data.message || "Delete failed", "error");
            return;
        }
        showToast("Server deleted", "success");
        await loadServers();
    } catch (e) {
        showToast(String(e), "error");
    }
}

function escapeHtml(s) {
    return String(s ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function escapeAttr(s) {
    return String(s ?? "").replace(/"/g, "&quot;");
}

async function deleteUser(userId) {
    if (!userId) return;
    if (!confirm("Delete this user?")) return;
    try {
        const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, { method: "DELETE" });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            showToast(data.message || "Delete failed", "error");
            return;
        }
        showToast("User deleted", "success");
        await loadUsers();
    } catch (e) {
        showToast(String(e), "error");
    }
}

document.getElementById("add-user-form")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const msg = document.getElementById("add-user-msg");
    if (msg) msg.textContent = "";
    const username = document.getElementById("new-username")?.value?.trim() || "";
    const password = document.getElementById("new-password")?.value || "";
    const role = document.getElementById("new-role")?.value || "user";
    try {
        const res = await fetch("/api/admin/users", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password, role }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (msg) msg.textContent = data.message || "Create failed";
            showToast(data.message || "Create failed", "error");
            return;
        }
        showToast("User created", "success");
        ev.target.reset();
        await loadUsers();
    } catch (e) {
        if (msg) msg.textContent = String(e);
        showToast(String(e), "error");
    }
});

document.getElementById("logout-btn")?.addEventListener("click", async () => {
    try {
        await fetch("/api/auth/logout", { method: "POST" });
    } catch {
        /* ignore */
    }
    window.location.href = "/login";
});

async function loadBaleSettings() {
    const input = document.getElementById("bale-bot-url");
    const msg = document.getElementById("bale-settings-msg");
    if (!input) return;
    try {
        const res = await fetch("/api/admin/bale-settings");
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (msg) msg.textContent = data.message || "Failed to load Bale settings";
            return;
        }
        input.value = data.bot_url || "";
        if (msg) msg.textContent = "";
    } catch (e) {
        if (msg) msg.textContent = String(e);
    }
}

async function loadSessionSettings() {
    const input = document.getElementById("session-timeout-minutes");
    const thrInput = document.getElementById("brute-force-threshold");
    const msg = document.getElementById("session-settings-msg");
    if (!input) return;
    try {
        const res = await fetch("/api/admin/session-settings");
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (msg) msg.textContent = data.message || "Failed to load session settings";
            return;
        }
        input.value = String(data.session_timeout_minutes ?? 15);
        if (thrInput) thrInput.value = String(data.brute_force_threshold ?? 5);
        if (msg) msg.textContent = "";
    } catch (e) {
        if (msg) msg.textContent = String(e);
    }
}

document.getElementById("session-settings-form")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const msg = document.getElementById("session-settings-msg");
    const raw = document.getElementById("session-timeout-minutes")?.value ?? "15";
    const thr = document.getElementById("brute-force-threshold")?.value ?? "5";
    if (msg) msg.textContent = "";
    try {
        const res = await fetch("/api/admin/session-settings", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_timeout_minutes: Number(raw), brute_force_threshold: Number(thr) }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (msg) msg.textContent = data.message || "Save failed";
            showToast(data.message || "Save failed", "error");
            return;
        }
        if (document.getElementById("session-timeout-minutes")) {
            document.getElementById("session-timeout-minutes").value = String(data.session_timeout_minutes ?? raw);
        }
        if (document.getElementById("brute-force-threshold")) {
            document.getElementById("brute-force-threshold").value = String(data.brute_force_threshold ?? thr);
        }
        showToast("Session lifetime saved", "success");
    } catch (e) {
        if (msg) msg.textContent = String(e);
        showToast(String(e), "error");
    }
});

document.getElementById("bale-settings-form")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const msg = document.getElementById("bale-settings-msg");
    const botUrl = document.getElementById("bale-bot-url")?.value?.trim() || "";
    if (msg) msg.textContent = "";
    try {
        const res = await fetch("/api/admin/bale-settings", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ bot_url: botUrl }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (msg) msg.textContent = data.message || "Save failed";
            showToast(data.message || "Save failed", "error");
            return;
        }
        showToast("Bale URL saved", "success");
    } catch (e) {
        if (msg) msg.textContent = String(e);
        showToast(String(e), "error");
    }
});

function formatBytes(n) {
    const num = Number(n) || 0;
    if (num === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(num) / Math.log(k)));
    return `${parseFloat((num / Math.pow(k, i)).toFixed(i === 0 ? 0 : 2))} ${sizes[i]}`;
}

async function loadStorage() {
    const loading = document.getElementById("storage-loading");
    const wrap = document.getElementById("storage-wrap");
    const errEl = document.getElementById("storage-error");
    const dirHint = document.getElementById("storage-data-dir");
    if (!wrap) return;
    if (loading) loading.classList.remove("hidden");
    if (wrap) wrap.classList.add("hidden");
    if (errEl) {
        errEl.classList.add("hidden");
        errEl.textContent = "";
    }
    try {
        const res = await fetch("/api/admin/storage");
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (errEl) {
                errEl.textContent = data.message || "Failed to load storage";
                errEl.classList.remove("hidden");
            }
            return;
        }
        if (dirHint && data.data_directory) dirHint.textContent = data.data_directory.replace(/\\/g, "/") + "/";
        const files = data.files || [];
        const catLabel = {
            configuration: "Configuration",
            logs: "Logs",
            data: "Other data",
        };
        const tbody = files
            .map((f) => {
                const cat = catLabel[f.category] || f.category || "—";
                const flushBtn =
                    f.flushable && f.id === "alert_history"
                        ? `<button type="button" class="btn btn-danger btn-sm js-flush-log" data-target="alert_history">Flush</button>`
                        : "—";
                return `<tr>
                    <td>${escapeHtml(cat)}</td>
                    <td class="storage-path"><span title="${escapeAttr(f.path)}">${escapeHtml(f.label)}</span><span class="storage-path-sub">${escapeHtml(f.path)}</span></td>
                    <td class="mono">${escapeHtml(formatBytes(f.size_bytes))}</td>
                    <td>${flushBtn}</td>
                </tr>`;
            })
            .join("");
        wrap.innerHTML = `
            <div class="storage-toolbar">
                <button type="button" class="btn btn-secondary btn-sm" id="storage-refresh"><i class="fas fa-sync-alt"></i> Refresh</button>
            </div>
            <table class="storage-table">
                <thead><tr><th>Category</th><th>File</th><th>Size</th><th></th></tr></thead>
                <tbody>${tbody}</tbody>
            </table>`;
        wrap.querySelector("#storage-refresh")?.addEventListener("click", () => loadStorage());
        wrap.querySelectorAll(".js-flush-log").forEach((btn) => {
            btn.addEventListener("click", () => flushAlertHistory());
        });
        wrap.classList.remove("hidden");
    } catch (e) {
        if (errEl) {
            errEl.textContent = String(e);
            errEl.classList.remove("hidden");
        }
    } finally {
        if (loading) loading.classList.add("hidden");
    }
}

async function flushAlertHistory() {
    if (!confirm("Clear the alert activity log? All entries will be removed. This cannot be undone.")) return;
    try {
        const res = await fetch("/api/admin/storage/flush", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: "alert_history" }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            showToast(data.message || "Flush failed", "error");
            return;
        }
        showToast("Alert log cleared", "success");
        await loadStorage();
    } catch (e) {
        showToast(String(e), "error");
    }
}

function initMgmtTabs() {
    const tabs = document.querySelectorAll(".mgmt-tab[data-tab]");
    const panels = document.querySelectorAll(".mgmt-panel[data-panel]");
    if (!tabs.length || !panels.length) return;

    const activate = (name) => {
        tabs.forEach((btn) => {
            const on = btn.getAttribute("data-tab") === name;
            btn.classList.toggle("active", on);
            btn.setAttribute("aria-selected", on ? "true" : "false");
        });
        panels.forEach((panel) => {
            const on = panel.getAttribute("data-panel") === name;
            panel.classList.toggle("active", on);
            panel.toggleAttribute("hidden", !on);
        });
        try {
            localStorage.setItem("mgmt_active_tab", name);
        } catch {
            /* ignore */
        }
        if (name === "storage") loadStorage();
        if (name === "security") loadSecurityStatus();
        if (name === "servers") loadServers();
    };

    tabs.forEach((btn) => {
        btn.addEventListener("click", () => activate(btn.getAttribute("data-tab") || "users"));
    });

    let initial = "users";
    try {
        const saved = localStorage.getItem("mgmt_active_tab");
        if (saved === "bale" || saved === "users" || saved === "storage" || saved === "security" || saved === "servers") initial = saved;
    } catch {
        /* ignore */
    }
    activate(initial);
}

document.getElementById("admin-pw-modal-close")?.addEventListener("click", closeAdminPasswordModal);
document.getElementById("admin-pw-cancel")?.addEventListener("click", closeAdminPasswordModal);
document.getElementById("admin-pw-save")?.addEventListener("click", saveAdminPassword);
document.getElementById("admin-password-modal")?.addEventListener("click", (ev) => {
    if (ev.target?.id === "admin-password-modal") closeAdminPasswordModal();
});
document.getElementById("blacklist-add-form")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const ip = document.getElementById("blacklist-ip-input")?.value?.trim() || "";
    const msg = document.getElementById("blacklist-msg");
    if (msg) msg.textContent = "";
    const { ok, data } = await addBlacklistIp(ip);
    if (!ok) {
        if (msg) msg.textContent = data.message || "Failed";
        showToast(data.message || "Failed", "error");
        return;
    }
    if (document.getElementById("blacklist-ip-input")) document.getElementById("blacklist-ip-input").value = "";
    showToast("IP blacklisted", "success");
    await loadSecurityStatus();
});
document.getElementById("whitelist-add-form")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const ip = document.getElementById("whitelist-ip-input")?.value?.trim() || "";
    const msg = document.getElementById("whitelist-msg");
    if (msg) msg.textContent = "";
    const { ok, data } = await addWhitelistIp(ip);
    if (!ok) {
        if (msg) msg.textContent = data.message || "Failed";
        showToast(data.message || "Failed", "error");
        return;
    }
    if (document.getElementById("whitelist-ip-input")) document.getElementById("whitelist-ip-input").value = "";
    showToast("IP added to whitelist", "success");
    await loadSecurityStatus();
});
document.getElementById("whitelist-toggle-btn")?.addEventListener("click", toggleWhitelistEnabled);
document.getElementById("add-server-form")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const msg = document.getElementById("add-server-msg");
    if (msg) msg.textContent = "";
    const serverId = document.getElementById("edit-server-id")?.value?.trim() || "";
    const name = document.getElementById("new-server-name")?.value?.trim() || "";
    const hostname = document.getElementById("new-server-hostname")?.value?.trim() || "";
    const username = document.getElementById("new-server-username")?.value?.trim() || "";
    const password = document.getElementById("new-server-password")?.value || "";
    try {
        const res = await fetch("/api/admin/servers", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: serverId || undefined, name, hostname, username, password }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (msg) msg.textContent = data.message || "Save failed";
            showToast(data.message || "Save failed", "error");
            return;
        }
        showToast(serverId ? "Server updated" : "Server saved", "success");
        resetServerForm();
        await loadServers();
    } catch (e) {
        if (msg) msg.textContent = String(e);
        showToast(String(e), "error");
    }
});
document.getElementById("cancel-server-edit")?.addEventListener("click", resetServerForm);

(async function init() {
    await requireSession();
    initMgmtTabs();
    await loadSessionSettings();
    await loadBaleSettings();
    await loadUsers();
    await loadServers();
})();
