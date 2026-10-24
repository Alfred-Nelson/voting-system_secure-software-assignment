/* Staff console. The UI only hides what a role cannot use - every permission is
   enforced again on the server (SR-16). */
"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  // UI-only copy of ROLE_PERMISSIONS (app/security/rbac.py); the server still checks every call.
  const PERMS = {
    employee: ["station.mark_voted", "approval.request", "terminal.view", "alerts.view"],
    delegate: ["candidates.edit", "approval.request", "approval.approve", "alerts.view"],
    admin: ["election.configure", "tally.run", "results.publish", "keys.rotate", "keys.view",
      "alerts.view", "alerts.ack", "terminal.view", "backup.run"],
    auditor: ["audit.view", "audit.verify", "ledger.verify", "alerts.view", "keys.view"],
  };
  let token = null, me = null;

  function msg(el, text, kind) {
    $(el).innerHTML = "";
    if (!text) return;
    const d = document.createElement("div"); d.className = "msg " + kind; d.textContent = text;
    $(el).appendChild(d);
  }
  // A 401 while signed in means the 3-minute idle timeout (or a revoked session) - sign the user out.
  async function api(method, path, body) {
    const r = await fetch(path, {
      method, body: body ? JSON.stringify(body) : undefined,
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
    });
    const data = await r.json().catch(() => ({}));
    if (r.status === 401 && token) { signedOut(data.error || "Session ended"); throw new Error(data.error); }
    if (!r.ok) throw new Error(data.error || "HTTP " + r.status);
    return data;
  }
  // Every cell is filled with textContent, never innerHTML, so server data cannot inject markup (XSS).
  function table(id, rows, cols, extra) {
    const t = $(id); t.innerHTML = "";
    const head = document.createElement("tr");
    for (const c of cols.concat(extra ? [""] : [])) { const th = document.createElement("th"); th.textContent = c; head.appendChild(th); }
    t.appendChild(head);
    for (const row of rows) {
      const tr = document.createElement("tr");
      for (const c of cols) {
        const td = document.createElement("td");
        let v = row[c]; if (typeof v === "object" && v !== null) v = JSON.stringify(v);
        td.textContent = v === undefined || v === null ? "" : String(v);
        tr.appendChild(td);
      }
      if (extra) { const td = document.createElement("td"); const el = extra(row); if (el) td.appendChild(el); tr.appendChild(td); }
      t.appendChild(tr);
    }
  }

  const can = (p) => (PERMS[me.role] || []).includes(p);

  // ---------------------------------------------------------------- login
  function signedOut(reason) {
    token = null; me = null;
    $("console").classList.add("hidden"); $("login-panel").classList.remove("hidden");
    $("who").classList.add("hidden");
    msg("login-msg", reason, "warn");
  }
  $("login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      const r = await fetch("/api/auth/staff/login", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: $("username").value.trim(), password: $("password").value, totp: $("totp").value.trim() }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error);
      token = d.token; me = { username: $("username").value.trim(), role: d.role, state: d.state };
      $("password").value = ""; $("totp").value = "";
      $("user").textContent = me.username + (me.state ? ` (${me.state})` : "");
      $("role").textContent = me.role; $("idle").textContent = d.idle_timeout_sec;
      $("who").textContent = me.role; $("who").classList.remove("hidden");
      $("login-panel").classList.add("hidden"); $("console").classList.remove("hidden");
      msg("login-msg", "", "");
      buildTabs();
    } catch (err) { msg("login-msg", err.message, "bad"); }
  });
  $("logout-btn").addEventListener("click", async () => {
    await api("POST", "/api/auth/logout").catch(() => {}); signedOut("Signed out.");
  });

  // Only tabs whose permission the role has are shown (UI only - the server enforces it).
  function buildTabs() {
    const tabs = $("tabs"); tabs.innerHTML = "";
    let first = null;
    document.querySelectorAll(".tab").forEach(panel => {
      const ok = can(panel.dataset.perm);
      panel.classList.add("hidden");
      if (!ok) return;
      const b = document.createElement("button"); b.type = "button"; b.textContent = panel.querySelector("h2").textContent.replace(/\s*\(.*\)/, "");
      b.addEventListener("click", () => select(panel.dataset.tab));
      b.dataset.tab = panel.dataset.tab; tabs.appendChild(b);
      first = first || panel.dataset.tab;
    });
    document.querySelectorAll(".admin-only").forEach(el => el.classList.toggle("hidden", !can("keys.rotate")));
    if (first) select(first);
  }
  const loaders = {};
  function select(name) {
    document.querySelectorAll(".tab").forEach(p => p.classList.toggle("hidden", p.dataset.tab !== name));
    document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    if (loaders[name]) loaders[name]().catch(() => {});
  }
})();
