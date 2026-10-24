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
    } catch (err) { msg("login-msg", err.message, "bad"); }
  });
  $("logout-btn").addEventListener("click", async () => {
    await api("POST", "/api/auth/logout").catch(() => {}); signedOut("Signed out.");
  });
})();
