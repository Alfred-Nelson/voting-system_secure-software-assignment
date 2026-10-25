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

  // ---------------------------------------------------------------- election
  loaders.election = async () => {
    const e = await fetch("/api/election").then(r => r.json());
    $("el-status").textContent = e.status; $("el-status").className = "badge " + e.status;
  };
  document.querySelectorAll("[data-status]").forEach(b => b.addEventListener("click", async () => {
    try { await api("POST", "/api/admin/election/status", { status: b.dataset.status }); msg("election-msg", "Status changed.", "ok"); }
    catch (err) { msg("election-msg", err.message, "bad"); }
    loaders.election();
  }));
  $("tally-btn").addEventListener("click", async () => {
    try {
      const r = await api("POST", "/api/admin/tally");
      const res = r.result;
      const label = id => res.candidates && res.candidates[id] ? `${res.candidates[id].name} (${res.candidates[id].party})` : id;
      msg("election-msg", `Ledger verified. Elected: ${res.elected.map(label).join(", ")} · formal ${res.formal_ballots}, informal ${res.informal_ballots} · quota ${res.quota}\nResult signed with results_sign v${r.key_version}.`, "ok");
      $("tally-out").textContent = JSON.stringify(r, null, 2); $("tally-out").classList.remove("hidden");
    } catch (err) { msg("election-msg", err.message, "bad"); }
    loaders.election();
  });

  // ---------------------------------------------------------------- keys
  loaders.keys = async () => {
    const r = await api("GET", "/api/admin/keys");
    table("keys-table", r.keys, ["purpose", "algorithm", "current_version", "created", "rotatable"]);
    if (r.rotation_due.length) msg("keys-msg", "Due for 90-day rotation: " + r.rotation_due.join(", "), "warn");
  };
  $("rotate-btn").addEventListener("click", async () => {
    try { const r = await api("POST", "/api/admin/keys/rotate", { purpose: $("rotate-purpose").value, reason: "manual (console)" });
      msg("keys-msg", `${r.purpose} rotated to version ${r.version}`, "ok"); loaders.keys(); }
    catch (err) { msg("keys-msg", err.message, "bad"); }
  });

  // ---------------------------------------------------------------- alerts
  loaders.alerts = async () => {
    const r = await api("GET", "/api/admin/alerts");
    table("alerts-table", r.alerts, ["id", "ts", "severity", "kind", "message"], can("alerts.ack") ? (row) => {
      const b = document.createElement("button"); b.className = "secondary"; b.type = "button"; b.textContent = "Ack";
      b.addEventListener("click", async () => { await api("POST", `/api/admin/alerts/${row.id}/ack`); loaders.alerts(); });
      return b;
    } : null);
  };
  $("alerts-refresh").addEventListener("click", () => loaders.alerts());

  // ---------------------------------------------------------------- terminals
  loaders.terminals = async () => {
    const r = await api("GET", "/api/admin/terminals");
    table("terminals-table", r.terminals.map(t => ({ ...t, last_heartbeat: t.last_heartbeat ? new Date(t.last_heartbeat * 1000).toLocaleTimeString() : "never" })),
      ["id", "location", "status", "last_heartbeat"]);
  };
  $("terminals-refresh").addEventListener("click", () => loaders.terminals());

  // ---------------------------------------------------------------- candidates
  $("cand-btn").addEventListener("click", async () => {
    const body = {};
    if ($("cand-name").value.trim()) body.name = $("cand-name").value.trim();
    if ($("cand-party").value.trim()) body.party = $("cand-party").value.trim();
    try { await api("PUT", "/api/admin/candidates/" + encodeURIComponent($("cand-id").value.trim()), body); msg("cand-msg", "Candidate updated (audited with before/after values).", "ok"); }
    catch (err) { msg("cand-msg", err.message, "bad"); }
  });

  // ---------------------------------------------------------------- approvals
  loaders.approvals = async () => {
    const r = await api("GET", "/api/admin/approvals");
    table("ap-table", r.requests.map(x => ({ ...x, approvals: x.approvals.join(", ") })),
      ["id", "action", "target", "reason", "requested_by", "status", "approvals"],
      can("approval.approve") ? (row) => {
        if (row.status !== "pending") return null;
        const b = document.createElement("button"); b.type = "button"; b.textContent = "Approve";
        b.addEventListener("click", async () => {
          try { const res = await api("POST", `/api/admin/approvals/${row.id}/approve`);
            msg("ap-msg", res.status === "executed" ? "Second approval recorded - action executed: " + JSON.stringify(res.outcome) : `Approval recorded - ${res.needed} more needed`, "ok"); }
          catch (err) { msg("ap-msg", err.message, "bad"); }
          loaders.approvals();
        });
        return b;
      } : null);
  };
  $("ap-btn").addEventListener("click", async () => {
    try { const r = await api("POST", "/api/admin/approvals", { action: $("ap-action").value, target: $("ap-target").value.trim() || null, reason: $("ap-reason").value.trim() });
      msg("ap-msg", `Request #${r.request_id} created - waiting for two delegate approvals.`, "ok"); loaders.approvals(); }
    catch (err) { msg("ap-msg", err.message, "bad"); }
  });
  $("ap-refresh").addEventListener("click", () => loaders.approvals());

  // ---------------------------------------------------------------- station
  $("st-btn").addEventListener("click", async () => {
    try { await api("POST", "/api/station/mark-voted", { enrolment_id: $("st-enrol").value.trim().toUpperCase(), channel: $("st-channel").value });
      msg("st-msg", "Voter marked as voted. Any further vote on any channel will be refused.", "ok"); }
    catch (err) { msg("st-msg", err.message, "bad"); }
  });

  // ---------------------------------------------------------------- audit
  loaders.audit = async () => {
    const r = await api("GET", "/api/audit");
    table("audit-table", r.entries.map(e => ({ ...e, entry_hash: e.entry_hash.slice(0, 16) + "…" })),
      ["seq", "ts", "actor", "role", "action", "details", "entry_hash"]);
  };
  $("audit-refresh").addEventListener("click", () => loaders.audit());
  $("audit-verify").addEventListener("click", async () => {
    try { const r = await api("GET", "/api/audit/verify");
      msg("audit-msg", r.ok ? `Audit chain intact - ${r.entries} entries, every MAC valid.` : `TAMPERING DETECTED at entry ${r.first_bad_seq}: ${r.reason}`, r.ok ? "ok" : "bad"); }
    catch (err) { msg("audit-msg", err.message, "bad"); }
  });
  $("ledger-verify").addEventListener("click", async () => {
    try { const r = await api("GET", "/api/ledger/verify");
      msg("audit-msg", r.ok ? `Ballot ledger intact - ${r.ledger_entries} ledger entries match ${r.stored_ballots} stored ballots.` : "LEDGER PROBLEM:\n" + r.problems.join("\n"), r.ok ? "ok" : "bad"); }
    catch (err) { msg("audit-msg", err.message, "bad"); }
  });
})();
