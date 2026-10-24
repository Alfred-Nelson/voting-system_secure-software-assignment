"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  function msg(text, kind) {
    $("check-msg").innerHTML = "";
    const d = document.createElement("div"); d.className = "msg " + kind; d.textContent = text;
    $("check-msg").appendChild(d);
  }
  async function load() {
    const r = await fetch("/api/bulletin").then(x => x.json());
    const body = $("receipts"); body.innerHTML = "";
    for (const rec of r.receipts) {
      const tr = document.createElement("tr");
      const a = document.createElement("td"); a.className = "mono"; a.textContent = rec.code;
      const b = document.createElement("td"); b.textContent = rec.issued_hour;
      tr.append(a, b); body.appendChild(tr);
    }
    $("count").textContent = r.receipts.length;
  }
  $("check-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const code = $("code").value.trim().toUpperCase();
    const r = await fetch("/api/bulletin/" + encodeURIComponent(code)).then(x => x.json());
    if (!r.found) msg("Receipt not found.", "bad");
    else if (!r.signature_valid) msg("Receipt found but its signature is INVALID - report this to the AEC.", "bad");
    else msg(`Recorded ✓  Signature valid ✓  (issued ${r.issued_hour})`, "ok");
  });
  load();
})();
