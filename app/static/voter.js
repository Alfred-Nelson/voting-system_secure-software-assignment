/* Voter client - all ballot cryptography runs here, in the browser (WebCrypto + BigInt).
   Mirrors client/voter_client.py. */
"use strict";

(() => {
  let election = null;
  let token = null;          // session token - only used to get the blind credential
  let walletKey = null;      // localStorage key for this voter's credential
  const $ = (id) => document.getElementById(id);

  // ---------------------------------------------------------------- encoding helpers
  const enc = new TextEncoder();
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  const sha256 = async (data) => crypto.subtle.digest("SHA-256", data);
  function pemToDer(pem) {
    const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    return Uint8Array.from(atob(body), c => c.charCodeAt(0)).buffer;
  }

  // ---------------------------------------------------------------- BigInt RSA blind signatures (SR-07)
  function modPow(base, exp, mod) {
    let result = 1n; base %= mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      base = (base * base) % mod; exp >>= 1n;
    }
    return result;
  }
  function modInv(a, m) {
    let [oldR, r] = [a % m, m], [oldS, s] = [1n, 0n];
    while (r !== 0n) { const q = oldR / r; [oldR, r] = [r, oldR - q * r]; [oldS, s] = [s, oldS - q * s]; }
    if (oldR !== 1n) throw new Error("not invertible");
    return ((oldS % m) + m) % m;
  }
  // Extra 8 random bytes keep the modulo bias negligible; result is in [2, n-1].
  function randomBelow(n) {
    const bytes = new Uint8Array(Math.ceil(n.toString(16).length / 2) + 8);
    crypto.getRandomValues(bytes);
    return (BigInt("0x" + hex(bytes)) % (n - 2n)) + 2n;
  }

  // The Bearer token is attached only when the caller asks (auth = true), so the
  // anonymous ballot submission never carries the login session.
  async function api(method, path, body, auth) {
    const headers = { "Content-Type": "application/json" };
    if (auth && token) headers["Authorization"] = "Bearer " + token;
    const r = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    return data;
  }

  // ---------------------------------------------------------------- render ballot paper
  // Built with createElement/textContent only - no server data goes through innerHTML (XSS-safe)
  function makeBox(section, id, title, subtitle) {
    const box = document.createElement("div"); box.className = "box";
    const input = document.createElement("input");
    input.dataset[section] = id; input.maxLength = 2; input.inputMode = "numeric";
    input.setAttribute("aria-label", title);
    const name = document.createElement("span"); name.className = "name"; name.textContent = title;
    const party = document.createElement("span"); party.className = "party"; party.textContent = subtitle;
    box.append(input, name, party);
    return box;
  }
  function renderBallot() {
    const atl = $("atl"), btl = $("btl");
    atl.replaceChildren(); btl.replaceChildren();
    for (const g of election.groups) {
      atl.appendChild(makeBox("atl", g.code, `Group ${g.code}`, g.name));
    }
    for (const c of election.candidates) {
      btl.appendChild(makeBox("btl", c.id, `${c.id} · ${c.name}`,
        c.party + (c.group_code ? ` (Group ${c.group_code})` : " (Ungrouped)")));
    }
  }
  function readBallot() {
    const ballot = { atl: {}, btl: {} };
    document.querySelectorAll("[data-atl]").forEach(i => { if (i.value.trim()) ballot.atl[i.dataset.atl] = i.value.trim(); });
    document.querySelectorAll("[data-btl]").forEach(i => { if (i.value.trim()) ballot.btl[i.dataset.btl] = i.value.trim(); });
    return ballot;
  }

  // ---------------------------------------------------------------- formality check (SR-12)
  function show(el, text, kind) {
    $(el).replaceChildren();
    if (!text) return;
    const d = document.createElement("div");
    d.className = "msg " + kind; d.textContent = text; $(el).appendChild(d);
  }
  function step(name) {
    document.querySelector(`#steps li[data-step="${name}"]`).classList.add("done");
  }
  function checkBallot() {
    const groups = Object.fromEntries(election.groups.map(g => [g.code, g.candidates]));
    const res = Formality.validate(readBallot(), groups, election.candidates.map(c => c.id));
    if (!res.formal) show("ballot-msg", "Not yet formal:\n• " + res.errors.join("\n• "), "bad");
    else show("ballot-msg", `Formal (${res.used.toUpperCase()}). Preference order: ${res.order.join(" > ")}` +
      (res.warnings.length ? "\n\nNote:\n• " + res.warnings.join("\n• ") : ""), res.warnings.length ? "warn" : "ok");
    return res;
  }

  // ---------------------------------------------------------------- credential (SR-03/04/07)
  async function obtainCredential() {
    const n = BigInt("0x" + election.keys.blind_n), e = BigInt("0x" + election.keys.blind_e);
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
    const m = BigInt("0x" + hex(await sha256(spki))) % n;
    const r = randomBelow(n);
    const blinded = (m * modPow(r, e, n)) % n;                  // m' = m * r^e mod n
    const res = await api("POST", "/api/voter/credential", { blinded: blinded.toString(16) }, true);
    const sig = (BigInt("0x" + res.blind_signature) * modInv(r, n)) % n;   // s = s' * r^-1
    if (modPow(sig, e, n) !== m) throw new Error("AEC returned an invalid blind signature");
    const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    localStorage.setItem(walletKey, JSON.stringify({ jwk, spki: b64(spki), token: sig.toString(16) }));
    return { key: pair.privateKey, spki, token: sig.toString(16) };
  }

  // ---------------------------------------------------------------- encrypt + sign (SR-05/09/10)
  async function buildSubmission(ballot, cred) {
    const json = enc.encode(JSON.stringify(ballot));
    const size = election.pad_bytes;
    if (json.length + 4 > size) throw new Error("ballot too large");
    const padded = new Uint8Array(size);                         // [len:4][json][random]
    new DataView(padded.buffer).setUint32(0, json.length);
    padded.set(json, 4);
    crypto.getRandomValues(padded.subarray(4 + json.length));

    const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, padded);
    const rsaPub = await crypto.subtle.importKey("spki", pemToDer(election.keys.ballot_encryption_pem),
      { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaPub,
      await crypto.subtle.exportKey("raw", aesKey));
    const envelope = { wrapped_key: b64(wrapped), iv: b64(iv), ciphertext: b64(ct) };
    step("encrypt");
    const msg = enc.encode(`v1|${envelope.wrapped_key}|${envelope.iv}|${envelope.ciphertext}`);
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, cred.key, msg);
    step("sign");
    return { credential: b64(cred.spki), token: cred.token, envelope, signature: b64(sig) };
  }

  // Reads back the credential stored by obtainCredential() so a re-vote reuses it
  async function loadWallet() {
    const raw = walletKey && localStorage.getItem(walletKey);
    if (!raw) return null;
    const w = JSON.parse(raw);
    const key = await crypto.subtle.importKey("jwk", w.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    return { key, spki: Uint8Array.from(atob(w.spki), c => c.charCodeAt(0)).buffer, token: w.token };
  }

  // ---------------------------------------------------------------- cast (SR-07/09/15)
  async function cast() {
    document.querySelectorAll("#steps li").forEach(li => li.classList.remove("done"));
    const res = checkBallot();
    if (!res.formal) return;
    step("check");
    $("cast-btn").disabled = true;
    try {
      const raw = readBallot(), ballot = { atl: {}, btl: {} };
      for (const s of ["atl", "btl"]) for (const [k, v] of Object.entries(raw[s])) ballot[s][k] = parseInt(v, 10);
      let cred = await loadWallet();
      if (!cred) cred = await obtainCredential();
      step("cred");
      if (token) { await api("POST", "/api/auth/logout", null, true).catch(() => {}); token = null; }
      step("logout");
      const submission = await buildSubmission(ballot, cred);
      // Small random delay so submission time does not line up with the login (SR-09)
      await new Promise(r => setTimeout(r, 300 + Math.random() * 1200));
      const receipt = await api("POST", "/api/ballots", submission, false);   // NO Authorization header
      step("submit");
      $("receipt").textContent = receipt.receipt;
      $("receipt-panel").classList.remove("hidden");
      $("ballot-panel").classList.add("hidden");
      show("ballot-msg", "", "");
    } catch (err) {
      show("ballot-msg", "Could not cast vote: " + err.message, "bad");
    } finally {
      $("cast-btn").disabled = false;
    }
  }

  // ---------------------------------------------------------------- login (SR-01)
  async function login(ev) {
    ev.preventDefault();
    show("login-msg", "", "");
    try {
      const enrol = $("enrol").value.trim().toUpperCase();
      const r = await api("POST", "/api/auth/voter/login",
        { enrolment_id: enrol, password: $("password").value, totp: $("totp").value.trim() });
      token = r.token;
      walletKey = "evote-credential-" + hex(await sha256(enc.encode(enrol))).slice(0, 16);
      $("password").value = ""; $("totp").value = "";
      $("login-panel").classList.add("hidden");
      $("ballot-panel").classList.remove("hidden");
      if (election.status !== "open") show("ballot-msg", "Voting is not open yet.", "warn");
    } catch (err) {
      show("login-msg", err.message, "bad");
    }
  }

  async function init() {
    election = await api("GET", "/api/election");
    $("status").textContent = election.status;
    $("status").className = "badge " + election.status;
    $("hdr-state").textContent = election.state;
    renderBallot();
    $("login-form").addEventListener("submit", login);
    $("check-btn").addEventListener("click", checkBallot);
    $("cast-btn").addEventListener("click", cast);
    $("clear-btn").addEventListener("click", () => { renderBallot(); show("ballot-msg", "", ""); });
    $("revote-btn").addEventListener("click", () => {
      renderBallot();
      $("receipt-panel").classList.add("hidden");
      $("ballot-panel").classList.remove("hidden");
      document.querySelectorAll("#steps li").forEach(li => li.classList.remove("done"));
    });
  }
  init().catch(err => show("login-msg", "Could not load election: " + err.message, "bad"));
})();
