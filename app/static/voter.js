/* Voter client - all ballot cryptography runs here, in the browser (WebCrypto + BigInt).
   Mirrors client/voter_client.py. */
"use strict";

(() => {
  let election = null;
  let token = null;          // session token - only used to get the blind credential
  const $ = (id) => document.getElementById(id);

  // ---------------------------------------------------------------- encoding helpers
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
})();
