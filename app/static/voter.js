/* Voter client - all ballot cryptography runs here, in the browser (WebCrypto + BigInt).
   Mirrors client/voter_client.py. */
"use strict";

(() => {
  let token = null;          // session token - only used to get the blind credential

  // ---------------------------------------------------------------- encoding helpers
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  const sha256 = async (data) => crypto.subtle.digest("SHA-256", data);
  function pemToDer(pem) {
    const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    return Uint8Array.from(atob(body), c => c.charCodeAt(0)).buffer;
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
})();
