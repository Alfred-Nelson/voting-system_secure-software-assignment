/* Senate formality rules (SR-12) - browser port of app/voting/formality.py.
   Runs BEFORE encryption so the voter gets an error message without the
   server ever seeing the plaintext ballot. The server re-checks at count time. */
"use strict";

const Formality = (() => {
  function clean(marks, validKeys, label, errors) {
    const out = {};
    for (const [key, raw] of Object.entries(marks || {})) {
      if (raw === "" || raw === null || raw === undefined) continue;
      if (!validKeys.includes(key)) { errors.push(`${label}: unknown box '${key}'`); continue; }
      if (!/^\s*\d+\s*$/.test(String(raw))) { errors.push(`${label}: box '${key}' must contain a whole number`); continue; }
      const v = parseInt(raw, 10);
      if (v < 1 || v > validKeys.length) {
        errors.push(`${label}: box '${key}' number ${v} is out of range (1-${validKeys.length})`); continue;
      }
      out[key] = v;
    }
    return out;
  }

  function sequence(marks) {
    const byNumber = {};
    for (const [k, n] of Object.entries(marks)) (byNumber[n] = byNumber[n] || []).push(k);
    const seq = [];
    let n = 1;
    while (byNumber[n] && byNumber[n].length === 1) { seq.push(byNumber[n][0]); n++; }
    return { seq, byNumber };
  }

  function validate(ballot, groups, candidates) {
    const errors = [], warnings = [];
    const atl = clean(ballot.atl, Object.keys(groups), "Above the line", errors);
    const btl = clean(ballot.btl, candidates, "Below the line", errors);
    if (errors.length) return { formal: false, errors, warnings };
    const btlNeeded = Math.min(6, candidates.length);
    const atlAdvised = Math.min(6, Object.keys(groups).length);

    if (Object.keys(btl).length) {
      const { seq, byNumber } = sequence(btl);
      if (seq.length >= btlNeeded) {
        if (seq.length < Object.keys(btl).length)
          warnings.push(`Below the line: counting stops after preference ${seq.length} because of a missing or repeated number`);
        if (Object.keys(atl).length) warnings.push("Both sections completed - your below-the-line vote is used");
        return { formal: true, used: "btl", order: seq, errors, warnings };
      }
      let msg = `Below the line: number at least 1 to ${btlNeeded} with no repeats or gaps`;
      const dupes = Object.keys(byNumber).map(Number).filter(n => byNumber[n].length > 1 && n <= btlNeeded);
      if (dupes.length) msg += ` (number ${Math.min(...dupes)} is used more than once)`;
      if (!Object.keys(atl).length) return { formal: false, errors: [msg], warnings };
      warnings.push(msg + " - falling back to your above-the-line vote");
    }
    if (Object.keys(atl).length) {
      const { seq, byNumber } = sequence(atl);
      if (!seq.length) {
        const reason = (byNumber[1] || []).length > 1 ? "the number 1 appears in more than one box" : "there is no number 1";
        return { formal: false, errors: [`Above the line: informal because ${reason}`], warnings };
      }
      if (seq.length < Object.keys(atl).length)
        warnings.push(`Above the line: counting stops after preference ${seq.length} because of a missing or repeated number`);
      if (seq.length < atlAdvised)
        warnings.push(`Above the line: you numbered ${seq.length} box(es); the instructions ask for at least ${atlAdvised}. Your vote is still formal.`);
      return { formal: true, used: "atl", order: seq.flatMap(g => groups[g]), errors, warnings };
    }
    return { formal: false, errors: ["The ballot is blank"], warnings };
  }

  return { validate };
})();
