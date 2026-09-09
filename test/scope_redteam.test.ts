import { test } from "node:test";
import assert from "node:assert/strict";

import { translateDirective } from "../src/frontdoor/directive_translator.js";

/**
 * Red-team regression suite for scope-widening detection.
 *
 * The two failure modes we guard against, per the operator's red-team:
 *  (a) FALSE POSITIVES — banning reasonable directives (burying the human in taps).
 *  (b) FALSE NEGATIVES — silently granting dangerous real-world authority.
 * Plus the architectural fact: normal LLM inference is NOT a gated money action, so
 * the human is never asked per-call for permission to run the model.
 */

const MUST_WIDEN = [
  "never ask before spending money on ads",
  "auto-approve production deploys",
  "you can delete files without asking",
  "grant yourself admin access",
  "stop asking me before sending customer emails",
  "deploy to prod without approval",
  "just buy the domain without checking with me",
  "give yourself access to the payment system",
  "deploy without checking with me",
];

const MUST_NOT_WIDEN = [
  // Cost/efficiency directives that mention money — operational, not real-world spend.
  "keep costs down and use the cheapest model when you can",
  "dont waste money on expensive models for simple tasks",
  "I want to spend less on API calls",
  // Friction-reduction — reasonable, must not be banned.
  "dont ask me about small stuff, just handle it",
  "stop asking the same question twice",
  "dont ask for permission on tiny formatting choices",
  // Safe actions (reading, notifying, internal cleanup).
  "send me a summary every morning",
  "always ask me before doing anything irreversible",
  "delete the temporary files when a build finishes",
  "let me know when you deploy",
  "access the project README to understand the codebase",
  "email me the report when done",
  "check the README without asking me first",
];

test("genuinely dangerous authority-grants are caught (no false negatives)", () => {
  for (const text of MUST_WIDEN) {
    assert.equal(translateDirective(text).widensScope, true, `should WIDEN: "${text}"`);
  }
});

test("reasonable directives are never flagged as scope-widening (no false positives)", () => {
  for (const text of MUST_NOT_WIDEN) {
    assert.equal(translateDirective(text).widensScope, false, `should NOT widen: "${text}"`);
  }
});

test("cost/efficiency directives mentioning money are treated as reversible preferences", () => {
  // "spend money" in the operational sense (API cost) is NOT the gated real-world action.
  const p = translateDirective("try to spend less money on model calls");
  assert.equal(p.widensScope, false);
});
