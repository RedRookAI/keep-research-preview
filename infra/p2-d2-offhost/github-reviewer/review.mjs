import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

const required = (name) => {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
};
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const hex64 = /^[0-9a-f]{64}$/u;
const counter = Number.parseInt(required("REVIEW_COUNTER"), 10);
const evidenceDigest = required("EVIDENCE_DIGEST");
const auditPlanDigest = required("AUDIT_PLAN_DIGEST");
const role = required("REVIEW_ROLE");
if (!Number.isSafeInteger(counter) || counter < 1 || !hex64.test(evidenceDigest) || !hex64.test(auditPlanDigest) ||
    !["advisory", "build-policy", "correctness", "license", "unsafe-contract"].includes(role))
  throw new Error("review dispatch fields are malformed");
const prompt = readFileSync(new URL("./review-prompt.txt", import.meta.url), "utf8");
const evidence = readFileSync(new URL("./review-evidence.txt", import.meta.url), "utf8");
if (digest(Buffer.from(evidence, "utf8")) !== evidenceDigest) throw new Error("evidence bytes disagree with dispatch digest");

const request = {
  model: "gpt-5.5-pro-2026-04-23",
  reasoning: { effort: "xhigh" },
  input: [{ role: "user", content: [{ type: "input_text", text: `${prompt}\n\nAUDIT PLAN DIGEST: ${auditPlanDigest}\nROLE: ${role}\nATTEMPT COUNTER: ${counter}\nEVIDENCE DIGEST: ${evidenceDigest}\n\n${evidence}` }] }],
  max_output_tokens: 64000,
  store: false,
};
const provider = await fetch("https://api.openai.com/v1/responses", {
  method: "POST", headers: { "authorization": `Bearer ${required("OPENAI_API_KEY")}`, "content-type": "application/json" },
  body: JSON.stringify(request),
});
const responseBytes = Buffer.from(await provider.arrayBuffer());
if (!provider.ok) throw new Error(`OpenAI response failed with ${provider.status}: ${responseBytes.toString("utf8").slice(0, 500)}`);
const response = JSON.parse(responseBytes.toString("utf8"));
if (response.model !== "gpt-5.5-pro-2026-04-23" || response.status !== "completed" || response.error !== null ||
    !Array.isArray(response.output) || response.output.length === 0 || response.usage === undefined)
  throw new Error("OpenAI response identity/completion/usage is incomplete");
const outputText = response.output.flatMap((item) => item.content ?? []).filter((item) => item.type === "output_text").map((item) => item.text).join("\n");
if (outputText.length === 0 || !/\bVERDICT:\s*(PASS|REVISE|BLOCK)\b/u.test(outputText))
  throw new Error("review response lacks a closed verdict");
const signed = {
  schema: "keep.p2-d2-offhost-review-result", version: 1, principal: "reviewer.github-openai",
  reviewerFamily: "openai", custodianFamily: "github-actions-sigstore", mechanism: "sigstore-keyless",
  evidenceDigest, auditPlanDigest, role, counter, promptDigest: digest(Buffer.from(prompt, "utf8")),
  responseDigest: digest(responseBytes), provider: "openai", model: response.model, requestId: response.id,
  usage: response.usage, outputText,
};
mkdirSync("artifact", { recursive: true });
writeFileSync("artifact/provider-response.json", responseBytes, { flag: "wx", mode: 0o400 });
writeFileSync("artifact/signed-preimage.json", `${JSON.stringify(signed)}\n`, { flag: "wx", mode: 0o400 });
