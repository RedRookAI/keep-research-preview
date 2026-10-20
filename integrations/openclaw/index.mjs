import { definePluginEntry, buildJsonPluginConfigSchema } from "openclaw/plugin-sdk/plugin-entry";
import { captureScope, configSchema, emptyInput, goalInput, parseConfig } from "./contracts.mjs";
import { heldResult, useKeep } from "./client.mjs";

const tools = [
  { name: "keep_submit", label: "Submit work to Keep", operation: "submit",
    description: "Submit one repository goal to the configured Keep instance. Keep requires separate human generation/proposal decisions. If earlier work is unresolved, recover or report that work instead of starting another goal.",
    parameters: { type: "object", additionalProperties: false, required: ["goal"], properties: { goal: { type: "string", minLength: 1, maxLength: 921600, description: "The requested repository outcome. No endpoint, credentials, identity, source path, command or approval options." } } },
  },
  { name: "keep_status", label: "Inspect Keep work", operation: "status",
    description: "Inspect this conversation's saved Keep submission. A lost acknowledgement is recovered with the original request/key. Never starts a new goal or approves work. Cancellation does not prove remote work stopped.",
    parameters: { type: "object", additionalProperties: false, properties: {} },
  },
];
function summary(result) {
  if (!result.status) return `Keep: ${result.state}. ${result.nextAction}`;
  const status = result.status, checks = status.proposal.checks;
  const tests = checks?.testsPassed === true ? "passed" : checks?.testsPassed === false ? "failed" : "not reported";
  return [`Keep job ${status.jobId}: ${status.job.state}.`,
    `Project ${status.projectId}: ${status.run ? `${status.run.stage} / ${status.run.status}` : "no run checkpoint yet"}.`,
    `Repository tests: ${tests}. Proposal: ${status.proposal.available ? status.proposal.digest : "not recorded"}.`,
    `Source delivery: ${status.delivery.source}. Owner veto: ${status.review.vetoed ? "recorded" : "not recorded"}.`,
    status.run?.wait?.reason ?? status.job.reason ?? "", result.nextAction,
  ].filter(Boolean).join("\n");
}

export default definePluginEntry({
  id: "keep", name: "Keep", description: "Repository work through Keep's restricted submission and review workflow.",
  configSchema: buildJsonPluginConfigSchema(configSchema),
  register(api) {
    const config = parseConfig(api.pluginConfig ?? {});
    api.registerTool({ contextVersion: 2, create(context) {
      // Catalog availability is separate from the live final-effect check below.
      if (context.senderIsOwner !== true || context.agentId !== config.openclawAgentId || typeof context.assertInvocationCurrent !== "function"
        || typeof context.sessionId !== "string" || typeof context.sessionKey !== "string") return null;
      return tools.map(tool => ({ name: tool.name, label: tool.label, description: tool.description, parameters: tool.parameters,
        async execute(toolCallId, params, signal) {
          let result;
          try {
            const scope = captureScope(config, context, toolCallId, signal);
            const goal = tool.operation === "submit" ? goalInput(params) : (emptyInput(params), undefined);
            result = await useKeep(config, scope, tool.operation, goal, signal);
            scope.assertCurrent();
          } catch (error) { result = heldResult(error); }
          return { content: [{ type: "text", text: summary(result) }], details: result, ...(result.state === "held" ? { isError: true } : {}) };
        },
      }));
    } }, { names: ["keep_submit", "keep_status"], optional: true });
  },
});
