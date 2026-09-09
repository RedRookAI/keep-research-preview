// Minimal MCP-style server over stdio (line-delimited JSON-RPC 2.0) for tests.
import { createInterface } from "node:readline";

const rl = createInterface({ input: process.stdin });
const send = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");

rl.on("line", (line) => {
  line = line.trim();
  if (!line) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const { id, method, params } = msg;
  if (method === "initialize") {
    send({ jsonrpc: "2.0", id, result: { protocolVersion: "2026-07-28", serverInfo: { name: "mock" } } });
  } else if (method === "tools/list") {
    send({ jsonrpc: "2.0", id, result: { tools: [
      { name: "echo", description: "Return the supplied arguments." },
      { name: "add", description: "Add two numeric arguments." },
    ] } });
  } else if (method === "tools/call") {
    const { name, arguments: args } = params;
    if (name === "echo") send({ jsonrpc: "2.0", id, result: { content: args } });
    else if (name === "add") send({ jsonrpc: "2.0", id, result: { content: (args.a ?? 0) + (args.b ?? 0) } });
    else send({ jsonrpc: "2.0", id, error: { code: -32601, message: `no tool ${name}` } });
  } else {
    send({ jsonrpc: "2.0", id, error: { code: -32601, message: `no method ${method}` } });
  }
});
