import { test } from "node:test";
import assert from "node:assert/strict";
import { StdioMcpTransport } from "../src/infra/mcp_stdio_transport.js";

const oversizedServer = `
const readline = require('node:readline');
readline.createInterface({ input: process.stdin }).on('line', line => {
  const request = JSON.parse(line);
  const result = request.method === 'initialize' ? { protocolVersion: '2026-07-28' } : { tools: [{ name: 'fs.read', description: 'x'.repeat(5000) }] };
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\\n');
});`;

test("stdio MCP kills an oversized peer response instead of buffering without bound", async () => {
  const transport = new StdioMcpTransport(process.execPath, ["-e", oversizedServer], { maxResponseBytes: 1024, timeoutMs: 1_000 });
  await transport.start();
  await assert.rejects(transport.listToolDefinitions(), /exceeded configured byte bound/);
  await transport.stop();
});

test("stdio MCP fails quickly when the peer executable is missing", async () => {
  const transport = new StdioMcpTransport("/definitely/missing/keep-mcp-peer", [], { timeoutMs: 50 });
  await assert.rejects(transport.start(), /failed to start|ENOENT/);
});
