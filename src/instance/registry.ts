/**
 * Theme 1 (Instance Isolation), Part 3 — Instance registry + runfile (discovery).
 *
 * When instances pick ephemeral ports/sockets, other tools must discover where each one
 * is — "you invent some signaling" (the documented ephemeral-port discovery gap). The
 * runfile IS that signaling channel: each instance atomically writes its bind info to
 * <home>/runtime.json, so the dashboard/CLI reads the real target instead of guessing.
 *
 * The registry is the fleet catalog: <base>/registry.json tracks every instance so N
 * projects on one Hetzner box coexist and are discoverable, and starting a new
 * top-level project just mints a fresh id. Updates prune dead entries (PID liveness)
 * and are written atomically (temp-then-rename) to survive concurrent writers.
 * Zero deps.
 */

import fs from "node:fs";
import path from "node:path";
import { keepBaseDir } from "./instance_home.js";
import type { BoundListener } from "./bind_strategy.js";

export interface RunInfo {
  readonly kind: BoundListener["kind"];
  readonly port?: number;
  readonly host?: string;
  readonly socketPath?: string;
  readonly pid: number;
  readonly startedAt: number;
}

export interface RegistryEntry {
  readonly id: string;
  readonly home: string;
  readonly projectName?: string;
  readonly run: RunInfo;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

function atomicWrite(filePath: string, data: unknown): void {
  const tmp = `${filePath}.tmp.${process.pid}.${Date.now()}`;
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { encoding: "utf8", mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

/** Write this instance's runfile so other tools can find its bind target. */
export function writeRunfile(home: string, bound: BoundListener, now = Date.now()): RunInfo {
  const run: RunInfo = {
    kind: bound.kind,
    ...(bound.port !== undefined ? { port: bound.port } : {}),
    ...(bound.host !== undefined ? { host: bound.host } : {}),
    ...(bound.socketPath !== undefined ? { socketPath: bound.socketPath } : {}),
    pid: process.pid,
    startedAt: now,
  };
  atomicWrite(path.join(home, "runtime.json"), run);
  return run;
}

/** Read an instance's runfile (how a client discovers where to connect). */
export function readRunfile(home: string): RunInfo | null {
  try {
    return JSON.parse(fs.readFileSync(path.join(home, "runtime.json"), "utf8")) as RunInfo;
  } catch {
    return null;
  }
}

function registryPath(baseDirOverride?: string): string {
  return path.join(keepBaseDir(baseDirOverride), "registry.json");
}

function readRegistry(baseDirOverride?: string): RegistryEntry[] {
  try {
    return JSON.parse(fs.readFileSync(registryPath(baseDirOverride), "utf8")) as RegistryEntry[];
  } catch {
    return [];
  }
}

/**
 * Register (or update) this instance in the fleet catalog, pruning any dead entries.
 * Last-write-wins on the id; atomic write survives concurrent updates.
 */
export function registerInstance(entry: RegistryEntry, baseDirOverride?: string): RegistryEntry[] {
  const current = readRegistry(baseDirOverride);
  const live = current.filter((e) => e.id !== entry.id && pidAlive(e.run.pid));
  const next = [...live, entry];
  atomicWrite(registryPath(baseDirOverride), next);
  return next;
}

/** Remove this instance from the catalog (on clean shutdown). */
export function deregisterInstance(id: string, baseDirOverride?: string): void {
  const current = readRegistry(baseDirOverride);
  const next = current.filter((e) => e.id !== id);
  atomicWrite(registryPath(baseDirOverride), next);
}

/** List all LIVE instances (dead ones pruned) — the "what projects are running" view. */
export function listInstances(baseDirOverride?: string): RegistryEntry[] {
  const current = readRegistry(baseDirOverride);
  const live = current.filter((e) => pidAlive(e.run.pid));
  if (live.length !== current.length) atomicWrite(registryPath(baseDirOverride), live); // prune
  return live;
}

/** Mint a fresh, collision-resistant instance id for a new top-level project. */
export function mintInstanceId(projectName?: string): string {
  const slug = (projectName ?? "keep").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 24) || "keep";
  const rand = Math.random().toString(36).slice(2, 8);
  return `${slug}-${rand}`;
}
