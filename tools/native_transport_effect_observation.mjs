#!/usr/bin/env node
/** Runtime syscall observation for the refusal-only A6 client/supervisor pair. */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { homedir, tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const nativeRoot = join(root, "native");
const lock = JSON.parse(readFileSync(join(nativeRoot, "toolchain-lock.json"), "utf8"));
const rustupHome = process.env.RUSTUP_HOME ?? join(homedir(), ".rustup");
const toolchainRoot = realpathSync(
  process.env.KEEP_P1_TOOLCHAIN_ROOT ?? join(rustupHome, "toolchains", lock.toolchain),
);
const cargo = join(toolchainRoot, "bin/cargo");
const rustLld = join(toolchainRoot, "lib/rustlib", lock.host, "bin/rust-lld");
const traceRoot = mkdtempSync(join(tmpdir(), "keep-native-effects-"));
const tracePrefix = join(traceRoot, "trace");

try {
  execFileSync(
    "/usr/bin/strace",
    [
      "-ff", "-qq", "-s", "4096", "-o", tracePrefix,
      cargo, "test", "-p", "keep-native-transport", "--offline",
      "separate_binaries_exchange", "--", "--nocapture",
    ],
    {
      cwd: nativeRoot,
      stdio: ["ignore", "ignore", "inherit"],
      env: {
        PATH: `${join(toolchainRoot, "bin")}:${dirname(rustLld)}:/usr/bin:/bin`,
        LANG: "C",
        LC_ALL: "C",
        RUSTUP_HOME: rustupHome,
        RUSTUP_TOOLCHAIN: lock.toolchain,
        RUST_TEST_THREADS: "1",
      },
    },
  );

  const traces = readdirSync(traceRoot)
    .filter((name) => name.startsWith("trace."))
    .map((name) => ({ name, text: readFileSync(join(traceRoot, name), "utf8") }));
  const peers = new Map();
  for (const trace of traces) {
    const match = trace.text.match(/^execve\("[^"]*\/(keep-native-(?:client|supervisor))"/m);
    if (match) {
      if (peers.has(match[1])) throw new Error(`duplicate traced ${match[1]} process`);
      peers.set(match[1], trace);
    }
  }
  if (peers.size !== 2) throw new Error("did not isolate exactly the native client and supervisor traces");

  const forbiddenSyscalls = new Set([
    "clone", "clone3", "fork", "vfork", "execveat", "setuid", "setgid", "setreuid",
    "setregid", "setresuid", "setresgid", "setgroups", "capset", "mount", "umount",
    "umount2", "pivot_root", "chroot", "unshare", "setns", "ptrace", "bpf",
    "io_uring_setup", "kexec_load", "reboot",
  ]);
  const result = {};
  for (const [peer, trace] of peers) {
    const lines = trace.text.trim().split("\n");
    const syscalls = [...new Set(lines.map((line) => line.match(/^([a-zA-Z0-9_]+)\(/)?.[1]).filter(Boolean))].sort();
    const postStartExec = lines.filter((line) => line.startsWith("execve(")).slice(1);
    if (postStartExec.length) throw new Error(`${peer} executed another program`);
    const forbidden = syscalls.filter((name) => forbiddenSyscalls.has(name));
    if (forbidden.length) throw new Error(`${peer} performed forbidden syscalls: ${forbidden.join(", ")}`);
    const sockets = lines.filter((line) => line.startsWith("socket("));
    if (sockets.length !== 1 || !sockets[0].startsWith("socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC"))
      throw new Error(`${peer} opened a socket outside the one AF_UNIX seqpacket channel`);
    const authorityLines = lines.filter((line) => /^(?:socket|connect|open|openat|openat2|execve)\(/.test(line));
    if (authorityLines.some((line) => /AF_(?:INET|INET6|NETLINK|PACKET)|\/dev\/kvm|firecracker|credential|secret/i.test(line)))
      throw new Error(`${peer} trace contains a forbidden authority path or socket family`);
    result[peer] = { trace: trace.name, syscalls, sockets };
  }
  process.stdout.write(`${JSON.stringify({ schema: "keep.native-transport-effect-observation/v1", peers: result }, null, 2)}\n`);
} finally {
  rmSync(traceRoot, { recursive: true, force: true });
}
