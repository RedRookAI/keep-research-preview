/**
 * HOST CAPABILITY PROBE (register row H-8 — "host capability probe", finally built).
 *
 * WHY THIS EXISTS. Keep's enforcement is a CAPABILITY-TIERED LADDER: it must serve a laptop (no KVM, no TPM) AND a
 * confidential-compute host (KVM + seccomp + TEE), so the STRONGEST enforcement AVAILABLE ON THIS HOST must be selected
 * at boot — MEASURED, never assumed. A "seam" (a guarantee Keep cannot provide here) is legitimate ONLY for a
 * capability this probe reports genuinely ABSENT; declaring a seam for a capability the host actually HAS is scope
 * reduction, not honesty. This module is the single source of that measurement — dogfooded: the exact same probe backs
 * the build loop's "PROBE BEFORE YOU SEAM" discipline and the product's runtime tier selection.
 *
 * The probe is READ-ONLY and side-effect-free (it inspects /dev, /proc, /sys, `which`, and one throwaway `unshare`
 * self-test that runs `true`), bounded in time, and fail-SAFE: a capability it cannot measure is "unknown" (recorded
 * with its evidence), never silently "present". Tier selection treats "unknown" conservatively (as not-available for
 * tiering up) so an unmeasured host degrades to a weaker tier LOUDLY rather than over-claiming.
 */

import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { eirDigest, type CanonicalValue } from "../eir/canonical.js";

export type CapabilityStatus = "present" | "absent" | "unknown";
export interface Capability {
  readonly name: string;
  readonly status: CapabilityStatus;
  /** Human-readable evidence for the status (the on-disk marker checked, the command run, or the error). */
  readonly evidence: string;
  /** The stronger mechanism this capability unlocks (for enforcement composition / the seam register). */
  readonly unlocks?: string;
  /** True when `status:"absent"` but the capability can be PROVISIONED here (e.g. a hypervisor/swtpm via apt or a
   *  release binary). Installable ≠ seam: it is buildable work (install then wire), NOT a limitation to seam around. */
  readonly installable?: boolean;
}

/**
 * A NON-GATING, monotone human summary of composed enforcement strength: 0 = pure-TS floor (every host); 1 = OS-kernel
 * isolation available; 2 = hardware root of trust available. IMPORTANT (operator directive): the tier is a REPORTING
 * LABEL only — it MUST NOT be consulted to DISABLE a mechanism. Enforcement is COMPOSED PER-CAPABILITY: Keep activates
 * every mechanism whose specific capability is present (namespaces→jailed process, seccomp→syscall belt, landlock→fs
 * sandbox, kvm→microVM, cgroups→resource caps, tpm/tee→sealed keys, ed25519→non-repudiable signing, …), so an odd
 * capability mix (e.g. KVM+Landlock but no seccomp) still uses everything it has and nothing available is wasted. The
 * tier is derived FROM that composition; it never bounds it.
 */
export type EnforcementTier = 0 | 1 | 2;

export interface CapabilityReport {
  readonly capabilities: Readonly<Record<string, Capability>>;
  readonly tier: EnforcementTier;
  readonly tierReason: string;
  /** Content-addressed fingerprint of the {name: status} profile (evidence prose excluded — host-path-independent). */
  readonly profileDigest: string;
}

const SPAWN = { timeout: 4000, encoding: "utf8" as const };
function tryRead(path: string): string | undefined { try { return readFileSync(path, "utf8"); } catch { return undefined; } }
function which(cmd: string): string | undefined {
  try { const r = spawnSync("sh", ["-c", `command -v ${cmd} 2>/dev/null`], SPAWN); const out = (r.stdout || "").trim(); return out.length > 0 ? out : undefined; } catch { return undefined; }
}
function cap(name: string, status: CapabilityStatus, evidence: string, unlocks?: string, installable?: boolean): Capability {
  return { name, status, evidence, ...(unlocks !== undefined ? { unlocks } : {}), ...(installable ? { installable: true } : {}) };
}

// ---- individual probes (each fail-safe: probe error -> "unknown" with the error as evidence) ----

function probeKvm(): Capability {
  try { return existsSync("/dev/kvm") ? cap("kvm", "present", "/dev/kvm present", "hardware-virtualized microVM (Firecracker/QEMU) isolation — Tier 1") : cap("kvm", "absent", "/dev/kvm not present"); }
  catch (e) { return cap("kvm", "unknown", `probe error: ${errText(e)}`); }
}
function probeCpuVirt(): Capability {
  const info = tryRead("/proc/cpuinfo");
  if (info === undefined) return cap("cpu-virt", "unknown", "/proc/cpuinfo unreadable");
  return /\b(vmx|svm)\b/.test(info) ? cap("cpu-virt", "present", "cpuinfo has vmx/svm") : cap("cpu-virt", "absent", "no vmx/svm in cpuinfo");
}
function probeSeccomp(): Capability {
  // kernel seccomp-bpf support: the filter action registry is exposed here when CONFIG_SECCOMP_FILTER is on.
  if (existsSync("/proc/sys/kernel/seccomp/actions_avail")) return cap("seccomp", "present", "/proc/sys/kernel/seccomp/actions_avail present", "syscall-filtering kernel egress/exec belt — Tier 1");
  const status = tryRead("/proc/self/status");
  if (status !== undefined && /Seccomp:/.test(status)) return cap("seccomp", "present", "/proc/self/status advertises Seccomp", "syscall-filtering belt — Tier 1");
  return cap("seccomp", "absent", "no seccomp actions_avail / status marker");
}
function probeLandlock(): Capability {
  const lsm = tryRead("/sys/kernel/security/lsm");
  if (lsm === undefined) return cap("landlock", "unknown", "/sys/kernel/security/lsm unreadable");
  return lsm.split(",").map((s) => s.trim()).includes("landlock") ? cap("landlock", "present", "landlock in active LSM list", "unprivileged filesystem-access sandboxing — Tier 1") : cap("landlock", "absent", `landlock not in LSM list (${lsm.trim()})`);
}
function probeNamespaces(): Capability {
  // self-test: create user+mount+pid namespaces and run `true`. Side-effect-free (the child exits immediately).
  try {
    const r = spawnSync("unshare", ["--user", "--map-root-user", "--mount", "--pid", "--fork", "true"], SPAWN);
    if (r.status === 0) return cap("namespaces", "present", "unshare user+mount+pid succeeded", "separate-process/separate-namespace witness + jailed executor — Tier 1");
    if (r.error) return cap("namespaces", spawnMissing(r.error) ? "absent" : "unknown", `unshare failed: ${errText(r.error)}`);
    return cap("namespaces", "absent", `unshare exited ${r.status}: ${(r.stderr || "").trim().slice(0, 120)}`);
  } catch (e) { return cap("namespaces", "unknown", `probe error: ${errText(e)}`); }
}
function probeCgroupsV2(): Capability {
  return existsSync("/sys/fs/cgroup/cgroup.controllers") ? cap("cgroups-v2", "present", "/sys/fs/cgroup/cgroup.controllers present", "memory/CPU resource caps on isolated executors — Tier 1") : cap("cgroups-v2", "absent", "no cgroup.controllers (not unified/v2)");
}
function probeContainerRuntime(): Capability {
  const found = ["runc", "crun", "docker", "podman"].filter((c) => which(c) !== undefined);
  return found.length > 0 ? cap("container-runtime", "present", `found: ${found.join(", ")}`, "OCI-container jailed execution + repo-materializing sandboxed runner") : cap("container-runtime", "absent", "no runc/crun/docker/podman on PATH");
}
function probeHypervisor(): Capability {
  const found = ["firecracker", "qemu-system-x86_64", "cloud-hypervisor"].filter((c) => which(c) !== undefined);
  if (found.length > 0) return cap("hypervisor", "present", `found: ${found.join(", ")}`, "microVM hermetic replay + isolation");
  // absent but INSTALLABLE (apt / firecracker release) → buildable work, NOT a seam. Only meaningful with KVM present.
  const installable = which("apt-get") !== undefined || which("curl") !== undefined || which("wget") !== undefined;
  return cap("hypervisor", "absent", installable ? "no hypervisor on PATH — INSTALLABLE (apt-get / firecracker release binary)" : "no hypervisor on PATH and no installer", "microVM hermetic replay + isolation", installable);
}
function probeTpm(): Capability {
  if (existsSync("/dev/tpm0") || existsSync("/dev/tpmrm0")) return cap("tpm", "present", "/dev/tpm* present", "hardware-sealed key custody + measured boot — Tier 2");
  return cap("tpm", "absent", "no /dev/tpm* (software swtpm installable for integration)");
}
function probeConfidentialCompute(): Capability {
  if (existsSync("/dev/sev-guest") || existsSync("/dev/tdx_guest")) return cap("tee", "present", "/dev/sev-guest or /dev/tdx_guest present", "confidential-VM remote attestation — Tier 2");
  const info = tryRead("/proc/cpuinfo");
  if (info !== undefined && /\b(sev_snp|tdx)\b/.test(info)) return cap("tee", "present", "cpuinfo advertises sev_snp/tdx", "confidential-VM remote attestation — Tier 2");
  return cap("tee", "absent", "no SEV-SNP/TDX guest device or cpuinfo flag");
}
function probeGpu(): Capability {
  if (existsSync("/dev/nvidia0") || which("nvidia-smi") !== undefined) return cap("gpu", "present", "nvidia device/smi present", "on-host LoRA training / synthesis");
  return cap("gpu", "absent", "no nvidia device or nvidia-smi");
}
function probeAsymmetricCrypto(): Capability {
  // ed25519 signing is what upgrades keyed-HMAC (stubSign, shared-secret) to NON-REPUDIABLE signatures — NO hardware
  // needed, only a keypair. This is `present` on any modern Node; it is the reason C-1/C-2/C-3 were mis-seam'd.
  try {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const sig = edSign(null, Buffer.from("keep-capability-probe"), privateKey);
    const ok = edVerify(null, Buffer.from("keep-capability-probe"), publicKey, sig);
    return ok ? cap("asymmetric-signing", "present", "node:crypto ed25519 sign/verify OK", "non-repudiable signatures (replaces shared-secret stubSign) — Tier 0, every host") : cap("asymmetric-signing", "absent", "ed25519 verify returned false");
  } catch (e) { return cap("asymmetric-signing", "unknown", `probe error: ${errText(e)}`); }
}
function probePackageInstall(): Capability {
  const found = ["apt-get", "dnf", "yum", "apk"].filter((c) => which(c) !== undefined);
  return found.length > 0 ? cap("package-install", "present", `found: ${found.join(", ")}`, "install missing substrate (firecracker/swtpm/bubblewrap)") : cap("package-install", "absent", "no package manager on PATH");
}

function errText(e: unknown): string { try { return String((e as { message?: unknown })?.message ?? e).slice(0, 160); } catch { return "unknown"; } }
function spawnMissing(e: unknown): boolean { return (e as { code?: string } | null)?.code === "ENOENT"; }

/**
 * Probe the host and select the strongest ENFORCEMENT TIER it can back — MEASURED, not assumed. Tier 2 needs a hardware
 * root of trust (TPM/TEE); Tier 1 needs kernel isolation (namespaces + seccomp); Tier 0 (pure-TS + ed25519 signing) is
 * always available. "unknown" capabilities do NOT lift the tier (conservative degrade), but are recorded so the gap is
 * visible and can be re-probed rather than silently seam'd.
 */
export function probeCapabilities(): CapabilityReport {
  const list = [
    probeAsymmetricCrypto(), probeKvm(), probeCpuVirt(), probeSeccomp(), probeLandlock(), probeNamespaces(),
    probeCgroupsV2(), probeContainerRuntime(), probeHypervisor(), probeTpm(), probeConfidentialCompute(), probeGpu(),
    probePackageInstall(),
  ];
  const capabilities: Record<string, Capability> = {};
  for (const c of list) capabilities[c.name] = c;
  const { tier, tierReason } = selectTier(capabilities);
  return { capabilities: Object.freeze(capabilities), tier, tierReason, profileDigest: profileDigestOf(capabilities) };
}

/** PURE tier selection over a measured capability map — Tier 2 needs a hardware root of trust; Tier 1 needs kernel
 *  isolation (namespaces+seccomp); Tier 0 (pure-TS + ed25519) is always the floor. Only "present" lifts the tier —
 *  "unknown"/"absent" degrade conservatively (LOUD weak tier, never a silent over-claim). */
export function selectTier(capabilities: Readonly<Record<string, Capability>>): { tier: EnforcementTier; tierReason: string } {
  const has = (n: string) => capabilities[n]?.status === "present";
  if (has("tpm") || has("tee")) return { tier: 2, tierReason: "hardware root of trust present (TPM/TEE) → Tier 2 (hardware-sealed keys + attestation)" };
  if (has("namespaces") && has("seccomp")) return { tier: 1, tierReason: `kernel isolation present (namespaces+seccomp${has("kvm") ? "+KVM" : ""}) → Tier 1 (OS-isolated executor/witness${has("kvm") ? " + microVM" : ""})` };
  return { tier: 0, tierReason: "no measured kernel isolation → Tier 0 (pure-TS in-process + ed25519 signing floor)" };
}

/** Content-address ONLY the {name→status} profile (evidence prose excluded, so the digest is host-path-independent). */
export function profileDigestOf(capabilities: Readonly<Record<string, Capability>>): string {
  const profile: CanonicalValue = { profile: Object.keys(capabilities).sort().map((k) => ({ name: k, status: capabilities[k]!.status })) };
  return eirDigest("keep.platform.capabilities/v1", profile);
}

let CACHED: CapabilityReport | undefined;
/** Memoized probe — host capabilities do not change during a process, so probe at most once (compose calls this at
 *  boot instead of re-spawning `unshare`/`which` per instance). */
export function cachedCapabilities(): CapabilityReport { return (CACHED ??= probeCapabilities()); }
