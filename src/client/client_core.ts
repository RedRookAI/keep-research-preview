export interface ClientTransportRequest { readonly method: "GET" | "POST"; readonly url: string; readonly headers: Readonly<Record<string, string>>; readonly body?: string; }
export interface ClientTransportResponse { readonly status: number; readonly body: string; }
export type ClientTransport = (request: ClientTransportRequest) => Promise<ClientTransportResponse>;
export interface KeepClientOptions { readonly origin: string; readonly token: string; readonly transport: ClientTransport; }
export interface ProjectSummary { readonly id: string; readonly name: string; readonly lifecycle: string; }
export interface ProjectList { readonly projects: readonly ProjectSummary[]; readonly active: string | null; }
export interface ReviewList { readonly reviews: readonly unknown[]; }
export interface ProjectRunResult { readonly runId?: string; readonly projectId?: string; readonly revision?: number; readonly proposalDigest?: string; readonly status: string; readonly note: string | null; }

/** details is untrusted parsed gateway data, not a successful result or replay authority. */
export class KeepClientError extends Error { constructor(readonly status: number, message: string, readonly details?: unknown) { super(message); this.name = "KeepClientError"; } }

export function normalizeGatewayOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("gateway origin must use http or https");
  if (url.protocol === "http:" && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) throw new Error("plaintext gateway origins must be loopback");
  if (url.username || url.password) throw new Error("gateway credentials must not be embedded in the URL");
  if (url.pathname !== "/" || url.search || url.hash) throw new Error("gateway origin must not contain a path, query, or fragment");
  return url.origin;
}

export class KeepClient {
  readonly #origin: string; readonly #token: string; readonly #transport: ClientTransport;
  constructor(options: KeepClientOptions) { this.#origin = normalizeGatewayOrigin(options.origin); if (options.token.trim() === "") throw new Error("gateway token is required"); this.#token = options.token; this.#transport = options.transport; }
  health(): Promise<{ readonly ok: boolean }> { return this.#request("GET", "/health", false); }
  projects(): Promise<ProjectList> { return this.#request("GET", "/projects"); }
  project(runId: string): Promise<unknown> { return this.#request("GET", `/project?runId=${encodeURIComponent(runId)}`); }
  reviews(): Promise<ReviewList> { return this.#request("GET", "/reviews"); }
  decision(id: string): Promise<{ readonly view: unknown }> { return this.#request("GET", `/decision?id=${encodeURIComponent(id)}`); }
  message(message: string): Promise<{ readonly result: unknown }> { return this.#request("POST", "/message", true, { message }); }
  startProject(goal: string): Promise<ProjectRunResult> { return this.#request("POST", "/project", true, { goal }); }
  /** A positive safe-integer top-up is a fresh grant, not an idempotent retry. */
  resumeProject(runId: string, addSteps?: number): Promise<ProjectRunResult> { return this.#request("POST", "/project/resume", true, { runId, ...(addSteps === undefined ? {} : { addSteps }) }); }
  projectTurn(runId: string, goal: string, stepBudget?: number): Promise<ProjectRunResult> { return this.#request("POST", "/project/turn", true, { runId, goal, ...(stepBudget === undefined ? {} : { stepBudget }) }); }
  /** Select within the project's tenant; no execution/compaction. projects().active uses the caller's scope (personal for a local owner). */
  switchProject(projectId: string): Promise<unknown> { return this.#request("POST", "/project/switch", true, { projectId }); }
  /** Park the selection; does not enqueue, cancel, or grant a run more authority or budget. */
  backgroundProject(projectId: string): Promise<unknown> { return this.#request("POST", "/project/background", true, { projectId }); }
  backgroundTurn(projectId: string, goal: string, stepBudget: number): Promise<ProjectRunResult> { return this.#request("POST", "/project/background/turn", true, { projectId, goal, stepBudget }); }
  /** Lists visible tracked jobs (including foreground jobs), optionally for one project. */
  backgroundJobs(projectId?: string): Promise<unknown> { return this.#request("GET", `/project/jobs${projectId === undefined ? "" : `?projectId=${encodeURIComponent(projectId)}`}`); }
  archiveProject(projectId: string): Promise<unknown> { return this.#request("POST", "/project/archive", true, { projectId }); }
  deleteProject(projectId: string, confirmProjectId: string): Promise<unknown> { return this.#request("POST", "/project/delete", true, { projectId, confirmProjectId }); }
  /** Names the exact durable proposal; never substitutes a newer digest or proves human review. */
  mergeProject(runId: string, decision: "approve" | "veto", proposalDigest: string): Promise<unknown> { return this.#request("POST", "/project/merge", true, { runId, decision, proposalDigest }); }
  revertProject(runId: string): Promise<unknown> { return this.#request("POST", "/project/revert", true, { runId }); }
  approve(id: string): Promise<{ readonly ok: boolean; readonly runnable: boolean }> { return this.#request("POST", "/veto/approve", true, { id }); }
  decline(id: string): Promise<{ readonly ok: boolean }> { return this.#request("POST", "/veto/decline", true, { id }); }
  async #request<T>(method: "GET" | "POST", path: string, authenticated = true, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json" }; if (authenticated) headers["authorization"] = `Bearer ${this.#token}`; if (body !== undefined) headers["content-type"] = "application/json";
    const response = await this.#transport({ method, url: `${this.#origin}${path}`, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    let payload: unknown; try { payload = JSON.parse(response.body); } catch { throw new KeepClientError(response.status, "gateway returned invalid JSON"); }
    if (response.status < 200 || response.status >= 300) { const detail = typeof payload === "object" && payload !== null && "error" in payload ? String((payload as { error: unknown }).error) : `gateway request failed (${response.status})`; throw new KeepClientError(response.status, detail, payload); }
    return payload as T;
  }
}

export type ClientShellPlatform = "desktop" | "ios" | "android";
export interface PlatformCredentialStore { readonly kind: "platform-secure-store"; read(key: "keep.gateway.token"): Promise<string | null>; }
export interface ConnectClientShellOptions { readonly platform: ClientShellPlatform; readonly origin: string; readonly transport: ClientTransport; readonly credentialStore?: PlatformCredentialStore; }
export async function connectClientShell(options: ConnectClientShellOptions): Promise<KeepClient> { if (!options.credentialStore || options.credentialStore.kind !== "platform-secure-store") throw new Error(`${options.platform} shell requires platform secure credential storage`); const token = await options.credentialStore.read("keep.gateway.token"); if (!token || token.trim() === "") throw new Error("gateway token is missing from platform secure credential storage"); return new KeepClient({ origin: options.origin, token, transport: options.transport }); }

export interface ClientShellDescriptor { readonly platform: ClientShellPlatform; readonly mode: "development-unsigned"; readonly clientModule: "keep/client-core"; readonly gatewayTransport: "injected-http"; readonly credentialStorage: "platform-secure-store-required"; readonly signing: "not-configured"; readonly distribution: "private-development-only"; }
export function prepareClientShell(platform: ClientShellPlatform): ClientShellDescriptor { return Object.freeze({ platform, mode: "development-unsigned", clientModule: "keep/client-core", gatewayTransport: "injected-http", credentialStorage: "platform-secure-store-required", signing: "not-configured", distribution: "private-development-only" }); }
