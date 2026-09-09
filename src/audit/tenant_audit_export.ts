import type { Spine } from "../spine/spine.js";
import { canonicalize } from "../spine/event.js";

export interface TenantAuditExportRow {
  /** Tenant-local ordinal (or complete local ordinal in n=1); never exposes foreign event volume. */
  readonly sequence: number;
  readonly type: string;
  readonly actor: string;
  readonly payload: Readonly<Record<string, unknown>>;
}

const SAFE_TENANT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

/**
 * Read-only export of the canonical Spine. Enterprise exports contain only events explicitly bound
 * to the requesting tenant; missing/global and foreign tenant labels are excluded. An omitted tenant
 * is the local n=1 contract and exports the complete local chain plus durable pending suffix.
 */
export function exportTenantAudit(spine: Spine, tenant?: string, page?: { readonly after?: number; readonly limit?: number }): readonly TenantAuditExportRow[] {
  if (tenant !== undefined && !SAFE_TENANT.test(tenant)) throw new Error("audit export requires a safe tenant id");
  const after = page?.after ?? 0, limit = page?.limit ?? (page === undefined ? Number.MAX_SAFE_INTEGER : 100);
  if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1 || (page !== undefined && limit > 500)) throw new Error("audit export page is invalid");
  const rows: TenantAuditExportRow[] = [];
  let localSequence = 0;
  for (const event of spine.currentEvents()) {
    if (tenant !== undefined && event.payload["tenant"] !== tenant) continue;
    if (localSequence++ < after) continue;
    if (rows.length >= limit) break;
    let payload: Record<string, unknown>;
    try { payload = JSON.parse(canonicalize(event.payload)) as Record<string, unknown>; }
    catch { throw new Error("audit export encountered a non-canonical payload"); }
    rows.push(Object.freeze({ sequence: localSequence - 1, type: event.type, actor: event.actor, payload: deepFreeze(payload) }));
  }
  return Object.freeze(rows);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
