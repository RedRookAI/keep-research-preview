/** One attributable public price source. No prompts, credentials or configurable destinations. */
import { createHash } from "node:crypto";
import type { RemoteProviderDescriptor } from "../gateway/provider_descriptor.js";
import type { ReferencePricing } from "./reference_registry.js";

export const PROVIDER_CHECK_PRICE_URL = "https://api-docs.deepseek.com/quick_start/pricing/";
export const PROVIDER_CHECK_PRICE_HOST = "api-docs.deepseek.com";
export interface ProviderCheckPrice extends ReferencePricing {
  readonly source: typeof PROVIDER_CHECK_PRICE_URL;
  readonly sourceDigest: string;
  readonly verifiedAtMs: number;
  readonly receivedAtMs: number;
}
export function supportedPriceRoute(route: RemoteProviderDescriptor): boolean {
  return route.mode === "openai-compatible" && route.model === "deepseek-flash" &&
    ["https://api.deepseek.com", "https://api.deepseek.com/v1"].includes(route.baseUrl);
}
export function validPriceMaxAge(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}
export function priceIsFresh(price: ProviderCheckPrice | undefined, maxAgeMs: number, now = Date.now()): price is ProviderCheckPrice {
  return price !== undefined && validPriceMaxAge(maxAgeMs) && now >= price.receivedAtMs &&
    now >= price.verifiedAtMs && now - price.verifiedAtMs <= maxAgeMs;
}

/** Strict current English table schema; layout/model changes refuse instead of guessing columns. */
export function parseProviderCheckPrice(html: string): Pick<ProviderCheckPrice, "model" | "inputPerM" | "outputPerM"> {
  const tables = [...html.matchAll(/<table\b[^>]*>([\s\S]*?)<\/table>/giu)];
  if (tables.length !== 1) throw new Error("price-unverifiable: expected one pricing table");
  const rows = [...tables[0]![1]!.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/giu)].map(row =>
    [...row[1]!.matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/giu)].map(cell => cell[1]!
      .replace(/<sup\b[^>]*>[\s\S]*?<\/sup>/giu, "").replace(/<br\s*\/?\s*>/giu, " ")
      .replace(/<[^>]*>/gu, "").replace(/\s+/gu, " ").trim()));
  if (rows[0]?.join("|") !== "MODEL|deepseek-flash|deepseek-v4-pro" ||
      rows[1]?.join("|") !== "BASE URL (OpenAI Format)|https://api.deepseek.com") {
    throw new Error("price-unverifiable: model or endpoint table changed");
  }
  const start = rows.findIndex(row => row[0] === "PRICING");
  const pricing = rows.slice(start, start + 6);
  const labels = ["PRICING|1M INPUT TOKENS (CACHE HIT)|OFF-PEAK", "PEAK",
    "1M INPUT TOKENS (CACHE MISS)|OFF-PEAK", "PEAK", "1M OUTPUT TOKENS|OFF-PEAK", "PEAK"];
  const rates = pricing.map((row, index) => {
    if (row.slice(0, -2).join("|") !== labels[index] || row.length < 3 ||
        row.slice(-2).some(value => !/^\$(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(value))) {
      throw new Error("price-unverifiable: unsupported pricing schema");
    }
    const rate = Number(row[row.length - 2]!.slice(1));
    if (!Number.isFinite(rate) || rate < 0) throw new Error("price-unverifiable: invalid rate");
    return rate;
  });
  if (start < 0 || pricing.length !== 6 || rows[start + 6]?.[0] !== "Concurrency Limit" ||
      rates[1]! < rates[0]! || rates[3]! < rates[2]! || rates[5]! < rates[4]! ||
      rates[0]! > rates[2]! || rates[1]! > rates[3]! || rates[3]! <= 0 || rates[5]! <= 0) {
    throw new Error("price-unverifiable: incomplete or inconsistent tiers");
  }
  return { model: "deepseek-flash", inputPerM: rates[3]!, outputPerM: rates[5]! };
}

/** Conservative RFC 9111 age, including transfer/body time; missing dates cannot qualify freshness. */
export async function fetchProviderCheckPrice(fetcher: typeof fetch = globalThis.fetch): Promise<ProviderCheckPrice[]> {
  const started = Date.now();
  const response = await fetcher(PROVIDER_CHECK_PRICE_URL, {
    method: "GET", redirect: "error", credentials: "omit",
    headers: { accept: "text/html", "cache-control": "no-cache, no-store" }, signal: AbortSignal.timeout(5000),
  });
  const reader = response.body?.getReader();
  try {
    if (response.status !== 200 || response.redirected || response.url !== PROVIDER_CHECK_PRICE_URL ||
        !response.headers.get("content-type")?.toLowerCase().startsWith("text/html") || !reader) {
      throw new Error("price-unverifiable: unsupported source response");
    }
    const date = Date.parse(response.headers.get("date") ?? "");
    const age = response.headers.get("age") ?? "0";
    if (!Number.isFinite(date) || !/^\d+$/u.test(age) || !Number.isSafeInteger(Number(age))) {
      throw new Error("price-unverifiable: invalid source age");
    }
    const chunks: Uint8Array[] = []; let bytes = 0;
    for (;;) {
      const part = await reader.read(); if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > 524288) throw new Error("price-unverifiable: source exceeds size limit");
      chunks.push(part.value);
    }
    const received = Date.now(), body = Buffer.concat(chunks);
    if (received < started || date > received || !Number.isSafeInteger(Number(age) * 1000)) {
      throw new Error("price-unverifiable: source clock invalid");
    }
    const initialAge = Math.max(received - date, Number(age) * 1000 + received - started);
    return [Object.freeze({ ...parseProviderCheckPrice(body.toString("utf8")), source: PROVIDER_CHECK_PRICE_URL,
      sourceDigest: createHash("sha256").update(body).digest("hex"), verifiedAtMs: received - initialAge, receivedAtMs: received })];
  } finally { await reader?.cancel().catch(() => {}); }
}
