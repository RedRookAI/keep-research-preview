import type { TestContext } from "node:test";
import { PROVIDER_CHECK_PRICE_URL } from "../../src/reference/provider_check_pricing.js";

/** Synthetic current table shape, not a saved copy of the provider's page. */
export function priceHtml(input = 0.3, output = 1.2): string {
  return `<table><tr><td colspan="3">MODEL</td><td>deepseek-flash<sup>(1)</sup></td><td>deepseek-v4-pro</td></tr>
    <tr><td colspan="3">BASE URL (OpenAI Format)</td><td colspan="2">https://api.deepseek.com</td></tr>
    <tr><td rowspan="6">PRICING<sup>(2)</sup></td><td rowspan="2">1M INPUT TOKENS<br>(CACHE HIT)</td><td>OFF-PEAK</td><td>$0.003</td><td>$0.022</td></tr>
    <tr><td>PEAK</td><td>$0.006</td><td>$0.044</td></tr>
    <tr><td rowspan="2">1M INPUT TOKENS<br>(CACHE MISS)</td><td>OFF-PEAK</td><td>$${input / 2}</td><td>$0.66</td></tr>
    <tr><td>PEAK</td><td>$${input}</td><td>$1.32</td></tr>
    <tr><td rowspan="2">1M OUTPUT TOKENS</td><td>OFF-PEAK</td><td>$${output / 2}</td><td>$1.98</td></tr>
    <tr><td>PEAK</td><td>$${output}</td><td>$3.96</td></tr>
    <tr><td colspan="3">Concurrency Limit<sup>(3)</sup></td><td>2500</td><td>500</td></tr></table>`;
}
export function priceResponse(body = priceHtml(), headers: Record<string, string> = {}, status = 200): Response {
  const response = new Response(body, { status, headers: { "content-type": "text/html", date: new Date(Date.now()).toUTCString(), ...headers } });
  Object.defineProperty(response, "url", { value: PROVIDER_CHECK_PRICE_URL }); return response;
}
interface Transport {
  sinkUrl: string;
  metadataHits: number;
  metadata: () => Response | Promise<Response>;
}
const transports = new WeakMap<TestContext, Transport>();
/** No actual TLS/source egress: metadata is synthetic; model transport uses the owned HTTP sink. */
export function priceTransport(t: TestContext, sinkUrl: string): Transport {
  const old = transports.get(t); if (old) { old.sinkUrl = sinkUrl; return old; }
  const saved = globalThis.fetch;
  const fixture: Transport = { sinkUrl, metadataHits: 0, metadata: () => priceResponse() };
  globalThis.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === PROVIDER_CHECK_PRICE_URL) {
      fixture.metadataHits++;
      if (init?.method !== "GET" || new Headers(init.headers).has("authorization") || init.body !== undefined) throw new Error("metadata leaked model data or authority");
      return fixture.metadata();
    }
    if (url.startsWith("https://api.deepseek.com/")) return saved(url.replace("https://api.deepseek.com", fixture.sinkUrl), init);
    return saved(input, init);
  };
  t.after(() => { globalThis.fetch = saved; }); transports.set(t, fixture); return fixture;
}
