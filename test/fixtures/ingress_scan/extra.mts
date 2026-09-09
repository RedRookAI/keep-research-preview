// Fixture in a NON-.ts source extension (.mts) — proves walkTs scans every build-eligible extension, not only .ts.
// A forbidden construct here must still be flagged (a whole file class going unscanned is a fail-open).
export const laundered = eval("1 + 1");
