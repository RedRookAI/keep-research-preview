// Fixture: reached ONLY via a dynamic `import()` from entry. A dynamic import IS a runtime
// load, but its target and reachability are not statically decidable in general (the specifier
// can be computed, gated, or registry-driven). The honest verdict is NEEDS-A-HUMAN-LOOK — never
// silently ISLAND (it may well run) and never silently RUNTIME-REACHABLE (it may never be called).
export function dynFn(): number {
  return 2;
}
