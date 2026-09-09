// Fixture: the DELIBERATE type-only island. It exports a RUNTIME value (islandRun — real
// code that can run) but the only edge into it is `import type` from entry, which the
// compiler ERASES at emit. So nothing loads it at runtime: TYPE-ONLY-ISLAND. This is the
// plan_gate.ts shape distilled to a fixture — the wire that reads connected but carries no load.
export function islandRun(): number {
  return 41;
}
export type IslandShape = ReturnType<typeof islandRun>;
