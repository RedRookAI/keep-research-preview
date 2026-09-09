// Fixture ROOT (the entrypoint the sweep marks from). It exercises all four edge colors:
//   - VALUE import of runtime_a  -> runtime chain is RUNTIME-REACHABLE
//   - `import type` of type_island -> ERASED edge; type_island is a TYPE-ONLY-ISLAND
//   - dynamic import() of dynamic_mod -> NEEDS-A-HUMAN-LOOK
// unreferenced.ts is deliberately not mentioned -> UNREFERENCED.
import { aRun } from "./runtime_a.js";
import type { IslandShape } from "./type_island.js";

export const started: IslandShape = aRun();

export async function loadDynamic(): Promise<number> {
  const mod = await import("./dynamic_mod.js");
  return mod.dynFn();
}
