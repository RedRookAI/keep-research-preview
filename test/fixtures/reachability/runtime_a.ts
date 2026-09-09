// Fixture: a real runtime node, value-imported by entry and value-importing runtime_b.
// The whole chain entry -> runtime_a -> runtime_b is RUNTIME-REACHABLE.
import { bVal } from "./runtime_b.js";
export function aRun(): number {
  return bVal + 1;
}
