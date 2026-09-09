// The declared OWNER of the fs family — allowed to touch node:fs. Must not be flagged for fs.
import { readFileSync } from "node:fs";
export function readIt(p: string): string { return readFileSync(p, "utf8"); }
