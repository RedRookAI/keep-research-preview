#!/usr/bin/env node
/**
 * `keep` entrypoint (Increment S0). Delegates to the CLI. The former Phase-0 substrate demo is retired in
 * favor of the real command surface; run `node dist/src/main.js <command>` (or the `keep` bin) to use it.
 */
import { main } from "./cli/keep.js";

main(process.argv.slice(2)).then((code) => { process.exitCode = code; }).catch((err) => {
  process.stderr.write(`fatal: ${(err as Error).message}\n`);
  process.exitCode = 1;
});
