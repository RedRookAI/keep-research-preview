/** Bind the appliance sample's executable, PATH and jail mount to one Node. */
import { realpathSync } from 'node:fs';
import { dirname } from 'node:path';

export function sampleNodeToolchain(execPath = process.execPath) {
  const executable = realpathSync(execPath);
  const bin = dirname(executable);
  return Object.freeze({ executable, bin, root: dirname(bin) });
}
