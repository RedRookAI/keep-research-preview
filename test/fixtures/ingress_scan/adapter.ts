// Fixture: an APPROVED adapter module. It holds ambient authority (a listener + a timer), but because it is on the
// scanner's --allow list it is the sole sanctioned holder and must NOT be flagged.
import { createServer } from "node:http";

export function startAdapter(): void {
  createServer(() => {}).listen(0);
  setInterval(() => {}, 1000);
}
