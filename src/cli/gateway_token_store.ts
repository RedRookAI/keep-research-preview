import { closeSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const TOKEN = /^[0-9a-f]{48,128}$/u;

export class FileGatewayTokenStore {
  constructor(private readonly path: string) {}

  load(): string | undefined {
    try {
      const stat = lstatSync(this.path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 49 || stat.size > 129 || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) throw new Error("gateway token must be a bounded mode-0600 regular file");
      const token = readFileSync(this.path, "utf8").replace(/\r?\n$/u, "");
      if (!TOKEN.test(token)) throw new Error("gateway token is malformed");
      return token;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  }

  save(token: string): void {
    if (!TOKEN.test(token)) throw new Error("gateway token is malformed");
    const temporary = `${this.path}.${process.pid}.tmp`;
    let fd: number | undefined;
    try {
      fd = openSync(temporary, "wx", 0o600);
      writeFileSync(fd, `${token}\n`, "utf8");
      fsyncSync(fd); closeSync(fd); fd = undefined;
      renameSync(temporary, this.path);
      if (process.platform !== "win32") { const directory = openSync(dirname(this.path), "r"); try { fsyncSync(directory); } finally { closeSync(directory); } }
    } finally {
      if (fd !== undefined) closeSync(fd);
      try { unlinkSync(temporary); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
  }
}
