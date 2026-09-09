/**
 * Theme 1 (Instance Isolation), Part 1 — BindStrategy.
 *
 * Keep must NEVER squat a fixed port (the OpenClaw failure: 2nd instance -> EADDRINUSE,
 * supervisor thrash, scanners find AI infra on known ports). This is the transport-bind
 * port with three strategies behind one interface:
 *
 *   - "unix-socket"        : a unix domain socket at a per-instance path. NO TCP port at
 *                            all; access is gated by filesystem permissions (strictly
 *                            better for local clients — SOTA-recommended). Default.
 *   - "ephemeral-loopback" : bind 127.0.0.1:0 so the OS assigns a free dynamic port; read
 *                            the REAL port back from server.address() AFTER listening.
 *                            We keep this exact listening socket — we never close-and-
 *                            rebind, which is the documented TOCTOU anti-pattern.
 *   - "fixed"              : an explicit operator port, ONLY when opted in (e.g. behind a
 *                            reverse proxy). Never a default.
 *
 * Zero runtime deps (node:net). What would change it: nothing near-term; this is the
 * correct portable floor. systemd socket activation could be an optional Linux upgrade.
 */

import net from "node:net";

export type BindKind = "unix-socket" | "ephemeral-loopback" | "fixed";

export interface BindRequest {
  readonly kind: BindKind;
  /** For "unix-socket": the socket file path. */
  readonly socketPath?: string;
  /** For "fixed": the explicit port the operator opted into. */
  readonly fixedPort?: number;
  /** For loopback/fixed: host to bind (defaults to 127.0.0.1 — loopback only). */
  readonly host?: string;
}

/** A description of what was actually bound — written to the instance runfile. */
export interface BoundListener {
  readonly kind: BindKind;
  /** The unix socket path, when kind === "unix-socket". */
  readonly socketPath?: string;
  /** The actual TCP port, when kind is loopback/fixed. */
  readonly port?: number;
  readonly host?: string;
  /** The live server. Callers attach connection/request handlers. */
  readonly server: net.Server;
  /** Stop listening and free the resource. */
  close(): Promise<void>;
}

/**
 * Bind a listener per the request. Resolves only once the socket is actually listening,
 * with the real assigned port already known (no close-and-rebind race).
 */
export function bindListener(req: BindRequest): Promise<BoundListener> {
  const server = net.createServer();

  return new Promise<BoundListener>((resolve, reject) => {
    server.once("error", reject);

    const onListening = () => {
      server.removeListener("error", reject);
      const close = () =>
        new Promise<void>((res) => {
          server.close(() => res());
        });

      if (req.kind === "unix-socket") {
        resolve({ kind: "unix-socket", socketPath: req.socketPath!, server, close });
        return;
      }
      // loopback / fixed: read the ACTUAL bound port from the live socket.
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : req.fixedPort!;
      const host = typeof addr === "object" && addr ? addr.address : (req.host ?? "127.0.0.1");
      resolve({ kind: req.kind, port, host, server, close });
    };

    switch (req.kind) {
      case "unix-socket": {
        if (!req.socketPath) return reject(new Error("unix-socket bind needs a socketPath"));
        server.listen({ path: req.socketPath }, onListening);
        break;
      }
      case "ephemeral-loopback": {
        // Port 0 => OS assigns a free dynamic port. Keep THIS socket (no rebind).
        server.listen({ host: req.host ?? "127.0.0.1", port: 0 }, onListening);
        break;
      }
      case "fixed": {
        if (typeof req.fixedPort !== "number") return reject(new Error("fixed bind needs a fixedPort"));
        server.listen({ host: req.host ?? "127.0.0.1", port: req.fixedPort }, onListening);
        break;
      }
      default:
        return reject(new Error(`unknown bind kind: ${(req as BindRequest).kind}`));
    }
  });
}

/**
 * The default bind request for an instance: a unix socket under the instance home when
 * the platform supports it, else an ephemeral loopback port. (Windows named-pipe paths
 * differ; callers pass the right socketPath for the platform.)
 */
export function defaultBindFor(instanceHome: string, opts: { preferSocket?: boolean; socketPath?: string } = {}): BindRequest {
  const preferSocket = opts.preferSocket ?? true;
  if (preferSocket) {
    return { kind: "unix-socket", socketPath: opts.socketPath ?? `${instanceHome}/keep.sock` };
  }
  return { kind: "ephemeral-loopback", host: "127.0.0.1" };
}
