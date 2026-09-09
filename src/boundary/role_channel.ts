import { randomBytes, timingSafeEqual } from "node:crypto";

export type BoundaryRole = "workload" | "authority" | "actuator" | "verifier-executor" | "evaluator";

export interface RoleIdentity {
  readonly role: BoundaryRole;
  readonly instanceId: string;
  readonly bootId: string;
}

export interface RoleCredential {
  readonly identity: RoleIdentity;
  readonly secret: Uint8Array;
}

export class BoundaryDeniedError extends Error {
  constructor(message: string) { super(`role boundary: ${message}`); this.name = "BoundaryDeniedError"; }
}

export function issueRoleCredential(role: BoundaryRole, instanceId: string, bootId: string): RoleCredential {
  if (!instanceId || !bootId) throw new BoundaryDeniedError("identity fields are required");
  return Object.freeze({ identity: Object.freeze({ role, instanceId, bootId }), secret: randomBytes(32) });
}

export interface RoleRequest<T> {
  readonly claimed: RoleIdentity;
  readonly credential: Uint8Array;
  readonly body: T;
}

/** Reference transport authenticator. Native transports replace the secret comparison with peer credentials. */
export class RoleChannel<TRequest, TResponse> {
  readonly #expected: RoleCredential;
  readonly #allowedRole: BoundaryRole;
  readonly #handler: (body: TRequest, peer: RoleIdentity) => TResponse | Promise<TResponse>;

  constructor(expected: RoleCredential, allowedRole: BoundaryRole,
    handler: (body: TRequest, peer: RoleIdentity) => TResponse | Promise<TResponse>) {
    this.#expected = expected;
    this.#allowedRole = allowedRole;
    this.#handler = handler;
  }

  async receive(request: RoleRequest<TRequest>): Promise<TResponse> {
    const expected = this.#expected.identity;
    const claimed = request.claimed;
    if (claimed.role !== this.#allowedRole || claimed.role !== expected.role ||
        claimed.instanceId !== expected.instanceId || claimed.bootId !== expected.bootId) {
      throw new BoundaryDeniedError("peer identity mismatch");
    }
    const supplied = Buffer.from(request.credential);
    const secret = Buffer.from(this.#expected.secret);
    if (supplied.length !== secret.length || !timingSafeEqual(supplied, secret)) {
      throw new BoundaryDeniedError("peer credential mismatch");
    }
    return this.#handler(request.body, expected);
  }
}

export function roleRequest<T>(credential: RoleCredential, body: T): RoleRequest<T> {
  return { claimed: credential.identity, credential: credential.secret, body };
}
