import type { BrokerRequest, BrokerResult, EffectBroker } from "../broker/broker.js";
import {
  RoleChannel,
  type RoleCredential,
  type RoleIdentity,
  type RoleRequest,
  roleRequest,
} from "./role_channel.js";

export interface ActuatorClock {
  now(): bigint;
  epoch(): bigint;
}

/**
 * D3 owns the broker and therefore the raw family executors. Its wire request contains only a broker request: trusted
 * time and policy epoch are sampled inside D3, never accepted from D1/D2. The RoleChannel binds the caller to the D2
 * authority instance and boot before dispatch can reach the broker.
 */
export class SacrificialActuator {
  readonly #channel: RoleChannel<BrokerRequest, BrokerResult>;

  constructor(authority: RoleCredential, broker: EffectBroker, clock: ActuatorClock) {
    this.#channel = new RoleChannel(authority, "authority", (request) =>
      broker.dispatch(request, clock.now(), clock.epoch()));
  }

  receive(request: RoleRequest<BrokerRequest>): Promise<BrokerResult> {
    return this.#channel.receive(request);
  }
}

/** The only endpoint D2 needs. The credential remains private and is never returned in an effect result. */
export class AuthorityActuatorClient {
  readonly #credential: RoleCredential;
  readonly #send: (request: RoleRequest<BrokerRequest>) => Promise<BrokerResult>;

  constructor(credential: RoleCredential, send: (request: RoleRequest<BrokerRequest>) => Promise<BrokerResult>) {
    this.#credential = credential;
    this.#send = send;
  }

  get identity(): RoleIdentity { return this.#credential.identity; }

  dispatch(request: BrokerRequest): Promise<BrokerResult> {
    return this.#send(roleRequest(this.#credential, request));
  }
}

