import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createSign, createHmac, type KeyObject } from "node:crypto";

import { OidcJwksProvider, type Jwks } from "../src/identity/oidc_provider.js";

const b64u = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const NOW = 1_760_000_000_000; // fixed ms
const nowSec = Math.floor(NOW / 1000);

// A local IdP: RSA keypair + published JWKS.
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>), kid: "k1", alg: "RS256", use: "sig" };
const jwks: Jwks = { keys: [jwk as never] };
const ISS = "https://idp.example.com";
const AUD = "keep-review";

function signRs256(payload: Record<string, unknown>, kid = "k1", key: KeyObject = privateKey): string {
  const h = b64u({ alg: "RS256", kid, typ: "JWT" });
  const p = b64u(payload);
  const sig = createSign("RSA-SHA256").update(`${h}.${p}`).end().sign(key).toString("base64url");
  return `${h}.${p}.${sig}`;
}
const goodClaims = () => ({ sub: "alice", iss: ISS, aud: AUD, exp: nowSec + 300, email: "a@x.io", name: "Alice" });
const provider = () => new OidcJwksProvider({ jwks, issuer: ISS, audience: AUD });

test("VALID (crown): a correctly RS256-signed OIDC token verifies against the JWKS → identity", async () => {
  const v = await provider().verify(signRs256(goodClaims()), NOW);
  assert.ok(v, "the token verified");
  assert.equal(v!.subject, "alice");
  assert.equal(v!.email, "a@x.io");
  assert.equal(v!.displayName, "Alice");
});

test("ALG CONFUSION (RS256→HS256): a token HMAC-signed with the RSA public key is REJECTED", async () => {
  // The classic attack: forge alg=HS256 and sign with the public key bytes as the HMAC secret.
  const pubPem = publicKey.export({ format: "pem", type: "spki" }) as string;
  const h = b64u({ alg: "HS256", kid: "k1", typ: "JWT" });
  const p = b64u(goodClaims());
  const forged = createHmac("sha256", pubPem).update(`${h}.${p}`).digest("base64url");
  const token = `${h}.${p}.${forged}`;
  assert.equal(await provider().verify(token, NOW), null, "algorithm confusion is defeated by pinning RS256");
});

test("ALG NONE: an unsigned alg:none token is REJECTED", async () => {
  const h = b64u({ alg: "none", kid: "k1", typ: "JWT" });
  const p = b64u(goodClaims());
  assert.equal(await provider().verify(`${h}.${p}.`, NOW), null, "alg:none is rejected");
});

test("TAMPER: a modified payload invalidates the signature", async () => {
  const token = signRs256(goodClaims());
  const [h, , s] = token.split(".");
  const tampered = `${h}.${b64u({ ...goodClaims(), sub: "attacker" })}.${s}`;
  assert.equal(await provider().verify(tampered, NOW), null, "a tampered payload fails signature verification");
});

test("ISS + AUD: wrong issuer or audience is REJECTED (cross-service replay defense)", async () => {
  assert.equal(await provider().verify(signRs256({ ...goodClaims(), iss: "https://evil.example" }), NOW), null, "wrong iss rejected");
  assert.equal(await provider().verify(signRs256({ ...goodClaims(), aud: "other-service" }), NOW), null, "wrong aud rejected");
  // aud as an array containing the expected value is accepted
  assert.ok(await provider().verify(signRs256({ ...goodClaims(), aud: ["x", AUD] }), NOW), "aud array containing us is accepted");
});

test("EXPIRY: an expired token is REJECTED (beyond leeway)", async () => {
  assert.equal(await provider().verify(signRs256({ ...goodClaims(), exp: nowSec - 3600 }), NOW), null, "expired token rejected");
});

test("KID MISS: a token referencing an unknown key is REJECTED", async () => {
  assert.equal(await provider().verify(signRs256(goodClaims(), "unknown-kid"), NOW), null, "no JWKS key for kid ⇒ reject");
});

test("WRONG KEY: a token signed by a DIFFERENT private key is REJECTED", async () => {
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  assert.equal(await provider().verify(signRs256(goodClaims(), "k1", other), NOW), null, "a signature from a non-JWKS key fails");
});

test("present malformed nbf is refused for owner and organization subjects", async () => {
  for (const sub of ["owner:local", "organization:tenant-a:member"]) {
    for (const nbf of [String(nowSec + 300), null, {}, [], true]) {
      assert.equal(await provider().verify(signRs256({ ...goodClaims(), sub, nbf }), NOW), null, `malformed ${JSON.stringify(nbf)}`);
    }
    // A signed JSON number can overflow the parser even though Infinity is not a JSON literal.
    const h = b64u({ alg: "RS256", kid: "k1" });
    const p = Buffer.from(JSON.stringify({ ...goodClaims(), sub }).replace(/}$/, ',"nbf":1e999}')).toString("base64url");
    const sig = createSign("RSA-SHA256").update(`${h}.${p}`).end().sign(privateKey).toString("base64url");
    assert.equal(await provider().verify(`${h}.${p}.${sig}`, NOW), null, "non-finite parsed NumericDate");
  }
});

test("optional and finite fractional nbf retain existing signature, issuer and time checks", async () => {
  for (const sub of ["owner:local", "organization:tenant-a:member"]) {
    assert.equal((await provider().verify(signRs256({ ...goodClaims(), sub }), NOW))?.subject, sub);
    assert.ok(await provider().verify(signRs256({ ...goodClaims(), sub, nbf: nowSec - 0.5 }), NOW));
    assert.ok(await provider().verify(signRs256({ ...goodClaims(), sub, nbf: nowSec + 60 }), NOW));
    assert.equal(await provider().verify(signRs256({ ...goodClaims(), sub, nbf: nowSec + 60.5 }), NOW), null);
    assert.equal(await provider().verify(signRs256({ ...goodClaims(), sub, nbf: nowSec - 0.5, iss: "https://wrong.example" }), NOW), null);
    const token = signRs256({ ...goodClaims(), sub, nbf: nowSec - 0.5 });
    const [h, , sig] = token.split(".");
    assert.equal(await provider().verify(`${h}.${b64u({ ...goodClaims(), sub, nbf: nowSec - 1 })}.${sig}`, NOW), null);
  }
});

test("invalid OIDC leeway fails construction before verification", () => {
  for (const leewaySec of [NaN, Infinity, -Infinity, -1, -0.1]) {
    assert.throws(() => new OidcJwksProvider({ jwks, issuer: ISS, audience: AUD, leewaySec }), /leeway/i);
  }
});

test("default, zero and fractional leeway preserve finite expiration decisions", async () => {
  for (const sub of ["owner:local", "organization:tenant-a:member"]) {
    for (const leewaySec of [undefined, 0, 0.5]) {
      const p = new OidcJwksProvider({ jwks, issuer: ISS, audience: AUD, ...(leewaySec === undefined ? {} : { leewaySec }) });
      assert.equal((await p.verify(signRs256({ ...goodClaims(), sub }), NOW))?.subject, sub);
      assert.equal(await p.verify(signRs256({ ...goodClaims(), sub, exp: nowSec - 3600 }), NOW), null);
      const skew = leewaySec ?? 60;
      assert.ok(await p.verify(signRs256({ ...goodClaims(), sub, exp: nowSec - skew + 0.25 }), NOW));
      assert.equal(await p.verify(signRs256({ ...goodClaims(), sub, exp: nowSec - skew - 0.25 }), NOW), null);
    }
  }
});

test("expiration upper boundary is strict at millisecond precision including skew", async () => {
  for (const sub of ["owner:local", "organization:tenant-a:member"]) {
    for (const leewaySec of [0, 0.25, 60]) {
      const p = new OidcJwksProvider({ jwks, issuer: ISS, audience: AUD, leewaySec });
      for (const exp of [nowSec, nowSec + 0.5]) {
        const token = signRs256({ ...goodClaims(), sub, exp });
        const boundaryMs = (exp + leewaySec) * 1000;
        assert.ok(await p.verify(token, boundaryMs - 1), "one millisecond before expiry");
        assert.equal(await p.verify(token, boundaryMs), null, "exact expiry plus skew");
        assert.equal(await p.verify(token, boundaryMs + 1), null, "one millisecond after expiry");
      }
    }
  }
});

test("fractional nbf lower boundary remains inclusive with valid skew", async () => {
  for (const leewaySec of [0, 0.25, 60]) {
    const p = new OidcJwksProvider({ jwks, issuer: ISS, audience: AUD, leewaySec });
    const nbf = nowSec + 0.5, boundaryMs = (nbf - leewaySec) * 1000;
    const token = signRs256({ ...goodClaims(), nbf });
    assert.equal(await p.verify(token, boundaryMs - 1), null);
    assert.ok(await p.verify(token, boundaryMs));
    assert.ok(await p.verify(token, boundaryMs + 1));
  }
});
