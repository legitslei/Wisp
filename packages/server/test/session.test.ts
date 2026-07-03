import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import { SECRET } from "../src/config.js";
import { SESSION_MAX_AGE_S, signSession, verifySession } from "../src/session.js";

/** Builds a token with the same HMAC recipe as src/session.ts but an
 *  arbitrary issuedAt, so expiry paths can be exercised. */
function forgeToken(userId: string, issuedAt: number): string {
  const payload = `${userId}.${issuedAt}`;
  const sig = createHmac("sha256", SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

test("sign then verify roundtrips the userId", () => {
  const token = signSession("user-123");
  assert.equal(verifySession(token), "user-123");
});

test("a tampered signature is rejected", () => {
  const token = signSession("user-123");
  const lastChar = token.slice(-1) === "A" ? "B" : "A";
  assert.equal(verifySession(token.slice(0, -1) + lastChar), null);
});

test("a tampered userId is rejected", () => {
  const token = signSession("user-123");
  const swappedFirstChar = token.startsWith("x") ? "y" : "x";
  assert.equal(verifySession(swappedFirstChar + token.slice(1)), null);
});

test("a truncated token is rejected", () => {
  const token = signSession("user-123");
  assert.equal(verifySession(token.slice(0, -5)), null);
});

test("empty-string and non-string tokens are rejected", () => {
  assert.equal(verifySession(""), null);
  assert.equal(verifySession(undefined), null);
  assert.equal(verifySession(42), null);
});

test("a userId containing a dot still roundtrips", () => {
  const token = signSession("team.alpha.user");
  assert.equal(verifySession(token), "team.alpha.user");
});

test("an expired token is rejected", () => {
  const issuedAt = Date.now() - SESSION_MAX_AGE_S * 1000 - 60_000;
  assert.equal(verifySession(forgeToken("user-123", issuedAt)), null);
});

test("a token issued in the future is rejected", () => {
  const issuedAt = Date.now() + 60 * 60_000;
  assert.equal(verifySession(forgeToken("user-123", issuedAt)), null);
});
