import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import test from "node:test";
import { SECRET } from "../src/config.js";
import { issueChallenge, verifyPow } from "../src/pow.js";
import { leadingZeroBits, solvePow } from "./helpers.js";

/** DIFFICULTY is private to src/pow.ts; the issued challenge reports it. */
const DIFFICULTY = issueChallenge().difficulty;

/** Signs an arbitrary "<ts>.<rand>" payload with the same recipe as
 *  src/pow.ts, so freshness checks can be exercised with valid signatures. */
function signChallenge(payload: string): string {
  const sig = createHmac("sha256", SECRET).update(payload).digest("hex");
  return `${payload}.${sig}`;
}

/** Finds a nonce that provably does NOT solve the challenge, so the
 *  wrong-nonce test can never flake into an accidental solution. */
function wrongNonce(challenge: string): string {
  // Tight numeric loop — sanctioned `let` (docs/rules/typescript.md → Avoid Let).
  for (let nonce = 0; ; nonce += 1) {
    const digest = createHash("sha256").update(`${challenge}:${nonce}`).digest();
    if (leadingZeroBits(digest) < DIFFICULTY) return String(nonce);
  }
}

test("issue then solve then verify succeeds", () => {
  const { challenge, difficulty } = issueChallenge();
  assert.equal(verifyPow(challenge, solvePow(challenge, difficulty)), true);
});

test("replaying a spent challenge fails", () => {
  const { challenge, difficulty } = issueChallenge();
  const nonce = solvePow(challenge, difficulty);
  assert.equal(verifyPow(challenge, nonce), true);
  assert.equal(verifyPow(challenge, nonce), false);
});

test("a flipped byte in the signature part fails", () => {
  const { challenge } = issueChallenge();
  const lastChar = challenge.slice(-1) === "a" ? "b" : "a";
  const tampered = challenge.slice(0, -1) + lastChar;
  assert.equal(verifyPow(tampered, solvePow(tampered, DIFFICULTY)), false);
});

test("garbage strings and non-strings fail", () => {
  assert.equal(verifyPow("garbage", "0"), false);
  assert.equal(verifyPow("a.b", "0"), false);
  assert.equal(verifyPow("a.b.c.d", "0"), false);
  assert.equal(verifyPow("", ""), false);
  assert.equal(verifyPow(undefined, "0"), false);
  assert.equal(verifyPow(null, null), false);
  assert.equal(verifyPow(issueChallenge().challenge, 42), false);
  assert.equal(verifyPow(12, {}), false);
});

test("a wrong nonce fails", () => {
  const { challenge } = issueChallenge();
  assert.equal(verifyPow(challenge, wrongNonce(challenge)), false);
});

test("a stale challenge fails even with a valid solution", () => {
  const staleTs = Date.now() - 6 * 60_000;
  const challenge = signChallenge(`${staleTs}.${randomBytes(16).toString("hex")}`);
  assert.equal(verifyPow(challenge, solvePow(challenge, DIFFICULTY)), false);
});

test("a future-dated challenge fails even with a valid solution", () => {
  const futureTs = Date.now() + 60 * 60_000;
  const challenge = signChallenge(`${futureTs}.${randomBytes(16).toString("hex")}`);
  assert.equal(verifyPow(challenge, solvePow(challenge, DIFFICULTY)), false);
});
