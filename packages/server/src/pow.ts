import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { SECRET } from "./config.js";

/** Leading zero bits required in sha256(challenge:nonce).
 *  ~2^15 hashes ≈ well under a second in a browser, annoying at bot scale. */
const DIFFICULTY = 15;
const TTL_MS = 5 * 60_000;

/** Challenges already spent — prevents replaying one solved puzzle. */
const used = new Map<string, number>();

function sweepUsed() {
  const now = Date.now();
  for (const [key, expires] of used) if (expires < now) used.delete(key);
}

/** Stateless, HMAC-signed challenge: "<timestamp>.<random>.<signature>". */
export function issueChallenge(): { challenge: string; difficulty: number } {
  const payload = `${Date.now()}.${randomBytes(16).toString("hex")}`;
  const sig = createHmac("sha256", SECRET).update(payload).digest("hex");
  return { challenge: `${payload}.${sig}`, difficulty: DIFFICULTY };
}

export function verifyPow(challenge: unknown, nonce: unknown): boolean {
  if (typeof challenge !== "string" || typeof nonce !== "string") return false;
  const parts = challenge.split(".");
  if (parts.length !== 3) return false;
  const [ts, rand, sig] = parts;
  if (ts === undefined || rand === undefined || sig === undefined) return false;

  // 1. Server-issued?
  const expected = createHmac("sha256", SECRET).update(`${ts}.${rand}`).digest();
  const given = Buffer.from(sig, "hex");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return false;

  // 2. Fresh and unspent? (ts is HMAC-covered, so this guard is belt-and-
  // braces against malformed self-issued data, not attacker input.)
  const age = Date.now() - Number(ts);
  if (!Number.isFinite(age) || age < 0 || age > TTL_MS) return false;
  if (used.has(challenge)) return false;

  // 3. Actually solved?
  const digest = createHash("sha256").update(`${challenge}:${nonce}`).digest();
  if (leadingZeroBits(digest) < DIFFICULTY) return false;

  sweepUsed();
  used.set(challenge, Date.now() + TTL_MS);
  return true;
}

function leadingZeroBits(buf: Buffer): number {
  let bits = 0;
  for (const byte of buf) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}
