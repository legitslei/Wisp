import { createHash } from "node:crypto";

/** Mirrors the private helper in src/pow.ts (not exported there). */
export function leadingZeroBits(buf: Buffer): number {
  // Tight numeric loop on a hot path — sanctioned `let` (docs/rules/typescript.md → Avoid Let).
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

/** Brute-forces a nonce: ~2^15 sha256 calls at difficulty 15, well under a second. */
export function solvePow(challenge: string, difficulty: number): string {
  // Tight numeric loop on a hot path — sanctioned `let` (docs/rules/typescript.md → Avoid Let).
  for (let nonce = 0; ; nonce += 1) {
    const digest = createHash("sha256").update(`${challenge}:${nonce}`).digest();
    if (leadingZeroBits(digest) >= difficulty) return String(nonce);
  }
}

/** Reads a route's JSON body. Boundary cast: the route contract fixes the
 *  top-level shape as a JSON object (docs/rules/typescript.md exception). */
export async function readJson(res: Response): Promise<Record<string, unknown>> {
  return (await res.json()) as Record<string, unknown>;
}

/** Pulls one field off an unknown value — same pattern (and sanctioned cast)
 *  as `field` in src/app.ts. */
export function prop(value: unknown, key: string): unknown {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)[key]
    : undefined;
}
