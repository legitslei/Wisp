import { createHash, randomBytes } from "node:crypto";

/** 32 characters (5 bits each), lowercase, without the lookalikes l/o/0/1.
 *  Exactly 32 keeps `byte % 32` free of modulo bias. */
const ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789";
const GROUP_COUNT = 6;
const GROUP_LENGTH = 4;

/** Server-generated account code: "wisp-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx".
 *  24 alphabet characters = 120 bits of entropy — far beyond guessable. */
export function generateAccountCode(): string {
  const bytes = randomBytes(GROUP_COUNT * GROUP_LENGTH);
  const chars = Array.from(bytes, (byte) => ALPHABET[byte % ALPHABET.length]);
  const groups = Array.from({ length: GROUP_COUNT }, (_, group) =>
    chars.slice(group * GROUP_LENGTH, (group + 1) * GROUP_LENGTH).join(""),
  );
  return `wisp-${groups.join("-")}`;
}

/** Plain SHA-256, deliberately not HMAC(SECRET): the stored hash must keep
 *  working across secret rotation and restarts, and the code's 120 bits of
 *  server-generated entropy already make offline guessing infeasible.
 *  Lookup happens by hash key, so no secret is ever compared with `===`. */
export function hashAccountCode(code: string): string {
  return createHash("sha256").update(code).digest("base64url");
}

/** Trims and lowercases a pasted code; returns undefined unless it matches
 *  the issued shape, so malformed input fails closed before any lookup. */
export function normalizeAccountCode(code: unknown): string | undefined {
  if (typeof code !== "string") return undefined;
  const cleaned = code.trim().toLowerCase();
  // Accept the legacy "phantom-" prefix too, so codes issued before the
  // rename still resolve (the stored hash covers the full code string).
  return /^(?:wisp|phantom)(-[a-z2-9]{4}){6}$/.test(cleaned) ? cleaned : undefined;
}
