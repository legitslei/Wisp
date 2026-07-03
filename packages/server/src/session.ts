import { createHmac, timingSafeEqual } from "node:crypto";
import { SECRET } from "./config.js";

/** Sessions expire after a year — keep in sync with the cookie maxAge,
 *  which imports this constant (app.ts → setSession). */
export const SESSION_MAX_AGE_S = 60 * 60 * 24 * 365;

function hmac(value: string): string {
  return createHmac("sha256", SECRET).update(value).digest("base64url");
}

/** Session token: "<userId>.<issuedAt>.<hmac(userId.issuedAt)>". Stateless,
 *  httpOnly cookie. The signed issue time bounds a leaked token's life to
 *  SESSION_MAX_AGE_S — without it a stolen token would be valid forever. */
export function signSession(userId: string): string {
  const payload = `${userId}.${Date.now()}`;
  return `${payload}.${hmac(payload)}`;
}

/** Returns the userId if the token is valid and unexpired, otherwise null. */
export function verifySession(token: unknown): string | null {
  if (typeof token !== "string") return null;
  const sigDot = token.lastIndexOf(".");
  if (sigDot <= 0) return null;
  const payload = token.slice(0, sigDot);
  const sig = Buffer.from(token.slice(sigDot + 1));
  const expected = Buffer.from(hmac(payload));
  if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return null;
  const tsDot = payload.lastIndexOf(".");
  if (tsDot <= 0) return null;
  const age = Date.now() - Number(payload.slice(tsDot + 1));
  if (!Number.isFinite(age) || age < 0 || age > SESSION_MAX_AGE_S * 1000) return null;
  return payload.slice(0, tsDot);
}
