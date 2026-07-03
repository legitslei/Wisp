/**
 * Wisp — drop-in browser widget.
 *
 * Bundled as an IIFE exposing a global `Wisp`:
 *
 *   <script src="/wisp.js"></script>
 *   <script>
 *     const account = await Wisp.signUp();             // PoW + create passkey
 *     const account = await Wisp.signIn();             // return with passkey
 *     const created = await Wisp.signUpWithCode();     // PoW + copyable code
 *     const account = await Wisp.signInWithCode(code); // return with code
 *     const account = await Wisp.signUpAsGuest();      // PoW only, ephemeral
 *     const me      = await Wisp.whoAmI();             // current session or null
 *     await Wisp.signOut();
 *   </script>
 *
 * The same script also registers optional drop-in UI elements
 * (<wisp-button>, <wisp-code-signup>, <wisp-code-signin>, <wisp-status>) —
 * see elements.ts. Using them is optional; the functions above stay the API.
 */
import {
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
// Side-effect import: registers the custom elements. elements.ts imports this
// module's functions — a benign cycle (function declarations are hoisted, and
// the elements only call them on user interaction).
import "./elements.js";

let base = "";

/** Point the widget at a server on another origin (default: same origin). */
export function configure(opts: { baseUrl?: string } = {}): void {
  base = opts.baseUrl?.replace(/\/$/, "") ?? "";
}

/* --------------------------- Proof of work -------------------------- */

async function sha256(input: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return new Uint8Array(digest);
}

function leadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const b of bytes) {
    if (b === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(b) - 24;
    break;
  }
  return bits;
}

/** At difficulty 15 a solution lands in ~2^15 tries; hitting this ceiling
 *  (2^24, ~500× the expectation) means something is wrong — give up rather
 *  than spin the tab forever. */
const MAX_POW_ATTEMPTS = 1 << 24;

async function solvePow(): Promise<{ challenge: string; nonce: string }> {
  const res = await fetch(`${base}/api/pow`);
  if (!res.ok) throw new Error(`could not fetch bot-filter challenge (HTTP ${res.status})`);
  const { challenge, difficulty } = (await res.json()) as {
    challenge: string;
    difficulty: number;
  };
  for (let nonce = 0; nonce < MAX_POW_ATTEMPTS; nonce++) {
    const digest = await sha256(`${challenge}:${nonce}`);
    if (leadingZeroBits(digest) >= difficulty) return { challenge, nonce: String(nonce) };
    if (nonce % 512 === 511) await new Promise((r) => setTimeout(r, 0)); // let the UI breathe
  }
  throw new Error("bot-filter puzzle not solved — refresh and try again");
}

/* ------------------------------ HTTP ------------------------------- */

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error((detail as { error?: string }).error ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export interface Account {
  userId: string;
  confidence: "bot-filtered" | "same-code return" | "same-passkey return";
}

/* ---------------------------- Public API ---------------------------- */

/** Solve the bot-filter puzzle (PoW), then create an anonymous passkey account. */
export async function signUp(): Promise<Account> {
  const pow = await solvePow();
  const { flowId, options } = await post<{
    flowId: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>("/api/register/options", pow);
  const credential = await startRegistration({ optionsJSON: options });
  return post<Account>("/api/register/verify", { flowId, credential });
}

/** Return to an existing account with a passkey this browser can present
 *  (including passkeys synced from another device). Solves the bot-filter
 *  puzzle first — sign-in costs a puzzle too, so bots can't probe for free. */
export async function signIn(): Promise<Account> {
  const pow = await solvePow();
  const { flowId, options } = await post<{
    flowId: string;
    options: PublicKeyCredentialRequestOptionsJSON;
  }>("/api/login/options", pow);
  const credential = await startAuthentication({ optionsJSON: options });
  return post<Account>("/api/login/verify", { flowId, credential });
}

/** Solve the bot-filter puzzle (PoW), then create an account unlocked by a copyable code.
 *  The code is returned exactly once — the user must save it somewhere. */
export async function signUpWithCode(): Promise<Account & { code: string }> {
  const pow = await solvePow();
  return post<Account & { code: string }>("/api/code/register", pow);
}

/** Return to a code account by pasting the code saved at sign-up. */
export async function signInWithCode(code: string): Promise<Account> {
  const pow = await solvePow();
  return post<Account>("/api/code/login", { ...pow, code });
}

/** Solve the bot-filter puzzle (PoW), then start a guest account — usable
 *  only as long as the session cookie in this browser lasts. Nothing to
 *  save, nothing to come back to. */
export async function signUpAsGuest(): Promise<Account> {
  const pow = await solvePow();
  return post<Account>("/api/guest", pow);
}

/** Current session, or null if signed out. (The one API method that returns
 *  null instead of throwing — "no session" is an answer, not an error.) */
export async function whoAmI(): Promise<(Account & { createdAt: number }) | null> {
  const res = await fetch(`${base}/api/me`, { credentials: "include" });
  if (!res.ok) return null;
  return res.json() as Promise<Account & { createdAt: number }>;
}

export async function signOut(): Promise<void> {
  await post("/api/logout", {});
}
