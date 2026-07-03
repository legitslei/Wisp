import { randomBytes, randomUUID } from "node:crypto";
import { serveStatic } from "@hono/node-server/serve-static";
import {
  type AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type RegistrationResponseJSON,
  type VerifiedAuthenticationResponse,
  type VerifiedRegistrationResponse,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { type Context, Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { generateAccountCode, hashAccountCode, normalizeAccountCode } from "./code.js";
import { MODES, ORIGIN, RP_ID, RP_NAME } from "./config.js";
import { issueChallenge, verifyPow } from "./pow.js";
import { SESSION_MAX_AGE_S, signSession, verifySession } from "./session.js";
import type { Credential, Store } from "./store.js";

/** API bodies are tiny (PoW fields + a WebAuthn response, a few KB at most);
 *  the cap stops free memory pressure from oversized POSTs. */
const MAX_BODY_BYTES = 32 * 1024;

/** Hard ceiling on concurrently pending WebAuthn flows — a flood past this
 *  gets "server busy" instead of growing the map without bound. */
const MAX_PENDING_FLOWS = 10_000;

/** Reads the JSON body as unknown (docs/rules/typescript.md — request bodies
 *  must be narrowed, never trusted as any). Malformed JSON degrades to null,
 *  which fails every downstream field check. */
async function readBody(c: Context): Promise<unknown> {
  return c.req.json().catch(() => null);
}

/** Pulls one field off an unknown body without widening the rest to any. */
function field(body: unknown, key: string): unknown {
  return typeof body === "object" && body !== null
    ? (body as Record<string, unknown>)[key]
    : undefined;
}

/** Builds the Hono app around any Store implementation — index.ts passes the
 *  FileStore; tests pass a throwaway one and drive routes via app.request(). */
export function createApp(store: Store): Hono {
  const app = new Hono();

  app.use("/api/*", bodyLimit({ maxSize: MAX_BODY_BYTES }));

  /* ------------------------------------------------------------------ */
  /* WebAuthn ceremonies are two-step; the expected challenge lives here  */
  /* between the "options" call and the "verify" call, keyed by a flowId. */
  /* ------------------------------------------------------------------ */
  const pendingChallenges = new Map<string, { challenge: string; expires: number }>();

  /** Returns the flowId, or undefined when the map is at capacity. */
  function rememberChallenge(challenge: string): string | undefined {
    const now = Date.now();
    for (const [key, entry] of pendingChallenges)
      if (entry.expires < now) pendingChallenges.delete(key);
    if (pendingChallenges.size >= MAX_PENDING_FLOWS) return undefined;
    const flowId = randomUUID();
    pendingChallenges.set(flowId, { challenge, expires: now + 5 * 60_000 });
    return flowId;
  }

  function takeChallenge(flowId: unknown): string | undefined {
    if (typeof flowId !== "string") return undefined;
    const entry = pendingChallenges.get(flowId);
    pendingChallenges.delete(flowId); // single use
    if (!entry || entry.expires < Date.now()) return undefined;
    return entry.challenge;
  }

  function setSession(c: Context, userId: string) {
    setCookie(c, "wisp_session", signSession(userId), {
      httpOnly: true,
      sameSite: "Lax",
      secure: ORIGIN.startsWith("https"),
      path: "/",
      maxAge: SESSION_MAX_AGE_S,
    });
  }

  /** Operators disable modes via WISP_MODES (config.ts). Returns the 404
   *  response to send when the mode is off, undefined when it's enabled. */
  function modeDisabled(c: Context, mode: "code" | "guest" | "passkey") {
    return MODES.has(mode) ? undefined : c.json({ error: `${mode} sign-up is disabled` }, 404);
  }

  /** The label reports the strength of the account's method, not of this
   *  session's sign-in event — a guest cookie never upgrades to a "return"
   *  claim (docs/rules/security.md). */
  function sessionConfidence(
    method: "code" | "guest" | "passkey",
  ): "bot-filtered" | "same-code return" | "same-passkey return" {
    if (method === "code") return "same-code return";
    if (method === "guest") return "bot-filtered";
    return "same-passkey return";
  }

  /* ---------------------------- Bot filter --------------------------- */

  app.get("/api/pow", (c) => c.json(issueChallenge()));

  /* ------------------------- Sign up: passkey ------------------------ */

  app.post("/api/register/options", async (c) => {
    const disabled = modeDisabled(c, "passkey");
    if (disabled) return disabled;
    const body = await readBody(c);
    if (!verifyPow(field(body, "challenge"), field(body, "nonce")))
      return c.json({ error: "proof-of-work failed" }, 400);

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      // Random handle — deliberately carries no identity.
      userName: `wisp-${randomBytes(4).toString("hex")}`,
      userDisplayName: "Anonymous account",
      attestationType: "none",
      // ES256 + RS256 only: Windows Hello's TPM can't store Ed25519 (-8)
      // and fails with "There was a problem saving your passkey" if offered it.
      supportedAlgorithmIDs: [-7, -257],
      authenticatorSelection: {
        residentKey: "required", // discoverable: enables usernameless return
        userVerification: "preferred",
      },
    });
    // Prefer the built-in device authenticator (Windows Hello, iCloud Keychain,
    // Android) over roaming provider apps like Microsoft Authenticator. Set the
    // raw WebAuthn hint on the returned options rather than the library's
    // `preferredAuthenticatorType` helper — that helper also pins
    // authenticatorAttachment: "platform", which would block phone-by-QR and
    // security-key registration and narrow the "wherever it syncs" promise.
    // Soft preference only: users can still pick "more options", and browsers
    // without hints support ignore it.
    options.hints = ["client-device"];

    const flowId = rememberChallenge(options.challenge);
    if (!flowId) return c.json({ error: "server busy, try again shortly" }, 503);
    return c.json({ flowId, options });
  });

  app.post("/api/register/verify", async (c) => {
    const disabled = modeDisabled(c, "passkey");
    if (disabled) return disabled;
    const body = await readBody(c);
    const expectedChallenge = takeChallenge(field(body, "flowId"));
    if (!expectedChallenge) return c.json({ error: "flow expired, try again" }, 400);

    const response = field(body, "credential");
    if (typeof response !== "object" || response === null)
      return c.json({ error: "malformed credential" }, 400);

    const verification = await runRegistrationVerification({
      expectedChallenge,
      // Boundary cast: SimpleWebAuthn shape-checks the response itself and
      // throws on mismatch (translated to a returned Error by the wrapper).
      response: response as RegistrationResponseJSON,
    });
    if (verification instanceof Error || !verification.verified || !verification.registrationInfo)
      return c.json({ error: "verification failed" }, 400);

    const { credential } = verification.registrationInfo;
    const userId = randomUUID();
    await store.createUser({ id: userId, createdAt: Date.now(), method: "passkey" });
    await store.addCredential({
      credentialId: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString("base64url"),
      counter: credential.counter,
      transports: credential.transports,
      userId,
      createdAt: Date.now(),
    });

    setSession(c, userId);
    return c.json({ userId, confidence: "bot-filtered" });
  });

  /* ---------------------- Sign up: account code ---------------------- */

  app.post("/api/code/register", async (c) => {
    const disabled = modeDisabled(c, "code");
    if (disabled) return disabled;
    const body = await readBody(c);
    if (!verifyPow(field(body, "challenge"), field(body, "nonce")))
      return c.json({ error: "proof-of-work failed" }, 400);

    const code = generateAccountCode();
    const userId = randomUUID();
    await store.createUser({ id: userId, createdAt: Date.now(), method: "code" });
    await store.addAccountCode({ codeHash: hashAccountCode(code), createdAt: Date.now(), userId });

    setSession(c, userId);
    // The plaintext code crosses the wire exactly once, here. Never log it.
    return c.json({ code, confidence: "bot-filtered", userId });
  });

  app.post("/api/code/login", async (c) => {
    const disabled = modeDisabled(c, "code");
    if (disabled) return disabled;
    const body = await readBody(c);
    // PoW-gated: every guess costs a puzzle solve — the identifier-free rate
    // limit this project allows (no IPs to key a conventional limiter on).
    if (!verifyPow(field(body, "challenge"), field(body, "nonce")))
      return c.json({ error: "proof-of-work failed" }, 400);

    const code = normalizeAccountCode(field(body, "code"));
    if (!code) return c.json({ error: "malformed code" }, 400);
    const known = await store.getAccountCode(hashAccountCode(code));
    if (!known) return c.json({ error: "unknown code" }, 400);

    setSession(c, known.userId);
    return c.json({ confidence: "same-code return", userId: known.userId });
  });

  /* ------------------------- Sign up: guest -------------------------- */

  app.post("/api/guest", async (c) => {
    const disabled = modeDisabled(c, "guest");
    if (disabled) return disabled;
    const body = await readBody(c);
    if (!verifyPow(field(body, "challenge"), field(body, "nonce")))
      return c.json({ error: "proof-of-work failed" }, 400);

    const userId = randomUUID();
    await store.createUser({ id: userId, createdAt: Date.now(), method: "guest" });
    setSession(c, userId);
    return c.json({ confidence: "bot-filtered", userId });
  });

  /* ------------------------ Return flow: passkey --------------------- */

  app.post("/api/login/options", async (c) => {
    const disabled = modeDisabled(c, "passkey");
    if (disabled) return disabled;
    const body = await readBody(c);
    // PoW-gated like every other flow-starting route: issuing a challenge
    // allocates pending-flow state, so it must cost the caller a puzzle.
    if (!verifyPow(field(body, "challenge"), field(body, "nonce")))
      return c.json({ error: "proof-of-work failed" }, 400);

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: "preferred",
      // No allowCredentials: the browser offers whatever passkey it holds.
    });
    // Same soft hint as registration — prefer the built-in device authenticator
    // first. See /api/register/options for why it's set here, not via the
    // library's attachment-pinning helper.
    options.hints = ["client-device"];
    const flowId = rememberChallenge(options.challenge);
    if (!flowId) return c.json({ error: "server busy, try again shortly" }, 503);
    return c.json({ flowId, options });
  });

  app.post("/api/login/verify", async (c) => {
    const disabled = modeDisabled(c, "passkey");
    if (disabled) return disabled;
    const body = await readBody(c);
    const expectedChallenge = takeChallenge(field(body, "flowId"));
    if (!expectedChallenge) return c.json({ error: "flow expired, try again" }, 400);

    const response = field(body, "credential");
    const credentialId = field(response, "id");
    const known =
      typeof credentialId === "string" ? await store.getCredential(credentialId) : undefined;
    if (!known) return c.json({ error: "unknown passkey" }, 400);

    const verification = await runAuthenticationVerification({
      expectedChallenge,
      known,
      // Boundary cast: SimpleWebAuthn shape-checks the response itself and
      // throws on mismatch (translated to a returned Error by the wrapper).
      response: response as AuthenticationResponseJSON,
    });
    if (verification instanceof Error || !verification.verified)
      return c.json({ error: "verification failed" }, 400);

    await store.updateCounter(known.credentialId, verification.authenticationInfo.newCounter);
    setSession(c, known.userId);
    return c.json({ userId: known.userId, confidence: "same-passkey return" });
  });

  /* ----------------------------- Session ----------------------------- */

  app.get("/api/me", async (c) => {
    const userId = verifySession(getCookie(c, "wisp_session"));
    const user = userId ? await store.getUser(userId) : undefined;
    if (!user) return c.json({ error: "no session" }, 401);
    return c.json({
      userId: user.id,
      createdAt: user.createdAt,
      confidence: sessionConfidence(user.method ?? "passkey"),
    });
  });

  app.post("/api/logout", (c) => {
    deleteCookie(c, "wisp_session", { path: "/" });
    return c.json({ ok: true });
  });

  /* ------------------------------ Demo ------------------------------- */

  app.use("/*", serveStatic({ root: "./apps/demo/public" }));

  return app;
}

/* SimpleWebAuthn's verify calls throw on malformed credentials; these
 * wrappers translate the throw into a returned Error so routes stay
 * const-only (docs/rules/typescript.md → Avoid Let / Avoid Try-Catch).
 * The Error is never echoed to the client — library messages can name
 * expected origins/RP IDs (docs/rules/security.md → no internal state). */

async function runRegistrationVerification(props: {
  expectedChallenge: string;
  response: RegistrationResponseJSON;
}): Promise<VerifiedRegistrationResponse | Error> {
  try {
    return await verifyRegistrationResponse({
      response: props.response,
      expectedChallenge: props.expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  }
}

async function runAuthenticationVerification(props: {
  expectedChallenge: string;
  known: Credential;
  response: AuthenticationResponseJSON;
}): Promise<VerifiedAuthenticationResponse | Error> {
  try {
    return await verifyAuthenticationResponse({
      response: props.response,
      expectedChallenge: props.expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: props.known.credentialId,
        publicKey: new Uint8Array(Buffer.from(props.known.publicKey, "base64url")),
        counter: props.known.counter,
        transports: props.known.transports,
      },
    });
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  }
}
