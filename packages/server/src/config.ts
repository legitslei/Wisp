import { randomBytes } from "node:crypto";

/** Read a WISP_* env var, falling back to the legacy PHANTOM_* name so
 *  deployments configured before the rename keep working unchanged.
 *  (The project was formerly "Phantom Sign Up".) */
function env(name: string): string | undefined {
  return process.env[`WISP_${name}`] ?? process.env[`PHANTOM_${name}`];
}

/** HMAC secret for PoW challenges and session cookies.
 *  Random per boot unless WISP_SECRET is set (set it in production,
 *  otherwise sessions and in-flight challenges die on restart). */
export const SECRET = env("SECRET") ?? randomBytes(32).toString("hex");

// RP_ID / ORIGIN fall back to the URL the host assigns (Render sets these
// automatically) before the localhost dev default, so a deploy needs no URL
// hardcoded. An explicit WISP_* value still wins — e.g. a custom domain.
export const RP_ID = env("RP_ID") ?? process.env.RENDER_EXTERNAL_HOSTNAME ?? "localhost";
export const ORIGIN = env("ORIGIN") ?? process.env.RENDER_EXTERNAL_URL ?? "http://localhost:8787";
export const PORT = Number(process.env.PORT ?? 8787);
export const DB_PATH = env("DB") ?? "./wisp-data.json";
export const RP_NAME = "Wisp";

/** Which sign-up modes the server exposes, e.g. WISP_MODES="passkey,code".
 *  All three ("code", "guest", "passkey") are on by default. */
export const MODES = new Set(
  (env("MODES") ?? "code,guest,passkey").split(",").map((mode) => mode.trim()),
);
