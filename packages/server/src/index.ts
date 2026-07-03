import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { DB_PATH, ORIGIN, PORT } from "./config.js";
import { createFileStore } from "./store.js";

// The cookie's Secure flag follows ORIGIN (app.ts → setSession), so a
// production deploy that forgets WISP_ORIGIN would silently send the
// session cookie over plaintext HTTP. Warn loudly; localhost dev is fine.
if (!ORIGIN.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)([:/]|$)/.test(ORIGIN))
  console.warn(
    `WARNING: WISP_ORIGIN (${ORIGIN}) is not HTTPS — the session cookie will be sent without its Secure flag. Set WISP_ORIGIN to your https:// URL in production.`,
  );

serve({ fetch: createApp(createFileStore(DB_PATH)).fetch, port: PORT });
console.log(`Wisp demo → http://localhost:${PORT}`);
