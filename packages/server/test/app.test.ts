import assert from "node:assert/strict";
import test from "node:test";
import type { Hono } from "hono";
import { createApp } from "../src/app.js";
import { signSession } from "../src/session.js";
import type { Credential, Store } from "../src/store.js";
import { prop, readJson, solvePow } from "./helpers.js";

/* store.ts only exports the Credential and Store types; recover the other
 * method-parameter shapes from the interface instead of duplicating them. */
type StoredAccountCode = Parameters<Store["addAccountCode"]>[0];
type StoredUser = Parameters<Store["createUser"]>[0];

const CODE_SHAPE = /^wisp(-[a-z2-9]{4}){6}$/;

/** Throwaway in-memory Store — the seam createApp is designed around. */
function createMemoryStore(): Store {
  const codes = new Map<string, StoredAccountCode>();
  const credentials = new Map<string, Credential>();
  const users = new Map<string, StoredUser>();
  return {
    async addAccountCode(code) {
      codes.set(code.codeHash, code);
    },
    async addCredential(cred) {
      credentials.set(cred.credentialId, cred);
    },
    async createUser(user) {
      users.set(user.id, user);
    },
    async getAccountCode(codeHash) {
      return codes.get(codeHash);
    },
    async getCredential(credentialId) {
      return credentials.get(credentialId);
    },
    async getUser(id) {
      return users.get(id);
    },
    async updateCounter(credentialId, counter) {
      const cred = credentials.get(credentialId);
      if (cred) credentials.set(credentialId, { ...cred, counter });
    },
  };
}

async function solvedPow(app: Hono): Promise<{ challenge: string; nonce: string }> {
  const body = await readJson(await app.request("/api/pow"));
  const challenge = body.challenge;
  const difficulty = body.difficulty;
  if (typeof challenge !== "string" || typeof difficulty !== "number")
    throw new Error("unexpected /api/pow response shape");
  return { challenge, nonce: solvePow(challenge, difficulty) };
}

async function postJson(app: Hono, path: string, body: unknown): Promise<Response> {
  return await app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function cookiePair(res: Response): string {
  const setCookie = res.headers.get("set-cookie");
  const pair = setCookie?.split(";")[0];
  if (!pair) throw new Error("expected a set-cookie header");
  return pair;
}

test("POST /api/guest without a body fails the proof-of-work gate", async () => {
  const app = createApp(createMemoryStore());
  const res = await app.request("/api/guest", { method: "POST" });
  assert.equal(res.status, 400);
  assert.equal((await readJson(res)).error, "proof-of-work failed");
});

test("guest sign-up sets a session cookie that /api/me accepts", async () => {
  const app = createApp(createMemoryStore());
  const res = await postJson(app, "/api/guest", await solvedPow(app));
  assert.equal(res.status, 200);
  assert.equal((await readJson(res)).confidence, "bot-filtered");
  const setCookie = res.headers.get("set-cookie");
  if (!setCookie) throw new Error("expected a set-cookie header");
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Lax/);

  const meRes = await app.request("/api/me", { headers: { cookie: cookiePair(res) } });
  assert.equal(meRes.status, 200);
  assert.equal((await readJson(meRes)).confidence, "bot-filtered");
});

test("code register then login with a mangled paste returns the same user", async () => {
  const app = createApp(createMemoryStore());
  const registerRes = await postJson(app, "/api/code/register", await solvedPow(app));
  assert.equal(registerRes.status, 200);
  const registerBody = await readJson(registerRes);
  const code = registerBody.code;
  if (typeof code !== "string") throw new Error("expected a code string");
  assert.match(code, CODE_SHAPE);
  assert.equal(typeof registerBody.userId, "string");

  const loginRes = await postJson(app, "/api/code/login", {
    ...(await solvedPow(app)),
    code: `  ${code.toUpperCase()}  `,
  });
  assert.equal(loginRes.status, 200);
  const loginBody = await readJson(loginRes);
  assert.equal(loginBody.confidence, "same-code return");
  assert.equal(loginBody.userId, registerBody.userId);
});

test("code login with an unknown but well-formed code fails", async () => {
  const app = createApp(createMemoryStore());
  const res = await postJson(app, "/api/code/login", {
    ...(await solvedPow(app)),
    code: "wisp-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa",
  });
  assert.equal(res.status, 400);
  assert.equal((await readJson(res)).error, "unknown code");
});

test("code login with a malformed code fails", async () => {
  const app = createApp(createMemoryStore());
  const res = await postJson(app, "/api/code/login", {
    ...(await solvedPow(app)),
    code: "not-a-code",
  });
  assert.equal(res.status, 400);
  assert.equal((await readJson(res)).error, "malformed code");
});

test("POST /api/login/options without proof-of-work is rejected", async () => {
  // Explicit security gate: starting a login flow allocates pending state,
  // so it must cost the caller a puzzle.
  const app = createApp(createMemoryStore());
  const res = await app.request("/api/login/options", { method: "POST" });
  assert.equal(res.status, 400);
  assert.equal((await readJson(res)).error, "proof-of-work failed");
});

test("POST /api/login/options with solved proof-of-work issues a flow", async () => {
  const app = createApp(createMemoryStore());
  const res = await postJson(app, "/api/login/options", await solvedPow(app));
  assert.equal(res.status, 200);
  const body = await readJson(res);
  assert.equal(typeof body.flowId, "string");
  assert.equal(typeof prop(body.options, "challenge"), "string");
  // Soft preference for the built-in authenticator — a refactor that drops it
  // would silently revert browsers to offering roaming provider apps first.
  assert.deepEqual(prop(body.options, "hints"), ["client-device"]);
});

test("POST /api/login/verify with an unknown flowId is rejected", async () => {
  const app = createApp(createMemoryStore());
  const res = await postJson(app, "/api/login/verify", { flowId: "nope", credential: {} });
  assert.equal(res.status, 400);
  assert.equal((await readJson(res)).error, "flow expired, try again");
});

test("POST /api/register/options without proof-of-work is rejected", async () => {
  const app = createApp(createMemoryStore());
  const res = await app.request("/api/register/options", { method: "POST" });
  assert.equal(res.status, 400);
  assert.equal((await readJson(res)).error, "proof-of-work failed");
});

test("POST /api/register/options with solved proof-of-work issues a flow", async () => {
  const app = createApp(createMemoryStore());
  const res = await postJson(app, "/api/register/options", await solvedPow(app));
  assert.equal(res.status, 200);
  const body = await readJson(res);
  assert.equal(typeof body.flowId, "string");
  assert.equal(typeof prop(body.options, "challenge"), "string");
  // Same soft built-in-authenticator preference as login/options.
  assert.deepEqual(prop(body.options, "hints"), ["client-device"]);
});

test("register/verify rejects bad credentials without leaking internals", async () => {
  const app = createApp(createMemoryStore());

  async function startFlow(): Promise<unknown> {
    const res = await postJson(app, "/api/register/options", await solvedPow(app));
    assert.equal(res.status, 200);
    return (await readJson(res)).flowId;
  }

  const malformedRes = await postJson(app, "/api/register/verify", {
    flowId: await startFlow(),
    credential: "not-an-object",
  });
  assert.equal(malformedRes.status, 400);
  assert.equal((await readJson(malformedRes)).error, "malformed credential");

  const garbageRes = await postJson(app, "/api/register/verify", {
    flowId: await startFlow(),
    credential: { id: "x", rawId: "x", type: "public-key", response: {} },
  });
  assert.equal(garbageRes.status, 400);
  const error = (await readJson(garbageRes)).error;
  if (typeof error !== "string") throw new Error("expected an error string");
  assert.equal(error, "verification failed");
  // The library's own messages can name expected origins/RP IDs — none of
  // that internal state may reach the client.
  assert.equal(error.includes("expected"), false);
  assert.equal(error.includes("origin"), false);
});

test("GET /api/me without a cookie is a 401", async () => {
  const app = createApp(createMemoryStore());
  const res = await app.request("/api/me");
  assert.equal(res.status, 401);
});

test("/api/me labels confidence by the account's method", async () => {
  const store = createMemoryStore();
  const app = createApp(store);
  await store.createUser({ id: "passkey-user", createdAt: 1234, method: "passkey" });
  await store.createUser({ id: "guest-user", createdAt: 1234, method: "guest" });
  await store.createUser({ id: "legacy-user", createdAt: 1234 }); // pre-method account

  async function confidenceFor(userId: string): Promise<unknown> {
    const cookie = `wisp_session=${signSession(userId)}`;
    const res = await app.request("/api/me", { headers: { cookie } });
    assert.equal(res.status, 200);
    return (await readJson(res)).confidence;
  }

  assert.equal(await confidenceFor("passkey-user"), "same-passkey return");
  assert.equal(await confidenceFor("guest-user"), "bot-filtered");
  assert.equal(await confidenceFor("legacy-user"), "same-passkey return");
});

test("POST /api/logout clears the session cookie", async () => {
  const app = createApp(createMemoryStore());
  const res = await app.request("/api/logout", { method: "POST" });
  assert.equal(res.status, 200);
  const setCookie = res.headers.get("set-cookie");
  if (!setCookie) throw new Error("expected a set-cookie header");
  assert.match(setCookie, /wisp_session=;|Max-Age=0/);
});

test("an oversized body is rejected with 413", async () => {
  const app = createApp(createMemoryStore());
  const res = await postJson(app, "/api/guest", { challenge: "x".repeat(64 * 1024), nonce: "0" });
  assert.equal(res.status, 413);
});
