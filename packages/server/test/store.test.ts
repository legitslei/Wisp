import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";
import { createFileStore } from "../src/store.js";

const dir = mkdtempSync(join(tmpdir(), "wisp-store-test-"));
after(() => rmSync(dir, { recursive: true, force: true }));

function tempPath(name: string): string {
  return join(dir, `${name}.json`);
}

test("createUser then getUser roundtrips, including the method field", async () => {
  const store = createFileStore(tempPath("users"));
  const user = { id: "user-1", createdAt: 1234, method: "code" } as const;
  await store.createUser(user);
  assert.deepEqual(await store.getUser("user-1"), user);
  assert.equal(await store.getUser("nobody"), undefined);
});

test("addCredential then getCredential roundtrips", async () => {
  const store = createFileStore(tempPath("credentials"));
  const credential = {
    credentialId: "cred-1",
    publicKey: "cGstYnl0ZXM",
    counter: 0,
    transports: ["usb" as const],
    userId: "user-1",
    createdAt: 1234,
  };
  await store.addCredential(credential);
  assert.deepEqual(await store.getCredential("cred-1"), credential);
  assert.equal(await store.getCredential("nobody"), undefined);
});

test("addAccountCode then getAccountCode roundtrips", async () => {
  const store = createFileStore(tempPath("codes"));
  const code = { codeHash: "hash-1", createdAt: 1234, userId: "user-1" };
  await store.addAccountCode(code);
  assert.deepEqual(await store.getAccountCode("hash-1"), code);
  assert.equal(await store.getAccountCode("nobody"), undefined);
});

test("updateCounter persists across a reopen", async () => {
  const path = tempPath("counter");
  const store = createFileStore(path);
  await store.addCredential({
    credentialId: "cred-1",
    publicKey: "cGstYnl0ZXM",
    counter: 0,
    userId: "user-1",
    createdAt: 1234,
  });
  await store.updateCounter("cred-1", 7);
  await store.updateCounter("missing", 99); // no-op, must not throw
  const reopened = createFileStore(path);
  const credential = await reopened.getCredential("cred-1");
  assert.equal(credential?.counter, 7);
});

test("a second store at the same path sees prior writes", async () => {
  const path = tempPath("persistence");
  const first = createFileStore(path);
  await first.createUser({ id: "user-1", createdAt: 1234, method: "guest" });
  const second = createFileStore(path);
  assert.deepEqual(await second.getUser("user-1"), {
    id: "user-1",
    createdAt: 1234,
    method: "guest",
  });
});

test("a missing file boots empty", async () => {
  const store = createFileStore(tempPath("missing"));
  assert.equal(await store.getUser("anyone"), undefined);
});

test("a corrupt JSON file boots empty and the store stays usable", async () => {
  const path = tempPath("corrupt");
  writeFileSync(path, "{not json at all");
  const store = createFileStore(path);
  assert.equal(await store.getUser("anyone"), undefined);
  await store.createUser({ id: "user-1", createdAt: 1234, method: "guest" });
  assert.notEqual(await store.getUser("user-1"), undefined);
});

test("a file missing the codes section still works", async () => {
  const path = tempPath("no-codes");
  const saved = {
    users: { "user-1": { id: "user-1", createdAt: 1234 } },
    credentials: {},
  };
  writeFileSync(path, JSON.stringify(saved));
  const store = createFileStore(path);
  assert.notEqual(await store.getUser("user-1"), undefined);
  assert.equal(await store.getAccountCode("anything"), undefined);
  await store.addAccountCode({ codeHash: "hash-1", createdAt: 1234, userId: "user-1" });
  assert.notEqual(await store.getAccountCode("hash-1"), undefined);
});

test("a saved __proto__ key cannot pollute Object.prototype", async () => {
  const path = tempPath("proto");
  writeFileSync(path, '{"users": {"__proto__": {"polluted": true}}}');
  const store = createFileStore(path);
  assert.equal(Object.getOwnPropertyDescriptor(Object.prototype, "polluted"), undefined);
  const probe = {};
  assert.equal("polluted" in probe, false);
  // The crafted key may resolve as an own property, but never to the prototype.
  const lookedUp = await store.getUser("__proto__");
  assert.notEqual(lookedUp, Object.prototype);
  assert.equal(await store.getUser("anyone-else"), undefined);
});
