import { readFileSync, renameSync, writeFileSync } from "node:fs";
import type { AuthenticatorTransportFuture } from "@simplewebauthn/server";

/** (Re-export when another file actually imports it.) */
interface User {
  id: string;
  createdAt: number;
  /** How the account was created. Accounts saved before this field existed
   *  are passkey accounts — readers treat `undefined` as "passkey". */
  method?: "code" | "guest" | "passkey";
}

/** (Re-export when another file actually imports it.) */
interface AccountCode {
  /** base64url SHA-256 of the code — the plaintext code is never stored */
  codeHash: string;
  createdAt: number;
  userId: string;
}

export interface Credential {
  /** base64url credential ID, as WebAuthn reports it */
  credentialId: string;
  /** base64url-encoded COSE public key */
  publicKey: string;
  counter: number;
  transports?: AuthenticatorTransportFuture[];
  userId: string;
  createdAt: number;
}

/** The database seam: swap this interface's implementation to move to
 *  SQLite/Postgres later. app.ts consumes it, so any adapter drops in. */
export interface Store {
  addAccountCode(code: AccountCode): Promise<void>;
  addCredential(cred: Credential): Promise<void>;
  createUser(user: User): Promise<void>;
  getAccountCode(codeHash: string): Promise<AccountCode | undefined>;
  getCredential(credentialId: string): Promise<Credential | undefined>;
  getUser(id: string): Promise<User | undefined>;
  updateCounter(credentialId: string, counter: number): Promise<void>;
}

interface Data {
  codes: Record<string, AccountCode>;
  credentials: Record<string, Credential>;
  users: Record<string, User>;
}

/** Zero-dependency JSON-file store. Fine for the demo and small sites;
 *  the Store interface is the seam for a real database adapter. */
export function createFileStore(path: string): Store {
  const data = loadData(path);

  function persist() {
    const tmp = `${path}.tmp`;
    // 0o600: owner-only on POSIX hosts (Windows ignores the mode).
    writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
    renameSync(tmp, path); // atomic-ish: no torn files on crash
  }

  return {
    async addAccountCode(code) {
      data.codes[code.codeHash] = code;
      persist();
    },
    async addCredential(cred) {
      data.credentials[cred.credentialId] = cred;
      persist();
    },
    async createUser(user) {
      data.users[user.id] = user;
      persist();
    },
    async getAccountCode(codeHash) {
      return data.codes[codeHash];
    },
    async getCredential(credentialId) {
      return data.credentials[credentialId];
    },
    async getUser(id) {
      return data.users[id];
    },
    async updateCounter(credentialId, counter) {
      const cred = data.credentials[credentialId];
      if (!cred) return;
      cred.counter = counter;
      persist();
    },
  };
}

// Tolerating a missing/corrupt DB file on first boot is the sanctioned
// try/catch case (docs/rules/typescript.md → Avoid Try / Catch).
// Normalizing fills in sections added after a data file was first written.
function loadData(path: string): Data {
  const saved = readSavedData(path);
  return {
    codes: cleanRecord(saved.codes),
    credentials: cleanRecord(saved.credentials),
    users: cleanRecord(saved.users),
  };
}

/** Null-prototype copy, so a crafted lookup key (e.g. "__proto__", which is
 *  valid base64url and could arrive as a WebAuthn credential ID) can only
 *  ever be an own property — never a prototype write. */
function cleanRecord<T>(saved: Record<string, T> | undefined): Record<string, T> {
  return Object.assign(Object.create(null), saved);
}

function readSavedData(path: string): Partial<Data> {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return {};
  }
}
