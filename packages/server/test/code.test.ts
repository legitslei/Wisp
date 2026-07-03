import assert from "node:assert/strict";
import test from "node:test";
import { generateAccountCode, hashAccountCode, normalizeAccountCode } from "../src/code.js";

const CODE_SHAPE = /^wisp(-[a-z2-9]{4}){6}$/;

test("generateAccountCode matches the issued shape and avoids lookalikes", () => {
  for (const _ of Array.from({ length: 50 })) {
    const code = generateAccountCode();
    assert.match(code, CODE_SHAPE);
    assert.doesNotMatch(code.slice("wisp".length), /[lo01]/);
  }
});

test("500 generated codes are all unique", () => {
  const codes = new Set(Array.from({ length: 500 }, () => generateAccountCode()));
  assert.equal(codes.size, 500);
});

test("normalizeAccountCode accepts uppercase, whitespace-padded input", () => {
  const code = generateAccountCode();
  assert.equal(normalizeAccountCode(`  \t${code.toUpperCase()} \n `), code);
});

test("normalizeAccountCode accepts the legacy phantom- prefix", () => {
  const legacy = generateAccountCode().replace(/^wisp/, "phantom");
  assert.equal(normalizeAccountCode(legacy.toUpperCase()), legacy);
});

test("normalizeAccountCode rejects wrong group counts", () => {
  const code = generateAccountCode();
  const fiveGroups = code.slice(0, code.lastIndexOf("-"));
  const sevenGroups = `${code}-abcd`;
  assert.equal(normalizeAccountCode(fiveGroups), undefined);
  assert.equal(normalizeAccountCode(sevenGroups), undefined);
});

test("normalizeAccountCode rejects characters outside the alphabet", () => {
  assert.equal(normalizeAccountCode("wisp-ab0d-abcd-abcd-abcd-abcd-abcd"), undefined);
  assert.equal(normalizeAccountCode("wisp-ab1d-abcd-abcd-abcd-abcd-abcd"), undefined);
  assert.equal(normalizeAccountCode("wisp-ab!d-abcd-abcd-abcd-abcd-abcd"), undefined);
});

test("normalizeAccountCode rejects non-string input through the unknown signature", () => {
  assert.equal(normalizeAccountCode(42), undefined);
  assert.equal(normalizeAccountCode({ code: generateAccountCode() }), undefined);
  assert.equal(normalizeAccountCode(undefined), undefined);
});

test("hashAccountCode is deterministic", () => {
  const code = generateAccountCode();
  assert.equal(hashAccountCode(code), hashAccountCode(code));
});

test("normalize-then-hash of a mangled paste equals the hash of the issued code", () => {
  const issued = generateAccountCode();
  const pasted = `   ${issued.toUpperCase()}\n`;
  const normalized = normalizeAccountCode(pasted);
  assert.notEqual(normalized, undefined);
  if (normalized === undefined) throw new Error("unreachable");
  assert.equal(hashAccountCode(normalized), hashAccountCode(issued));
});
