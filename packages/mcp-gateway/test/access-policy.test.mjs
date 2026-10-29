import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, rmSync, readFileSync, writeFileSync, readdirSync, chmodSync, renameSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initializeAccessPolicy, openAccessPolicy } from "../dist/access-policy.js";

const issuer = "http://127.0.0.1:8788/realms/test";
const a = { issuer, subject: "alice", clientId: "native", bindingId: "analyst", tokenId: "ticket-1" };
function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-policy-")));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 10 }));
  const directory = join(root, "policy");
  return { directory, root, policy: initializeAccessPolicy({ directory, issuer, bindings: [{ bindingId: a.bindingId, subject: a.subject, clientId: a.clientId }] }) };
}
test("binding denial survives reopening and applies to renewed tokens", (t) => {
  const f = fixture(t);
  assert(f.policy.isActive(a));
  f.policy.revokeBinding(a.bindingId);
  f.policy.revokeBinding(a.bindingId);
  assert(!f.policy.isActive(a));
  assert(!openAccessPolicy(f).isActive({ ...a, tokenId: "renewed" }));
});
test("token denial is exact, durable and does not remove binding denial", (t) => {
  const f = fixture(t);
  f.policy.revokeToken(a);
  assert(!openAccessPolicy(f).isActive(a));
  assert(f.policy.isActive({ ...a, tokenId: "new" }));
  f.policy.revokeBinding(a.bindingId);
  assert(!f.policy.isActive({ ...a, tokenId: "new" }));
});
test("identity mismatch never creates authority", (t) => {
  const f = fixture(t);
  for (const k of ["issuer", "subject", "clientId", "bindingId"]) assert(!f.policy.isActive({ ...a, [k]: "other" }));
  assert(!f.policy.isActive({ ...a, extra: true }));
  assert.throws(() => f.policy.revokeToken({ ...a, subject: "other" }));
});
test("missing or edited policy fails closed without auto-creation", (t) => {
  const f = fixture(t), p = join(f.directory, "policy.json"), old = readFileSync(p);
  writeFileSync(p, old.toString().replace("alice", "mallory"));
  assert(!f.policy.isActive(a));
  assert.throws(() => f.policy.revokeBinding(a.bindingId));
  rmSync(p);
  assert(!f.policy.isActive(a));
  assert.throws(() => openAccessPolicy(f));
});
test("corrupt or public denial record fails closed", (t) => {
  const f = fixture(t);
  f.policy.revokeToken(a);
  const p = join(f.directory, readdirSync(f.directory).find((n) => n.startsWith("token-")));
  writeFileSync(p, "{}");
  assert(!f.policy.isActive(a));
  chmodSync(p, 0o644);
  assert(!f.policy.isActive(a));
});
test("directory replacement and symlink substitution fail closed", (t) => {
  const f = fixture(t);
  renameSync(f.directory, f.directory + "-old");
  mkdirSync(f.directory, { mode: 0o700 });
  assert(!f.policy.isActive(a));
  rmSync(f.directory, { recursive: true });
  symlinkSync(f.directory + "-old", f.directory);
  assert(!f.policy.isActive(a));
});
test("opening missing state and initializing an existing directory refuse", (t) => {
  const f = fixture(t);
  assert.throws(() => openAccessPolicy({ directory: join(f.root, "absent") }));
  assert.throws(() => initializeAccessPolicy({ directory: f.directory, issuer, bindings: [{ bindingId: "x", subject: "u", clientId: "c" }] }));
  assert(f.policy.isActive(a));
});
test("malformed selected denial never restores access", (t) => {
  const f = fixture(t);
  f.policy.revokeBinding(a.bindingId);
  const p = join(f.directory, readdirSync(f.directory).find((n) => n.startsWith("binding-")));
  writeFileSync(p, "not-json");
  assert(!f.policy.isActive(a));
  assert.throws(() => f.policy.revokeBinding(a.bindingId));
});
