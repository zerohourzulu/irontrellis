/**
 * Host-owned access policy for authenticated callers: approved
 * issuer/subject/client/binding assignments recorded once, plus durable
 * denial records. No grant, un-revoke, restore or network access. The
 * synchronous `isActive` callback fails closed on any missing, changed or
 * unreadable state.
 */
import { lstatSync, mkdirSync, readdirSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { check, codeOf, data, durableCreate, exact, hash, id, privateDirectory, readPrivate, same, type Json } from "./data.ts";

export type AccessBinding = Readonly<{ bindingId: string; subject: string; clientId: string }>;
export type AccessIdentity = Readonly<{ issuer: string; subject: string; clientId: string; bindingId: string; tokenId: string }>;
export type AccessPolicyDefinition = Readonly<{ version: 1; issuer: string; bindings: readonly AccessBinding[] }>;
export interface AccessPolicy {
  /** True only for an approved, undenied identity; any failure answers false. */
  isActive(identity: unknown): boolean;
  /** Deny every token for one assignment; a refreshed login cannot undo it. */
  revokeBinding(bindingId: string): void;
  /** Deny one exact issuer/subject/client/binding/token tuple. */
  revokeToken(identity: unknown): void;
}

/** An https issuer URL (an explicit `http://127.0.0.1` issuer is accepted only for isolated tests). */
export function issuerUrl(value: string, allowTestIssuer = false): string {
  const url = new URL(value);
  check(url.href === value && !url.username && !url.password && !url.search && !url.hash, "INVALID_INPUT");
  check(url.protocol === "https:" || (allowTestIssuer && url.protocol === "http:" && url.hostname === "127.0.0.1"), "INVALID_INPUT");
  return value;
}
function assignment(raw: unknown): AccessBinding {
  const v = exact(data(raw), ["bindingId", "subject", "clientId"]);
  for (const value of Object.values(v)) id(value);
  return v as unknown as AccessBinding;
}
function definition(raw: unknown): AccessPolicyDefinition {
  const v = exact(data(raw), ["version", "issuer", "bindings"]);
  check(v.version === 1);
  issuerUrl(v.issuer as string, true);
  check(Array.isArray(v.bindings) && v.bindings.length > 0 && v.bindings.length <= 16);
  const bindings = (v.bindings as unknown[]).map(assignment);
  check(new Set(bindings.map((b) => b.bindingId)).size === bindings.length);
  return v as unknown as AccessPolicyDefinition;
}

/** Create a new private, deny-only policy. Never opens or overwrites an existing directory. */
export function initializeAccessPolicy(input: Readonly<{ directory: string; issuer: string; bindings: readonly AccessBinding[] }>): AccessPolicy {
  const policy = definition({ version: 1, issuer: input.issuer, bindings: input.bindings }), path = resolve(input.directory);
  check(realpathSync(dirname(path)) === dirname(path), "STORAGE_UNAVAILABLE");
  privateDirectory(dirname(path));
  mkdirSync(path, { mode: 0o700 });
  durableCreate(join(path, "policy.json"), policy);
  return openAccessPolicy({ directory: path });
}

/** Open existing host-owned policy state. */
export function openAccessPolicy(input: Readonly<{ directory: string }>): AccessPolicy {
  const path = privateDirectory(input.directory), stat = lstatSync(path);
  const policy = definition(readPrivate(join(path, "policy.json"))), fingerprint = hash(policy);
  const bindings = new Map(policy.bindings.map((b) => [b.bindingId, b]));
  const current = (): void => {
    privateDirectory(path);
    const now = lstatSync(path);
    check(now.dev === stat.dev && now.ino === stat.ino, "STORAGE_UNAVAILABLE");
    check(hash(definition(readPrivate(join(path, "policy.json")))) === fingerprint, "STORAGE_UNAVAILABLE");
  };
  const identity = (raw: unknown): AccessIdentity => {
    const v = exact(data(raw), ["issuer", "subject", "clientId", "bindingId", "tokenId"]);
    for (const k of ["subject", "clientId", "bindingId", "tokenId"]) id(v[k]);
    check(v.issuer === policy.issuer, "ACCESS_NOT_CURRENT");
    const b = bindings.get(v.bindingId as string);
    check(b !== undefined && b.subject === v.subject && b.clientId === v.clientId, "ACCESS_NOT_CURRENT");
    return v as unknown as AccessIdentity;
  };
  const record = (kind: string, value: unknown): Json => ({ version: 1, policy: fingerprint, kind, value });
  const file = (kind: string, value: unknown): string => join(path, kind + "-" + hash(value) + ".json");
  const denied = (kind: string, value: unknown): boolean => {
    let found: unknown;
    try { found = readPrivate(file(kind, value)); } catch (error) { if (codeOf(error) === "ENOENT") return false; throw error; }
    check(same(found, record(kind, value)), "STORAGE_UNAVAILABLE");
    return true;
  };
  const revoke = (kind: string, value: unknown): void => {
    current();
    if (denied(kind, value)) return;
    // Operator calls are serialized. Exhaustion refuses; denial records are never pruned.
    check(readdirSync(path).length < 1025, "POLICY_CAPACITY_EXHAUSTED");
    try { durableCreate(file(kind, value), record(kind, value)); } catch (error) { if (codeOf(error) !== "EEXIST" || !denied(kind, value)) throw error; }
  };
  const policyHandle: AccessPolicy = {
    isActive(raw) {
      try { current(); const v = identity(raw); const active = !denied("binding", v.bindingId) && !denied("token", v); current(); return active; } catch { return false; }
    },
    revokeBinding(bindingId) { id(bindingId); check(bindings.has(bindingId)); revoke("binding", bindingId); },
    revokeToken(raw) { revoke("token", identity(raw)); },
  };
  return Object.freeze(policyHandle);
}
