#!/usr/bin/env node
/**
 * `irontrellis-evidence-setup /absolute/new/directory`: a fresh synthetic
 * case (format-2 history, one agent with a role tenure, an admitted runtime
 * with a disposable Ed25519 key, one grant, one selected input file) and its
 * private configuration. Refuses to overwrite an existing directory.
 */
import { mkdirSync, readFileSync, writeFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { isEntryPoint } from "./entry.ts";
import { createLocalDomain, createLocalOwner, generateKeyPair, selectEvidence, type LocalOwner } from "@ramex-labs/irontrellis";

export const HOUR = 3600_000;
const packageVersion = (): string => {
  try { return (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version; } catch { return "0.0.0"; }
};
export type Demo = Readonly<{ configFile: string; config: Readonly<Record<string, unknown>>; ownerConfig: Readonly<Record<string, unknown>>; owner: LocalOwner; privateKey: string }>;

export async function createDemo(target: string): Promise<Demo> {
  mkdirSync(resolve(target), { mode: 0o700 });
  const dir = realpathSync(target), inputDirectory = join(dir, "source"), outputDirectory = join(dir, "packets");
  mkdirSync(inputDirectory, { mode: 0o700 });
  mkdirSync(outputDirectory, { mode: 0o700 });
  writeFileSync(join(inputDirectory, "incident.txt"), "Synthetic example: unusual access requires review.\n", { mode: 0o600 });
  const pair = generateKeyPair("ed25519", "key:bea"), keyFile = join(dir, "runtime.key");
  writeFileSync(keyFile, pair.privateKey + "\n", { mode: 0o600 });
  const ownerConfig = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator" };
  const owner = await createLocalOwner({ ...ownerConfig, now: Date.now });
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "first-shift", number: 1 });
  await owner.admitRuntime({ session: "session:bea", agent: "bea", epoch: 1, key: "key:bea", credential: pair.credential, expiresAt: Date.now() + HOUR });
  await owner.grant({ id: "collect", to: "bea", actions: ["collect-evidence-packet"], resources: ["incident:42"], expiresAt: Date.now() + HOUR });
  const config = {
    ...ownerConfig, session: "session:bea", role: "reviewer", tenure: "first-shift", resource: "incident:42", inputDirectory, outputDirectory, selection: selectEvidence(inputDirectory), keyFile,
  };
  const configFile = join(dir, "gateway.json");
  writeFileSync(configFile, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  return { configFile, config, ownerConfig, owner, privateKey: pair.privateKey };
}

const USAGE = `◆ IronTrellis evidence setup

Usage: irontrellis-evidence-setup /absolute/new-directory
       irontrellis-evidence-setup --help | --version

Creates a fresh synthetic case in a new directory (its parent must exist): a
format-2 history, one agent with a role tenure and an admitted runtime session
(disposable Ed25519 key), one grant, one input file and gateway.json. It never
overwrites. Then: irontrellis-evidence-demo <new-directory>/gateway.json

A refusal is one JSON line on stderr, exit code 2: {"status":"REFUSED","reason":<CODE>,"detail":<why>}
`;
const SETUP_ERRORS: Readonly<Record<string, readonly [string, string]>> = {
  EEXIST: ["TARGET_EXISTS", "already exists; setup never overwrites, choose a new directory"],
  ENOENT: ["TARGET_PARENT_MISSING", "cannot be created because its parent directory does not exist"],
  ENOTDIR: ["TARGET_PARENT_MISSING", "cannot be created because a component of its path is not a directory"],
  EACCES: ["TARGET_NOT_WRITABLE", "cannot be created: permission denied"],
  EROFS: ["TARGET_NOT_WRITABLE", "cannot be created: read-only file system"],
};
const refuse = (reason: string, detail: string, usage = false): void => {
  if (usage) process.stderr.write(USAGE);
  process.stderr.write(JSON.stringify({ status: "REFUSED", reason, detail }) + "\n");
  process.exitCode = 2;
};

/** The `irontrellis-evidence-setup` command line. Called without `await` below, so this module (and the package index) has no top-level await and `require()` of the package works. */
async function cli(args: readonly string[]): Promise<void> {
  if (args.some((a) => a === "--help" || a === "-h" || a === "help")) process.stdout.write(USAGE);
  else if (args.length === 1 && args[0] === "--version") process.stdout.write(`irontrellis-evidence-setup ${packageVersion()}\n`);
  else if (args.length !== 1) refuse("USAGE", args.length === 0 ? "missing the directory to create" : "expected exactly one directory", true);
  else if (args[0]!.startsWith("-")) refuse("USAGE", `unknown option ${JSON.stringify(args[0]!.slice(0, 64))}`, true);
  else {
    const target = resolve(args[0]!);
    try {
      const demo = await createDemo(target);
      console.log("Fresh synthetic case created. Keep this directory private.");
      console.log("Configuration:", demo.configFile);
    } catch (error) {
      const code = typeof (error as { code?: unknown })?.code === "string" ? (error as { code: string }).code : undefined;
      const known = code === undefined ? undefined : SETUP_ERRORS[code];
      refuse(known?.[0] ?? "SETUP_FAILED", `${target} ${known?.[1] ?? (error instanceof Error ? error.message.slice(0, 200) : "could not be set up")}`);
    }
  }
}
if (isEntryPoint(import.meta.url)) void cli(process.argv.slice(2));
