// A flag before the command keeps its own value: removing the command words must not let it take a `true`/`false` that
// follows them (fuzz/targets/cli-args.mjs, VAST-FUZZ-01 F1: `--json status false` printed the human status with exit 0).
// Build first (`pnpm build`).
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BIN = resolve(fileURLToPath(new URL(".", import.meta.url)), "../bin/irontrellis.mjs");
const run = (args, env) => spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1", ...env } });
const parsed = (r) => { try { return JSON.parse(r.stdout); } catch (error) { assert.fail(`not one JSON document (${error.message}):\n${r.stdout}\n${r.stderr}`); } };

test("--json before the command: a stray true/false after it is an unexpected argument, answered as JSON", (t) => {
  const dir = mkdtempSync(join(realpathSync(tmpdir()), "irontrellis-args-boundary-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const env = { IRONTRELLIS_HISTORY: join(dir, "h.jsonl") };
  assert.equal(run(["init", "--owner", "ops", "--controller", "op"], env).status, 0);
  for (const stray of ["false", "true"]) {
    const r = run(["--json", "status", stray], env);
    assert.notEqual(r.status, 0, `--json status ${stray} must not succeed`);
    const value = parsed(r);
    assert.match(value.error.message, new RegExp(`unexpected argument "${stray}"`));
  }
  for (const args of [["--json", "status"], ["status", "--json"], ["--no-color", "--json", "status"], ["--json", "--history", env.IRONTRELLIS_HISTORY, "status"]]) {
    const r = run(args, env);
    assert.equal(r.status, 0, args.join(" "));
    assert.equal(parsed(r).error, undefined, args.join(" "));
  }
  // There are no short forms (args.ts refuses every single-dash option), so `-j status false` cannot neighbour either.
  for (const short of ["-j", "-h"]) {
    const r = run([short, "status", "false"], env);
    assert.notEqual(r.status, 0, `${short} status false must not succeed`);
    assert.match(r.stderr + r.stdout, /short options are not supported/);
  }
  // Unchanged: an explicit value after the flag itself still applies.
  const off = run(["status", "--json", "false"], env);
  assert.equal(off.status, 0);
  assert.throws(() => JSON.parse(off.stdout));
});
