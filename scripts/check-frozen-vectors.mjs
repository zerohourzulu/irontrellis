#!/usr/bin/env node
/**
 * Frozen-vector gate: the conformance material we never edit is byte-identical to what was recorded.
 *
 *   node scripts/check-frozen-vectors.mjs          # exit 0 when every file matches, 1 otherwise
 *   node scripts/check-frozen-vectors.mjs --json   # the report as JSON
 *
 * Two hash lists, both in `sha256sum` format (so `sha256sum -c` works from their directory):
 *  - conformance/FROZEN.sha256     conformance/legacy (byte-frozen Continuity vectors and runner),
 *                                  conformance/v1 (the format-1 suite), conformance/inputs-ref
 *                                  (the two reference vectors from the frozen suites);
 *  - conformance/v2/FROZEN.sha256  conformance/v2 (the format-2 suite from the architect package).
 * Each list's own sha256 is pinned below, so a list cannot be edited to match a changed vector, and the v2
 * MANIFEST.json must have the sha256 the architect package's MANIFEST.json records for it. A file that is
 * missing, changed, or present in a frozen directory without being listed is a finding.
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const LISTS = [
  { list: "conformance/FROZEN.sha256", base: "conformance", dirs: ["legacy", "v1", "inputs-ref"], sha256: "501b196795fc2bacd7029a640fb3240aaefa3e4e91fcf1b9d66fac26c98d33ef" },
  { list: "conformance/v2/FROZEN.sha256", base: "conformance/v2", dirs: ["."], sha256: "158e500260b95bb056158a0ab566bade98aab42b29e300e00384ba6de9a097b0" },
];
/** Recorded in the architect package's MANIFEST.json for conformance/v2/MANIFEST.json. */
const PINNED = { "conformance/v2/MANIFEST.json": "948385f84bd830ddea8d972800a83bad4c03c9b04e28432b1f5b411febf43b42" };
/** Interpreter caches the Python runners may leave behind; never part of the frozen material. */
const IGNORED = (name) => name === "__pycache__" || name.endsWith(".pyc");

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const problems = [];
const counts = {};

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (IGNORED(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else yield path;
  }
}

for (const { list, base, dirs, sha256: listHash } of LISTS) {
  const listPath = join(ROOT, list);
  if (!existsSync(listPath)) { problems.push(`${list}: missing`); continue; }
  const actualListHash = sha256(listPath);
  if (actualListHash !== listHash) problems.push(`${list}: sha256 ${actualListHash}, pinned ${listHash} (the hash list itself changed)`);
  const listed = new Map();
  for (const [index, line] of readFileSync(listPath, "utf8").split("\n").entries()) {
    if (line === "") continue;
    const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
    if (match === null) { problems.push(`${list}:${index + 1}: malformed line`); continue; }
    listed.set(match[2], match[1]);
  }
  let ok = 0;
  for (const [path, hash] of listed) {
    const abs = join(ROOT, base, path);
    if (!existsSync(abs)) { problems.push(`MISSING    ${base}/${path}`); continue; }
    const actual = sha256(abs);
    if (actual !== hash) { problems.push(`MODIFIED   ${base}/${path}: sha256 ${actual}, recorded ${hash}`); continue; }
    ok += 1;
  }
  for (const dir of dirs) {
    const absDir = join(ROOT, base, dir);
    if (!existsSync(absDir)) { problems.push(`MISSING    ${base}/${dir}/`); continue; }
    for (const file of walk(absDir)) {
      const rel = relative(join(ROOT, base), file).split("\\").join("/");
      if (`${base}/${rel}` === list) continue;
      if (!listed.has(rel)) problems.push(`UNEXPECTED ${base}/${rel} (not in ${list})`);
    }
  }
  counts[list] = { files: listed.size, ok };
}

for (const [path, hash] of Object.entries(PINNED)) {
  const abs = join(ROOT, path);
  const actual = existsSync(abs) ? sha256(abs) : "missing";
  if (actual !== hash) problems.push(`PINNED     ${path}: sha256 ${actual}, architect MANIFEST.json records ${hash}`);
}

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ counts, problems }, null, 2));
} else if (problems.length === 0) {
  console.log(`check-frozen-vectors: ok (${Object.entries(counts).map(([list, { ok }]) => `${list} ${ok} files`).join(", ")}; v2 MANIFEST.json matches the architect package)`);
} else {
  console.error(`check-frozen-vectors: FAIL — ${problems.length} finding(s)`);
  for (const problem of problems) console.error(`  ${problem}`);
  console.error("conformance/legacy, conformance/v1, conformance/inputs-ref and conformance/v2 are frozen; restore the files, never edit them.");
}
process.exit(problems.length === 0 ? 0 : 1);
