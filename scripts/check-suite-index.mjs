#!/usr/bin/env node
/**
 * Suite index gate: each format-2 conformance suite has an INDEX.sha256 that lists every file of the suite, so one
 * digest (the sha256 of INDEX.sha256) pins the whole suite: its vectors, expected results, histories and generator.
 *
 *   node scripts/check-suite-index.mjs           # exit 0 when every index matches its suite, 1 otherwise
 *   node scripts/check-suite-index.mjs --json    # the report as JSON
 *   node scripts/check-suite-index.mjs --write   # rewrite the indexes after a deliberate regeneration of a suite
 *
 * The format, which a second implementation can reproduce with standard tools:
 *  - `conformance/<suite>/INDEX.sha256`, in `sha256sum` text format: `<64 lowercase hex>␠␠<path>\n` per file, so
 *    `sha256sum -c INDEX.sha256` works from the suite's directory;
 *  - one line for every regular file under the suite's directory, with paths relative to it and `/` separators,
 *    except INDEX.sha256 itself;
 *  - lines sorted by path, comparing the UTF-8 bytes; LF line ends, with a final LF; nothing else in the file.
 * A suite is a `conformance/v2-<name>` directory with a `vectors.json`. The frozen `conformance/v2` is not indexed here:
 * it is byte-frozen, and its complete list is `conformance/v2/FROZEN.sha256` (check-frozen-vectors), whose sha256 is
 * its digest. A file that is missing,
 * changed, unlisted, listed twice or out of order is a finding. The suite digest (printed below) is the sha256 of the
 * INDEX.sha256 bytes.
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CONFORMANCE = join(ROOT, "conformance");
const INDEX = "INDEX.sha256";
/** Interpreter caches the Python runners may leave behind; never part of a suite (as in check-frozen-vectors). */
const IGNORED = (name) => name === "__pycache__" || name.endsWith(".pyc");

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const byBytes = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (IGNORED(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else yield path;
  }
}

const suites = readdirSync(CONFORMANCE, { withFileTypes: true })
  .filter((e) => e.isDirectory() && /^v2-[a-z0-9][a-z0-9-]*$/.test(e.name) && existsSync(join(CONFORMANCE, e.name, "vectors.json")))
  .map((e) => e.name).sort(byBytes);

/** The index a suite should have: every file but INDEX.sha256, sorted by UTF-8 bytes. */
function expectedIndex(suite) {
  const dir = join(CONFORMANCE, suite);
  const paths = [...walk(dir)].map((file) => relative(dir, file).split("\\").join("/")).filter((p) => p !== INDEX).sort(byBytes);
  return paths.map((p) => `${sha256(readFileSync(join(dir, p)))}  ${p}\n`).join("");
}

const write = process.argv.includes("--write");
const problems = [];
const report = {};
for (const suite of suites) {
  const indexPath = join(CONFORMANCE, suite, INDEX);
  const expected = expectedIndex(suite);
  if (write) writeFileSync(indexPath, expected);
  if (!existsSync(indexPath)) { problems.push(`MISSING    conformance/${suite}/${INDEX}`); continue; }
  const actual = readFileSync(indexPath);
  const lines = expected === "" ? 0 : expected.split("\n").length - 1;
  report[suite] = { files: lines, digest: sha256(actual) };
  if (actual.toString("utf8") === expected) continue;
  // Name the difference: the index's own lines against the files on disk.
  const listed = new Map();
  let previous;
  for (const [n, line] of actual.toString("utf8").split("\n").entries()) {
    if (line === "") continue;
    const m = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
    if (m === null) { problems.push(`conformance/${suite}/${INDEX}:${n + 1}: malformed line`); continue; }
    if (listed.has(m[2])) problems.push(`DUPLICATE  conformance/${suite}/${m[2]}`);
    if (previous !== undefined && byBytes(previous, m[2]) >= 0) problems.push(`ORDER      conformance/${suite}/${INDEX}:${n + 1}: ${m[2]} after ${previous}`);
    previous = m[2];
    listed.set(m[2], m[1]);
  }
  const onDisk = new Map(expected.split("\n").filter(Boolean).map((l) => [l.slice(66), l.slice(0, 64)]));
  for (const [path, hash] of listed) {
    if (!onDisk.has(path)) problems.push(`MISSING    conformance/${suite}/${path} (listed, not on disk)`);
    else if (onDisk.get(path) !== hash) problems.push(`MODIFIED   conformance/${suite}/${path}: sha256 ${onDisk.get(path)}, indexed ${hash}`);
  }
  for (const path of onDisk.keys()) if (!listed.has(path)) problems.push(`UNEXPECTED conformance/${suite}/${path} (not in ${INDEX})`);
  if (!problems.some((p) => p.includes(`conformance/${suite}/`))) problems.push(`conformance/${suite}/${INDEX}: not in the canonical form (sorted lines, two spaces, LF, final LF)`);
}

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ suites: report, problems }, null, 2));
} else if (problems.length === 0) {
  console.log(`check-suite-index: ${write ? "written" : "ok"} (${Object.entries(report).map(([s, { files, digest }]) => `${s} ${files} files, digest ${digest}`).join("; ")})`);
} else {
  console.error(`check-suite-index: FAIL — ${problems.length} finding(s)`);
  for (const problem of problems) console.error(`  ${problem}`);
  console.error("A suite changed without its index. If the change is deliberate (a regenerated suite), run with --write and commit the new index with it.");
}
process.exit(problems.length === 0 ? 0 : 1);
