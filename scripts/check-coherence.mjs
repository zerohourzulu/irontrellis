#!/usr/bin/env node
/**
 * Coherence gate: the public documents, the CLI help text and the source comments describe the release as it is.
 *
 *   node scripts/check-coherence.mjs          # exit 0 when clean, 1 with one line per finding
 *   node scripts/check-coherence.mjs --json   # the findings as JSON
 *   node scripts/check-coherence.mjs --self-test   # only the rule self-test
 *
 * What it refuses, in every scanned file:
 *  - development history: build stages ("block 3", "phase 2", a bare "rc.2"), internal notes and review files
 *    (WITNESS-DESIGN, HANDOFF, NOTES-*, REVIEW-BLOCK*), review finding IDs ("(M2)", "review H1"), "pre-review",
 *    "unreleased", "since rc…";
 *  - a release-candidate version other than the one in packages/core/package.json (CHANGELOG.md excepted);
 *  - identifiers that do not exist in this release (the anchor layer's old witness names and codes, endpoints and
 *    wire versions that were never published);
 *  - a hard-coded count of format-1 conformance vectors (conformance/README.md has the generated table);
 *  - a page set over its word cap (WORD_CAPS below), counted in prose words.
 *
 * What it does not scan: tests (any `test/` or `tests/` directory and `*.test.*` files, which may keep provenance
 * comments), docs/reviews/ and docs/history/ (the labelled pre-release review record), docs/spec/ and docs/records/ (the
 * architect's specification and the dated records, kept verbatim; the publication-gate scanner still scans them for host
 * data, secrets and the old name), the posted Internet-Draft files (docs/ietf/draft-*), docs/legacy-semantics/ and
 * packages/reference-0.2/ and packages/reference-0.3/ (Continuity's own specification and code, frozen),
 * conformance/legacy/ (byte-frozen Continuity vectors), conformance/v2/ and conformance/inputs-ref/ (the frozen
 * format-2 suite and its reference inputs, checked byte for byte by scripts/check-frozen-vectors.mjs), generated
 * vectors and histories (conformance/v1/histories/), fuzz regressions and output, node_modules and dist. Mentions of
 * Continuity itself are causal history and are never flagged by these rules.
 *
 * Generated blocks: only conformance/README.md may fence a generated table with `<!-- name:begin -->` and
 * `<!-- name:end -->`; a marker anywhere else, an unterminated or nested block, or an end without its begin is a
 * finding, so a stray marker can never hide the rest of a file.
 *
 * Every run first checks the rules against known phrasings (SELF_TEST below: each must be flagged, each clean line
 * must pass) and exits 2 if a rule no longer catches one. `--self-test` runs only that.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SELF = "scripts/check-coherence.mjs";
const json = process.argv.includes("--json");
const selfTestOnly = process.argv.includes("--self-test");

const TEXT_EXTENSIONS = new Set([".md", ".ts", ".mts", ".js", ".mjs", ".cjs", ".py", ".yml", ".yaml", ".toml", ".sh", ".txt", ".json"]);
const SKIP_DIRS = new Set(["node_modules", "dist", ".git", "test", "tests", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv", "venv"]);
const SKIP_PREFIXES = [
  "docs/reviews/", "docs/history/", "docs/legacy-semantics/",
  // the architect's specification and the dated records, verbatim (exactly these two prefixes; the publication gate still scans them)
  "docs/spec/", "docs/records/", "packages/reference-0.2/", "packages/reference-0.3/", "conformance/legacy/",
  "conformance/v2/", "conformance/inputs-ref/", "conformance/v1/histories/",
  // the frozen architect's generator re-run under A-54 and its README (frozen like conformance/v2/; never edited)
  "conformance/v2-g3/",
  "fuzz/out/", "fuzz/regressions/", "bench/out/", "bench/results/",
  // the chapter 1 record's evidence files, verbatim: their sha256 are published on its page (the publication gate still scans them)
  "docs/examples/chapter-1/",
  // the Internet-Draft files exactly as posted to the IETF (docs/ietf/README.md is still scanned)
  "docs/ietf/draft-",
];
/** The dated results page: its counts come from the records, and it names the reviews and their findings by design, so
 * vector-count, finding-id and review-talk skip it (every other rule still applies). */
const RESULTS_PAGE = "docs/TESTING.md";
/** The one file whose generated table is fenced by begin/end markers. */
const MARKER_FILES = new Set(["conformance/README.md"]);
// Generated or data files: JSON is scanned only where people write prose in it (manifests of the packages).
const JSON_ALLOW = [/^packages\/[^/]+\/package\.json$/, /^integrations\/[^/]+\/package\.json$/, /^packages\/[^/]+\/server\.json$/, /^package\.json$/];
const ROOT_FILES = ["README.md", "CHANGELOG.md", "CHECKLIST.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "package.json"];
const SCAN_DIRS = ["docs", "packages", "integrations", "plugins", "python", "conformance", "fuzz", "bench", "examples", "scripts", ".github", "brand"];

const coreVersion = JSON.parse(readFileSync(join(ROOT, "packages/core/package.json"), "utf8")).version;
const currentRc = /-rc\.(\d+)$/.exec(coreVersion)?.[1];

// The vector generators write deliberately invalid inputs (unknown anchor kinds, wrong wire versions) into negative
// vectors; the identifier rules do not apply to them, the prose rules do (their purposes are published in MANIFEST.json).
const GENERATOR = /^conformance\/[^/]+\/(?:generate|scenario)\.mjs$/;
const inGenerator = (file) => GENERATOR.test(file);

/** Where a format-1 history literal is legitimately read (see the `format1-wire` rule). Narrowed as the outer packages move to format 2. */
const FORMAT1_READERS = [
  "packages/core/src/", "packages/core/bench/", "packages/core/README.md", "python/", "conformance/", "fuzz/", "bench/", "examples/", "scripts/verify-install.mjs",
  "packages/witness/", "packages/cli/", "packages/hooks/", "packages/mcp-gateway/",
];
const FORMAT1_PAGES = new Set(["docs/HISTORY-FORMAT.md", "docs/MIGRATION.md", "docs/GLOSSARY.md", "docs/OPERATOR.md", "docs/API.md", "CHANGELOG.md", "docs/reviews/2026-09-26-production-readiness-review.md",
  // The read-only legacy/format-1 byte reference (docs/HISTORY-FORMAT.md and docs/API.md moved it there).
  "docs/reference/api-migration-store.md", "docs/reference/api-owner.md", "docs/reference/history-encoding.md", "docs/reference/history-events.md", "docs/reference/history-migration-examples.md", "docs/reference/history-signatures.md", "docs/reference/history-storage.md"]);

/** @type {{ id: string, re: RegExp, why: string, skip?: (file: string, line: string, match: RegExpMatchArray) => boolean }[]} */
const RULES = [
  // Development history.
  { id: "bare-rc", re: /(?:^|[^\w.+-])(rc(?:[.-]|\s+)?\d+)\b/i, why: "names a release candidate without its version (write the full version, or nothing)" },
  {
    id: "build-stage",
    re: /\b(?:block[ -]?\d{1,3}|blocks \d|[Pp]hase (?:\d+|[A-Z])\b|(?:first|second|third|fourth|fifth|previous|earlier|later|next|last) (?:build|development|implementation) (?:stage|step|round|pass|phase))\b/,
    why: "names an internal build stage",
  },
  { id: "internal-note", re: /\b(?:WITNESS-DESIGN|WIRE-DEVIATIONS|HANDOFF(?:\.md)?|REVIEW-BLOCK\d*|NOTES-[\w.]+|AUDIT\.md|PLAN\.md)\b/, why: "cites an internal design note or review file that is not in the repository" },
  { id: "review-talk", re: /\b(?:pre-review|re-review|review round|(?:first|second|third|fourth) review|was flaky|unreleased|coherence (?:pass|audit|review)|internal audit)\b/i, why: "talks about the development process", skip: (file) => file === RESULTS_PAGE },
  {
    id: "since-history",
    re: /\bsince (?:v?\d+\.\d+\.\d+-rc|rc\b|rc[.\s-]?\d|the (?:previous|last|first|earlier) (?:build|candidate|review|draft|release candidate)|block|phase|the review|the audit)/i,
    why: "dates behaviour against an internal stage",
  },
  {
    id: "finding-id",
    re: /\((?:[BHMLNFR]-?\d{1,2})(?:\s*(?:[,/]|and)\s*[BHMLNFR]-?\d{1,2})*\)|\b(?:review|finding|fix(?:es|ed)?(?: for)?)\s+[BHMLNFR]-?\d{1,2}\b/,
    why: "cites a review finding ID (they live in docs/history/ and tests only)",
    skip: (file) => file === RESULTS_PAGE,
  },
  // Versions.
  {
    id: "other-rc-version",
    re: /\b\d+\.\d+\.\d+-rc\.(\d+)\b/,
    why: `names a release candidate other than this one (${coreVersion})`,
    skip: (file, line) => file === "CHANGELOG.md" || (currentRc !== undefined && [...line.matchAll(/\b\d+\.\d+\.\d+-rc\.(\d+)\b/g)].every((m) => m[0] === coreVersion)),
  },
  // Identifiers that do not exist in this release.
  { id: "stale-identifier", skip: inGenerator, re: /\b(?:ANCHOR_WITNESSES|httpWitness|rekorWitness|localWitness|http-witness|WITNESS_(?:ROLLBACK|INVALID|MISSING|NONE|IGNORED|LOG_\w+|AFTER_ACCEPTED_ROLLBACK)|OWNER_NEXT_KEYS_COMMITTED|LATEST_NOTE_VERSIONS|witness-binding\/\d+|WitnessContext|witnessContextOf|CommittedEntry|ROTATION_(?:INVALID|HEAD_UNKNOWN)|WitnessRotateResult|HASH_SIZE|verifyKeyCommitmentEvent)\b/, why: "names an identifier this release does not have" },
  // The fuzz targets and the generators feed retired options on purpose (negative inputs the CLI must refuse).
  { id: "stale-cli", skip: (file) => inGenerator(file) || file.startsWith("fuzz/targets/"), re: /\banchor\b[^\n]{0,60}?--(?:witness|kind[ =]http)\b/, why: "the CLI anchor command has no --witness or --kind http (bind a remote witness with init --witness or witness bind)" },
  { id: "stale-field", re: /\bdata\.witness\b|ANCHOR_RECORDED[^\n]{0,80}\bwitness:/, why: "ANCHOR_RECORDED names its target in data.anchor" },
  // Format 2 (SPEC-IRONTRELLIS-CORE-v2 §5.1, §19) is the current history format: its `/2` literals are the wire. A `/3`
  // or later literal, or the retired rotations endpoint, does not exist.
  { id: "stale-wire", skip: inGenerator, re: /\/v1\/histories\/[^\s`'"]*\/rotations\b|\birontrellis-[a-z-]+\/[3-9]\b/, why: "names an endpoint or wire version that does not exist" },
  // The format-1 history literals (genesis `versions`, store line, attestation, policy) are read, never written, by this
  // release (SPEC §16.1): they belong in the reader and the migration (packages/core/src), the frozen Python verifier,
  // the conformance suites and their adapters, the fuzz seeds, the benchmarks of format-1 files, the packages that still
  // open format-1 files (witness, cli, hooks, gateway: their format-2 move is a later stage) and the pages that document
  // reading and migrating older formats. Anywhere else a format-1 literal is stale: write the format-2 one.
  {
    id: "format1-wire",
    re: /\birontrellis-(?:event|portable-file-store|record|state|projection|control-authorization|authorization-proof|runtime-authorization|administrative-authorization|receipt|head-attestation|local-owner)\/1\b/,
    why: "names a format-1 history literal outside the reader, the migration, the frozen suites and the older-format documentation (format 2 is the wire; SPEC §16.1)",
    skip: (file) => inGenerator(file) || FORMAT1_READERS.some((prefix) => file.startsWith(prefix)) || FORMAT1_PAGES.has(file),
  },
  { id: "local-witness", re: /\blocal witness(?:es)?\b|\bwitness log file\b/i, why: "a local log is an anchor log; \"witness\" means the remote witness only" },
  // Counts.
  {
    id: "vector-count",
    re: /(?<![\w.-]|RFC )\d[\d,]*\s+(?:[\w-]+\s+){0,3}vectors\b|\bvectors (?:over|across|in) \d+ histories\b/i,
    why: "hard-codes a vector count (refer to the generated table in conformance/README.md)",
    // A count of the frozen legacy vectors (or of Continuity's) is a fixed fact; it is named next to the number.
    skip: (file, line, m) => file === "conformance/README.md" || file === RESULTS_PAGE || /legacy|Continuity/i.test(line.slice(Math.max(0, m.index - 40), m.index + m[0].length)),
  },
];

function* walk(dir) {
  let entries;
  try { entries = readdirSync(join(ROOT, dir), { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const rel = dir === "" ? entry.name : `${dir}/${entry.name}`;
    if (SKIP_PREFIXES.some((p) => `${rel}/`.startsWith(p) || rel.startsWith(p))) continue;
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walk(rel);
    } else if (entry.isFile()) yield rel;
  }
}

function scanned(file) {
  if (file === SELF) return false;
  if (/\.test\.[cm]?[jt]s$|(^|\/)test_[^/]*\.py$/.test(file)) return false;
  const dot = file.lastIndexOf(".");
  const ext = dot < 0 ? "" : file.slice(dot);
  const base = file.slice(file.lastIndexOf("/") + 1);
  if (ext === ".json") return JSON_ALLOW.some((re) => re.test(file));
  if (base.startsWith("Dockerfile")) return true;
  return TEXT_EXTENSIONS.has(ext);
}

/** The findings for one file's text (`file` is its repository-relative path; it decides the skips and markers). */
function scanText(file, text) {
  const found = [];
  const lines = text.split(/\r?\n/);
  // Generated blocks: a begin, then its own end with no other marker in between. Only lines strictly inside such a
  // pair are skipped, and only in MARKER_FILES; every other marker is a finding and hides nothing.
  const markerAt = lines.map((line) => {
    const m = /<!--\s*([\w-]+):(begin|end)\b/.exec(line);
    return m === null ? undefined : { name: m[1], kind: m[2], text: m[0] };
  });
  const skip = new Set();
  const bad = new Map(); // line index -> why
  const indices = markerAt.flatMap((m, i) => (m === undefined ? [] : [i]));
  for (let k = 0; k < indices.length; k++) {
    const i = indices[k], m = markerAt[i];
    if (inGenerator(file)) continue; // the generator writes the markers as string literals
    if (!MARKER_FILES.has(file)) { bad.set(i, `generated-block markers are honoured only in ${[...MARKER_FILES].join(", ")}`); continue; }
    if (m.kind === "end") { bad.set(i, `closes "${m.name}", which is not open`); continue; }
    const next = indices[k + 1];
    if (next === undefined) { bad.set(i, `generated block "${m.name}" is never closed (it hides nothing; close it or remove it)`); continue; }
    const n = markerAt[next];
    if (n.kind === "begin") { bad.set(i, `generated block "${m.name}" is not closed before "${n.name}" opens`); continue; }
    if (n.name !== m.name) { bad.set(i, `generated block "${m.name}" is closed by "${n.name}"`); bad.set(next, `closes "${n.name}", which is not open`); k++; continue; }
    for (let j = i; j <= next; j++) skip.add(j);
    k++;
  }
  lines.forEach((line, i) => {
    if (bad.has(i)) found.push({ file, line: i + 1, rule: "generated-marker", match: markerAt[i].text, why: bad.get(i), text: line.trim().slice(0, 200) });
    if (skip.has(i)) return;
    for (const rule of RULES) {
      const flags = rule.re.flags.includes("g") ? rule.re.flags : `${rule.re.flags}g`;
      for (const m of line.matchAll(new RegExp(rule.re.source, flags))) {
        if (rule.skip?.(file, line, m) === true) continue;
        found.push({ file, line: i + 1, rule: rule.id, match: m[0].trim(), why: rule.why, text: line.trim().slice(0, 200) });
        break; // one finding per rule and line
      }
    }
  });
  return found;
}

// ---------------------------------------------------------------- self-test
// Phrasings each rule must catch (the bypasses an independent review found, and the original mutation set), and
// present-tense lines that must pass. The probe file is a public doc, so every rule applies.
const PROBE = "docs/PROBE.md";
const SELF_TEST = {
  flagged: [
    ["since-history", "Since 1.0.0-rc.1 the genesis carries the next-key commitment."],
    ["since-history", "This works since rc 1."],
    ["build-stage", "The binding was added in phase B."],
    ["build-stage", "The second build stage moved the commitment into the genesis."],
    ["build-stage", "It was added in block 4."],
    ["build-stage", "phase 2 adds the witness."],
    ["stale-identifier", "Pass a WitnessContext to witnessContextOf."],
    ["stale-identifier", "Each CommittedEntry is checked."],
    ["stale-identifier", "The witness answers ROTATION_INVALID."],
    ["stale-identifier", "rotate() returns a WitnessRotateResult."],
    ["stale-identifier", "HASH_SIZE is 32."],
    ["stale-identifier", "Use verifyKeyCommitmentEvent first."],
    ["stale-identifier", "The anchor is http-witness."],
    ["stale-cli", "Run `irontrellis anchor --witness http` to anchor remotely."],
    ["stale-cli", "irontrellis anchor --kind http"],
    ["bare-rc", "This changed in rc 2."],
    ["bare-rc", "Fixed in rc.2."],
    // Any release candidate but the current one (computed, so the self-test follows the version label).
    ["other-rc-version", `Fixed in 1.0.0-rc.${Number(currentRc ?? 0) + 1}.`],
    ["finding-id", "This closes review finding M-2."],
    ["finding-id", "See (H1, M2)."],
    ["review-talk", "As the coherence audit found, this is safe."],
    ["review-talk", "The feature is unreleased."],
    ["vector-count", "There are 89 replay vectors over 7 histories."],
    ["vector-count", "89 format-1 vectors pass."],
    ["vector-count", "The suite has vectors over 7 histories."],
    ["stale-wire", "POST /v1/histories/:id/rotations"],
    ["stale-wire", "the genesis declares irontrellis-event/3"],
    ["format1-wire", "the genesis declares irontrellis-event/1"],
    ["local-witness", "The local witness keeps a log."],
    ["internal-note", "See NOTES-C3.md."],
  ],
  clean: [
    "The genesis carries the next-key commitment (HISTORY-FORMAT §7.2).",
    "Continuity Core 0.2.2 ships 34 legacy vectors.",
    "RFC 8032 test vectors are checked.",
    "The reader pinned Etherlink block 56457192.",
    "The build stage downloads pnpm through corepack; the runtime stage has no npm.",
    "The owner phase and the direct phase are timed separately.",
    `This is ${coreVersion}.`,
    "Bind a remote witness with `irontrellis init --witness <url>`.",
    "a head the file no longer contains",
    "the genesis declares irontrellis-event/2 and irontrellis-head-statement/1",
  ],
};

function selfTest() {
  const failures = [];
  for (const [rule, line] of SELF_TEST.flagged) {
    if (!scanText(PROBE, line).some((f) => f.rule === rule)) failures.push(`rule ${rule} does not flag: ${line}`);
  }
  for (const line of SELF_TEST.clean) {
    const hits = scanText(PROBE, line);
    if (hits.length > 0) failures.push(`clean line flagged by ${hits.map((f) => f.rule).join(", ")}: ${line}`);
  }
  // Markers: an unterminated block hides nothing; markers outside the one generated file are findings; a closed block
  // in that file hides only its content.
  const hidden = "added in block 4 and is not yet published";
  const unterminated = scanText(PROBE, `<!-- table:begin -->\nrow\n${hidden}`);
  if (!unterminated.some((f) => f.rule === "generated-marker")) failures.push("a begin marker outside conformance/README.md is not flagged");
  if (!unterminated.some((f) => f.rule === "build-stage")) failures.push("a line after a stray begin marker is not scanned");
  const readme = scanText("conformance/README.md", `<!-- table:begin -->\n${hidden}`);
  if (!readme.some((f) => f.rule === "generated-marker" && /never closed/.test(f.why))) failures.push("an unterminated begin marker is not flagged");
  if (!readme.some((f) => f.rule === "build-stage")) failures.push("lines after an unterminated begin marker are not scanned");
  const fenced = scanText("conformance/README.md", `<!-- table:begin -->\n| 89 vectors |\n<!-- table:end -->\n${hidden}`);
  if (fenced.some((f) => f.rule === "vector-count")) failures.push("a closed generated block is scanned");
  if (!fenced.some((f) => f.rule === "build-stage")) failures.push("a line after a closed generated block is not scanned");
  const nested = scanText("conformance/README.md", "<!-- a:begin -->\n<!-- b:begin -->\n<!-- b:end -->\n<!-- a:end -->");
  if (!nested.some((f) => f.rule === "generated-marker")) failures.push("a nested begin marker is not flagged");
  if (!scanText("conformance/README.md", "<!-- a:end -->").some((f) => f.rule === "generated-marker")) failures.push("an end marker without its begin is not flagged");
  if (scanText("conformance/v1/generate.mjs", "'<!-- vector-counts:begin -->',").length > 0) failures.push("the generator's marker literals are flagged");
  // Test files are not scanned; the skipped directories are explicit paths, not names anywhere in the tree.
  if (scanned("packages/core/test/x.test.mjs")) failures.push("a test file is scanned");
  if (SKIP_PREFIXES.some((p) => "docs/seeds/x.md".startsWith(p)) || SKIP_DIRS.has("seeds")) failures.push("a directory named seeds is skipped anywhere");
  // docs/spec/ and docs/records/ are skipped as exact prefixes, nothing broader: a sibling, a longer name or a records-named
  // file elsewhere is scanned, and the same text is still flagged everywhere else under docs/ and in the root README.
  const skippedPath = (rel) => SKIP_PREFIXES.some((p) => `${rel}/`.startsWith(p) || rel.startsWith(p));
  for (const rel of ["docs/spec/SPEC-X.md", "docs/records/DEVIATIONS-r2.2.md"]) if (!skippedPath(rel)) failures.push(`${rel} is scanned`);
  for (const rel of ["docs/specs/x.md", "docs/spec.md", "docs/records-old/x.md", "docs/DEVIATIONS-r2.2.md", "docs/reference/KNOWN-ISSUES-r2.2.md", "packages/core/docs/records/x.md", "README.md"]) {
    if (skippedPath(rel) || !scanned(rel)) failures.push(`${rel} is not scanned`);
  }
  // The results page skips three rules only: build-stage is still flagged there.
  for (const rule of ["vector-count", "finding-id", "review-talk"]) if (scanText(RESULTS_PAGE, SELF_TEST.flagged.find(([r]) => r === rule)[1]).some((f) => f.rule === rule)) failures.push(`${rule} is flagged in ${RESULTS_PAGE}`);
  if (!scanText(RESULTS_PAGE, "It was added in block 4.").some((f) => f.rule === "build-stage")) failures.push(`build-stage is not flagged in ${RESULTS_PAGE}`);
  if (!skippedPath("docs/examples/chapter-1/read-record-1.txt") || skippedPath("docs/examples/chapter-1-record.md")) failures.push("the chapter 1 evidence skip is not exact");
  for (const rule of ["bare-rc", "build-stage", "finding-id", "vector-count", "review-talk"]) {
    const line = SELF_TEST.flagged.find(([r]) => r === rule)?.[1];
    if (line === undefined) { failures.push(`no self-test phrasing for ${rule}`); continue; }
    for (const file of ["docs/reference/x.md", "README.md", "docs/DEVIATIONS-r2.2.md"]) if (!scanText(file, line).some((f) => f.rule === rule)) failures.push(`${rule} is not flagged in ${file}`);
  }
  return failures;
}

/**
 * The word caps (the coordinator's ruling of 2026-10-23, DEVIATIONS-r2.5 entry 92, as re-ruled for the documentation pass:
 * decisions D3 and D3a), counted in prose words so that tables and examples are not penalized for their markup. Fenced
 * code blocks (``` and ~~~, Mermaid included), table separator rows and table pipes don't count; every other
 * whitespace-separated word does. docs/*.md means the top-level pages only, so reference/, history/, legacy-semantics/,
 * reviews/, spec/ and records/ are outside the budget.
 */
const WORD_CAPS = [
  { name: "the documentation budget (docs/*.md)", cap: 36_000, files: () => readdirSync(join(ROOT, "docs")).filter((n) => n.endsWith(".md")).map((n) => `docs/${n}`) },
  { name: "README.md", cap: 1_200, files: () => ["README.md"] },
  { name: "packages/hooks/README.md", cap: 1_500, files: () => ["packages/hooks/README.md"] },
];
/** A named, dated allowance for a page set known to be over its cap, removed by the commit that brings it under. */
// A dated exception to a cap: { words, why }. Documentation batch 03 brought the hooks README under its cap; the docs/*.md
// budget has one (the coordinator's rulings of 2026-10-28, launch commits 8 and 10).
const WORD_CAP_ALLOWANCES = new Map([
  ["the documentation budget (docs/*.md)", { words: 37_900, why: "4eb public documents plus 4ex legal notices (28 Oct 2026); revisit at rc.3" }],
]);
export function proseWords(text) {
  let fence = null, words = 0;
  for (const raw of text.split(/\r?\n/)) {
    const open = /^\s*(`{3,}|~{3,})/.exec(raw);
    if (open !== null) { if (fence === null) fence = open[1][0]; else if (open[1][0] === fence) fence = null; continue; }
    if (fence !== null) continue;
    // The founder's ruling (4do item 12): tables, images and diagrams do not count. A table row is a line that starts
    // with a pipe; an image is dropped with its alt text; fenced blocks (Mermaid included) are dropped above.
    if (/^\s*\|/.test(raw)) continue;
    words += raw.replace(/!\[[^\]]*\]\([^)]*\)/g, " ").split(/\s+/).filter((w) => w !== "").length;
  }
  return words;
}
function wordCapFindings(read = (file) => readFileSync(join(ROOT, file), "utf8"), caps = WORD_CAPS, allowances = WORD_CAP_ALLOWANCES) {
  const out = [];
  for (const { name, cap, files } of caps) {
    const words = files().reduce((sum, file) => { try { return sum + proseWords(read(file)); } catch { return sum; } }, 0);
    const allowed = allowances.get(name);
    if (words > cap && !(allowed !== undefined && words <= allowed.words)) {
      out.push({ file: files().length === 1 ? files()[0] : "docs", line: 0, rule: "word-cap", match: `${words} prose words`, why: `${name} is over its cap of ${cap} prose words${allowed ? ` and its allowance of ${allowed.words} (${allowed.why})` : ""}`, text: "" });
    }
  }
  return out;
}
function wordCapSelfTest() {
  const failures = [];
  const sample = "Two words.\n\n```mermaid\nflowchart LR\n  A --> B\n```\n\n| Col | Other |\n|---|---|\n| a | b |\n\n~~~\nfenced too\n~~~\n![a picture of words](x.png)\nEnd.";
  if (proseWords(sample) !== 3) failures.push(`proseWords counted ${proseWords(sample)} words in the sample, not 3`);
  const one = [{ name: "P", cap: 3, files: () => ["p.md"] }];
  if (wordCapFindings(() => "a b c", one, new Map()).length !== 0) failures.push("a page at its cap is flagged");
  if (wordCapFindings(() => "a b c d", one, new Map()).length !== 1) failures.push("a page over its cap is not flagged");
  if (wordCapFindings(() => "a b c d", one, new Map([["P", { words: 4, why: "test" }]])).length !== 0) failures.push("an allowance is not honoured");
  if (wordCapFindings(() => "a b c d e", one, new Map([["P", { words: 4, why: "test" }]])).length !== 1) failures.push("a page over its allowance is not flagged");
  return failures;
}

const selfTestFailures = [...selfTest(), ...wordCapSelfTest()];
if (selfTestFailures.length > 0) {
  for (const failure of selfTestFailures) process.stderr.write(`check-coherence self-test: ${failure}\n`);
  process.exit(2);
}
if (selfTestOnly) {
  process.stdout.write(`check-coherence: self-test ok (${SELF_TEST.flagged.length} phrasings flagged, ${SELF_TEST.clean.length} clean lines pass, markers)\n`);
  process.exit(0);
}

const files = [...ROOT_FILES.filter((f) => { try { return statSync(join(ROOT, f)).isFile(); } catch { return false; } }), ...SCAN_DIRS.flatMap((d) => [...walk(d)])]
  .filter(scanned)
  .sort();

const findings = [...files.flatMap((file) => scanText(file, readFileSync(join(ROOT, file), "utf8"))), ...wordCapFindings()];

if (json) {
  process.stdout.write(`${JSON.stringify({ ok: findings.length === 0, filesScanned: files.length, findings }, null, 2)}\n`);
} else if (findings.length === 0) {
  process.stdout.write(`check-coherence: ok (${files.length} files scanned)\n`);
} else {
  for (const f of findings) process.stdout.write(`${f.file.split("/").join(sep)}:${f.line}: [${f.rule}] "${f.match}": ${f.why}\n    ${f.text}\n`);
  process.stdout.write(`check-coherence: ${findings.length} finding${findings.length === 1 ? "" : "s"} in ${new Set(findings.map((f) => f.file)).size} of ${files.length} files scanned\n`);
}
process.exit(findings.length === 0 ? 0 : 1);
