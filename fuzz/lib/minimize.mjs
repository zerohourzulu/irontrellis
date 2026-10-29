/**
 * Greedy delta-debugging minimizer for JSON-shaped fuzz inputs. It tries
 * removals from large to small (array chunks, record keys, lines of a
 * multi-line string, string chunks), then simplifications (a subtree replaced
 * by null / 0 / "" / [] / {}), keeping any candidate for which the failure is
 * still the same (`stillFails`), until nothing smaller fails or the budget is
 * spent. The result is what the regression vector records.
 */
import { clone, getAt, paths } from './mutate.mjs';

const isRecord = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const size = (v) => JSON.stringify(v)?.length ?? 0;

function replaceAt(value, path, replacement) {
  if (path.length === 0) return replacement;
  const copy = Array.isArray(value) ? value.slice() : { ...value };
  const [head, ...rest] = path;
  copy[head] = replaceAt(value[head], rest, replacement);
  return copy;
}

function* chunks(length) {
  for (let width = Math.max(1, Math.ceil(length / 2)); ; width = Math.max(1, Math.floor(width / 2))) {
    for (let start = 0; start < length; start += width) yield [start, width];
    if (width === 1) return;
  }
}

function* candidates(value) {
  const all = [[], ...paths(value, 2000)].map((path) => ({ path, weight: size(getAt(value, path)) })).sort((a, b) => b.weight - a.weight);
  for (const { path } of all) {
    const node = getAt(value, path);
    if (Array.isArray(node) && node.length > 0) {
      for (const [start, width] of chunks(node.length)) yield replaceAt(value, path, [...node.slice(0, start), ...node.slice(start + width)]);
    } else if (isRecord(node)) {
      for (const key of Object.keys(node)) { const { [key]: _drop, ...rest } = node; yield replaceAt(value, path, rest); }
    } else if (typeof node === 'string' && node.length > 1) {
      if (node.includes('\n')) {
        const lines = node.split('\n');
        for (const [start, width] of chunks(lines.length)) yield replaceAt(value, path, [...lines.slice(0, start), ...lines.slice(start + width)].join('\n'));
      }
      if (node.length <= 4096) for (const [start, width] of chunks(node.length)) if (width >= Math.max(1, node.length / 64)) yield replaceAt(value, path, node.slice(0, start) + node.slice(start + width));
    }
    if (path.length > 0) {
      for (const simple of [null, 0, '', [], {}]) if (JSON.stringify(simple) !== JSON.stringify(node)) yield replaceAt(value, path, simple);
    }
  }
}

/**
 * Minimizes `input` while `stillFails(candidate)` resolves true. `protect(path)` may exclude paths (e.g. a target's
 * `kind` selector). Returns `{ input, checks, reduced }`.
 */
export async function minimize(input, stillFails, { budget = 1500, deadlineMs = 120_000, protect = () => false } = {}) {
  const deadline = Date.now() + deadlineMs;
  let best = clone(input), checks = 0, improved = true;
  while (improved && checks < budget && Date.now() < deadline) {
    improved = false;
    for (const candidate of candidates(best)) {
      if (checks >= budget || Date.now() >= deadline) break;
      if (size(candidate) >= size(best)) continue;
      if (protectedChange(best, candidate, protect)) continue;
      checks += 1;
      let fails = false;
      try { fails = await stillFails(candidate); } catch { fails = false; }
      if (fails) { best = candidate; improved = true; break; }
    }
  }
  return { input: best, checks, reduced: size(best) < size(input) };
}

function protectedChange(before, after, protect) {
  for (const path of paths(before, 200)) if (protect(path) && JSON.stringify(getAt(before, path)) !== JSON.stringify(getAt(after, path))) return true;
  return false;
}
