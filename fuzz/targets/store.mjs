/**
 * Target `store`: history directories (JSONL file, pinned head `.head`, local
 * anchor log `.anchors`, witness side file `.witness.json`) written by the
 * owner API, then damaged: bytes, lines, number spellings, events (re-chained
 * and re-signed or not), rollbacks with and without a re-written pin, pins,
 * anchor logs and side files.
 *
 * TypeScript: `openHistoryStore` strict and `inspect`, `state()`, `verify()`,
 * and `verifyHistory` (what `irontrellis verify` runs). Python: the store
 * reader + replay, and `python -m irontrellis verify` on the same bytes.
 *
 * Invariants: every rejection is an EngineError (TypeScript) or a documented
 * report (Python, never a traceback); a strict open that succeeds carries no
 * seed owner signature over altered content and contains the head its pin's
 * owner attestation names; the TypeScript store reader and the Python reader
 * agree on acceptance, on the layer that rejects (record vs replay), the
 * replay code and the position.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { core, plain } from '../lib/env.mjs';
import { controlTemplates, mutateHistory } from '../lib/history.mjs';
import { attestationFailures, attestationIndex, crashFailure, isTypedError, signatureIndex, signedContentFailures } from '../lib/invariants.mjs';
import { Dictionary, clone, mutateBytes, mutateLines, mutateText, mutateValue } from '../lib/mutate.mjs';
import { keyRegistry, replaySeeds, storeSeeds } from '../lib/seeds.mjs';
import { encodeHistory, parseHistory, pinFor } from '../lib/storefile.mjs';
import { PYTHON_SKIP_REASON, format2Input } from '../lib/python.mjs';

const UTF8 = new TextDecoder('utf-8', { fatal: true });
export const fileSpec = (bytes) => { try { return { text: UTF8.decode(bytes) }; } catch { return { b64: Buffer.from(bytes).toString('base64') }; } };
export const fileBytes = (spec) => (spec === null || spec === undefined ? undefined : spec.text !== undefined ? Buffer.from(spec.text, 'utf8') : Buffer.from(spec.b64, 'base64'));
const textOf = (spec) => (spec?.text !== undefined ? spec.text : spec?.b64 !== undefined ? Buffer.from(spec.b64, 'base64').toString('latin1') : '');
const reasonClass = (text) => String(text ?? '').replace(/\/[^\s)]+/g, 'P').replace(/"[^"]*"/g, 'S').replace(/\b[\w:.-]*\d[\w:.-]*\b/g, 'N').split(/\s+/).slice(0, 8).join(' ');

export function writeStore(input) {
  const dir = mkdtempSync(join(tmpdir(), 'irontrellis-fuzz-store-'));
  for (const [name, spec] of Object.entries(input.files)) {
    const bytes = fileBytes(spec);
    if (bytes !== undefined) writeFileSync(join(dir, name), bytes, { mode: 0o600 });
  }
  return { dir, path: join(dir, 'history.jsonl'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function errorView(error) {
  return { code: error.code, reason: error.detail?.reason ?? null, position: error.detail?.position ?? null, detailCode: error.detail?.code ?? null, message: String(error.message).slice(0, 300) };
}

/** Runs `fn`; a typed engine error is a result, anything else a crash failure. */
function guarded(where, fn, failures) {
  try { return { ok: true, value: fn() }; } catch (error) {
    if (isTypedError(error)) return { ok: false, error: errorView(error) };
    failures.push(crashFailure(where, error));
    return { ok: false, crashed: true };
  }
}

/** The TypeScript reader's verdict in the vocabulary the Python reader answers in. */
function readerView(inspect) {
  if (inspect.ok) return { layer: 'replay', status: 'ACCEPTED', head: plain(inspect.value.head) };
  const e = inspect.error;
  if (e === undefined) return { layer: 'crash' };
  if (e.code === 'INVALID_HISTORY' && e.detailCode) return { layer: 'replay', status: 'REJECTED', code: e.detailCode, position: e.position };
  if (e.code === 'INVALID_HISTORY' || e.code === 'HISTORY_EMPTY') return { layer: 'store', position: e.position ?? /record (\d+)/.exec(e.message)?.[1] ?? null };
  return { layer: 'other', code: e.code };
}
function pythonLine(message) {
  const line = /^line (\d+):/.exec(message ?? '');
  return line ? Number(line[1]) - 1 : null;
}

export default {
  name: 'store',
  async setup(ctx) {
    const seeds = await storeSeeds();
    const histories = [...replaySeeds(), ...seeds.map((s) => ({ name: `store/${s.name}`, events: s.events }))];
    const dict = new Dictionary();
    for (const { events } of histories) dict.add(events);
    const attestations = [];
    for (const seed of seeds) {
      if (seed.files['history.jsonl.head']) { try { attestations.push(JSON.parse(seed.files['history.jsonl.head'].toString('utf8')).attestation); } catch { /* none */ } }
      for (const line of (seed.files['history.jsonl.anchors']?.toString('utf8') ?? '').split('\n')) { try { attestations.push(JSON.parse(line).attestation); } catch { /* skip */ } }
    }
    return {
      ctx, seeds, histories, dict: dict.freeze(), registry: keyRegistry(), templates: controlTemplates(histories), index: signatureIndex(histories),
      attestations: attestationIndex(attestations.filter(Boolean)), attestationList: attestations.filter(Boolean),
    };
  },
  seedInputs(state) {
    return state.seeds.map((seed) => ({ seed: seed.name, witness: seed.name === 'witnessed' ? 'default' : 'off', files: Object.fromEntries(Object.entries(seed.files).map(([name, bytes]) => [name, fileSpec(bytes)])) }));
  },
  async mutate(rng, base, state) {
    const input = clone(base);
    const files = input.files;
    const history = files['history.jsonl'];
    const op = rng.weighted([[14, 'event'], [6, 'event-nochain'], [3, 'reformat'], [8, 'lines'], [10, 'text'], [5, 'bytes'], [8, 'rollback'], [8, 'rollback-pin'], [8, 'pin'], [6, 'anchors'], [5, 'side'], [3, 'witness'], [4, 'two']]);
    const apply = async (kind) => {
      switch (kind) {
        case 'event': case 'event-nochain': {
          let parsed;
          try { parsed = parseHistory(textOf(history)); } catch { files['history.jsonl'] = { text: mutateLines(rng, textOf(history)) }; return; }
          if (parsed.format === undefined) return;
          const donors = state.histories.filter((h) => core.detectFormat(h.events) === parsed.format);
          const events = await mutateHistory(rng, parsed.events, { dict: state.dict, donors, templates: state.templates, registry: state.registry });
          if (kind === 'event') { files['history.jsonl'] = { text: encodeHistory(parsed.format, events) }; return; }
          const lines = textOf(history).split('\n');
          const k = rng.int(Math.max(1, lines.length - 1));
          try { const record = JSON.parse(lines[k]); record.event = mutateValue(rng, record.event, state.dict, 1); lines[k] = JSON.stringify(record); } catch { /* keep */ }
          files['history.jsonl'] = { text: lines.join('\n') };
          return;
        }
        case 'reformat': { // the same events under the other line format (a format-1 file carrying a legacy history, and back)
          let parsed;
          try { parsed = parseHistory(textOf(history)); } catch { return; }
          if (parsed.format === undefined) return;
          const other = parsed.format === core.LEGACY_FORMAT ? core.TRELLIS_FORMAT : core.LEGACY_FORMAT;
          const donor = rng.chance(0.5) ? parsed.events : rng.pick(state.histories).events;
          files['history.jsonl'] = { text: encodeHistory(rng.chance(0.7) ? other : parsed.format, donor) };
          return;
        }
        case 'lines': files['history.jsonl'] = { text: mutateLines(rng, textOf(history)) }; return;
        case 'text': {
          const lines = textOf(history).split('\n');
          const k = rng.int(Math.max(1, lines.length - 1));
          lines[k] = mutateText(rng, lines[k] ?? '', 2);
          files['history.jsonl'] = { text: lines.join('\n') };
          return;
        }
        case 'bytes': files['history.jsonl'] = fileSpec(mutateBytes(rng, fileBytes(history) ?? Buffer.alloc(0))); return;
        case 'rollback': case 'rollback-pin': {
          const lines = textOf(history).split('\n').filter((l) => l.length > 0);
          const keep = rng.int(lines.length);
          files['history.jsonl'] = { text: lines.slice(0, keep).map((l) => `${l}\n`).join('') };
          if (kind === 'rollback-pin' && keep > 0) {
            try {
              const parsed = parseHistory(files['history.jsonl'].text);
              const attestation = rng.pick([undefined, null, clone(rng.pick(state.attestationList)), (() => { try { return JSON.parse(textOf(files['history.jsonl.head'])).attestation; } catch { return undefined; } })()]);
              const pin = pinFor(parsed.format, parsed.events, keep - 1, { attestation: attestation === null ? undefined : attestation });
              if (attestation === null) pin.attestation = null;
              files['history.jsonl.head'] = { text: `${JSON.stringify(pin)}\n` };
            } catch { /* leave the old pin */ }
          }
          if (rng.chance(0.3)) delete files['history.jsonl.anchors'];
          return;
        }
        case 'pin': {
          const pin = files['history.jsonl.head'];
          if (pin === undefined || rng.chance(0.1)) { delete files['history.jsonl.head']; return; }
          try { files['history.jsonl.head'] = { text: `${JSON.stringify(mutateValue(rng, JSON.parse(textOf(pin)), state.dict, 2))}\n` }; } catch { files['history.jsonl.head'] = { text: mutateText(rng, textOf(pin)) }; }
          return;
        }
        case 'anchors': {
          const anchors = files['history.jsonl.anchors'];
          if (anchors === undefined) return;
          if (rng.chance(0.4)) { files['history.jsonl.anchors'] = { text: mutateLines(rng, textOf(anchors)) }; return; }
          const lines = textOf(anchors).split('\n');
          const k = rng.int(Math.max(1, lines.length - 1));
          try { lines[k] = JSON.stringify(mutateValue(rng, JSON.parse(lines[k]), state.dict, 2)); } catch { lines[k] = mutateText(rng, lines[k] ?? ''); }
          files['history.jsonl.anchors'] = { text: lines.join('\n') };
          return;
        }
        case 'side': {
          const side = files['history.jsonl.witness.json'];
          if (side === undefined) return;
          try { files['history.jsonl.witness.json'] = { text: JSON.stringify(mutateValue(rng, JSON.parse(textOf(side)), state.dict, 2)) }; } catch { files['history.jsonl.witness.json'] = { text: mutateText(rng, textOf(side)) }; }
          return;
        }
        case 'witness': input.witness = input.witness === 'off' ? 'default' : 'off'; return;
        default: await apply(rng.pick(['event', 'text', 'pin', 'anchors', 'rollback'])); await apply(rng.pick(['pin', 'anchors', 'side', 'event', 'lines']));
      }
    };
    await apply(op);
    return input;
  },
  async check(input, state) {
    const failures = [];
    const { path, cleanup } = writeStore(input);
    const options = input.witness === 'off' ? { witness: false } : {};
    const outcome = {};
    const features = [];
    try {
      // Strict open: what a writer or reader gets by default.
      let strictStore;
      const strict = guarded('openHistoryStore', () => { strictStore = core.openHistoryStore(path, options); return strictStore.state(); }, failures);
      if (strict.ok) {
        failures.push(...signedContentFailures(state.index, strict.value, 'store'));
        let pin;
        try { pin = JSON.parse(textOf(input.files['history.jsonl.head'])); } catch { pin = undefined; }
        if (pin && strict.value.format === core.TRELLIS_FORMAT && strict.value.events.length > 1) failures.push(...attestationFailures(state.attestations, pin.attestation, strict.value, 'store pin'));
        const report = guarded('HistoryStore.verify', () => strictStore.verify(), failures);
        features.push(`strict:ok:verify:${report.ok ? report.value.ok : report.error?.code}:${report.ok ? report.value.failures.map((f) => f.split(':')[0]).sort().join('+') : ''}`);
      } else if (strict.error) {
        features.push(`strict:${strict.error.code}:${strict.error.reason ?? strict.error.detailCode ?? ''}`);
      }
      try { strictStore?.close(); } catch { /* closed */ }
      outcome.strict = strict.ok ? { ok: true, head: plain(strict.value.head) } : { ok: false, code: strict.error?.code ?? 'CRASH', reason: strict.error?.reason ?? null };
      // Inspect: the reader's verdict on the file alone, then verify's report.
      let inspectStore;
      const opened = guarded('openHistoryStore(inspect)', () => { inspectStore = core.openHistoryStore(path, { ...options, inspect: true }); return inspectStore; }, failures);
      let inspect = { ok: false };
      if (opened.ok) {
        inspect = guarded('HistoryStore.state(inspect)', () => inspectStore.state(), failures);
        const report = guarded('HistoryStore.verify(inspect)', () => inspectStore.verify(), failures);
        features.push(`inspect:${inspect.ok ? 'ok' : `${inspect.error?.code}:${inspect.error?.detailCode ?? reasonClass(inspect.error?.message)}`}:${report.ok ? report.value.failures.map((f) => f.split(':')[0]).sort().join('+') : report.error?.code}`);
        try { inspectStore.close(); } catch { /* closed */ }
      } else if (opened.error) features.push(`inspect-open:${opened.error.code}:${opened.error.reason ?? ''}`);
      // repin (owner signer in force, reads tolerated): it must refuse to vouch for a file its pin or anchor log contradicts,
      // so a successful re-pin never attests less than a seed attestation the old pin carried, nor a file without that head.
      if (inspect.ok && inspect.value.format === core.TRELLIS_FORMAT && (input.repin ?? input.files['history.jsonl']?.text?.length ?? 0) % 3 === 0) {
        let before;
        try { before = JSON.parse(textOf(input.files['history.jsonl.head'])); } catch { before = undefined; }
        const keys = core.ownerKeysAt(inspect.value, inspect.value.head.position);
        const signer = keys.length ? state.registry.get(String(keys[0].credential).toLowerCase()) : undefined;
        let writer;
        const repinned = signer === undefined ? undefined : guarded('repin', () => { writer = core.openHistoryStore(path, { ...options, allowUnpinned: true, signer }); return writer.repin(); }, failures);
        try { writer?.close(); } catch { /* closed */ }
        if (repinned?.ok) {
          const old = before?.attestation?.signature === undefined ? undefined : state.attestations.get(String(before.attestation.signature).toLowerCase());
          const now = repinned.value.attestation?.head;
          // Only for a file with events after genesis: a genesis-only format-1 file needs no pin at all (the documented
          // exemption: only its creation precedes the first pin), so the store cannot treat its pin's attestation as evidence.
          if (inspect.value.events.length > 1 && old !== undefined && typeof old.position === 'number' && (now === undefined || now.position < old.position || inspect.value.eventHistoryHashes[old.position] !== old.hash)) {
            failures.push({ invariant: 'ATTESTED_PREFIX_LOST', key: 'REPIN_LAUNDERED', message: `repin attested position ${now?.position} over a pin whose owner attestation named position ${old.position}${inspect.value.eventHistoryHashes[old.position] !== old.hash ? ' (not in the file)' : ''}` });
          }
          features.push(`repin:ok:${repinned.value.rollbackAcceptedAt === undefined ? 'plain' : 'accepted'}`);
        } else if (repinned) features.push(`repin:${repinned.error?.code}:${repinned.error?.reason ?? ''}`);
      }
      const verified = guarded('verifyHistory', () => core.verifyHistory(path), failures);
      features.push(`verifyHistory:${verified.ok ? verified.value.ok : verified.error?.code}`);
      const reader = opened.ok ? readerView(inspect) : { layer: 'other', code: opened.error?.code };
      outcome.reader = reader;
      const storeBytes = fileBytes(input.files['history.jsonl']) ?? Buffer.alloc(0);
      if (state.ctx.python && format2Input({ text: storeBytes.toString('utf8') })) features.push(`py:skipped:${PYTHON_SKIP_REASON}`);
      else if (state.ctx.python && !failures.some((f) => f.invariant === 'UNTYPED_CRASH')) {
        const bytes = storeBytes;
        const py = await state.ctx.python.request({ op: 'store', b64: bytes.toString('base64') });
        if (py.crash) failures.push({ invariant: 'UNTYPED_CRASH', key: `PY_CRASH:store:${py.crash.split(':')[0]}:${py.where?.at(-1)}`, message: `python store reader: ${py.crash}`, detail: py });
        else if (reader.layer !== 'other') {
          const pyView = py.layer === 'replay' ? { layer: 'replay', status: py.status, code: py.code ?? null, position: py.position ?? null, head: py.head } : { layer: 'store', position: pythonLine(py.message) };
          let disagree = pyView.layer !== reader.layer || pyView.status !== reader.status;
          if (!disagree && reader.layer === 'replay' && reader.status === 'REJECTED') disagree = pyView.code !== reader.code || pyView.position !== reader.position;
          if (!disagree && reader.layer === 'replay' && reader.status === 'ACCEPTED') disagree = JSON.stringify(pyView.head) !== JSON.stringify(reader.head);
          if (!disagree && reader.layer === 'store' && pyView.position !== null && reader.position !== null) disagree = Number(pyView.position) !== Number(reader.position);
          if (disagree) {
            failures.push({ invariant: 'TS_PY_DISAGREE', key: `STORE:ts=${reader.layer}/${reader.status ?? ''}/${reader.code ?? ''}:py=${pyView.layer}/${pyView.status ?? ''}/${pyView.code ?? ''}`,
              message: `store reader: TypeScript ${JSON.stringify(reader).slice(0, 200)} (${inspect.error?.message?.slice(0, 160) ?? ''}), Python ${JSON.stringify(pyView).slice(0, 200)} (${py.message?.slice(0, 160) ?? ''})` });
          }
          outcome.py = pyView;
          features.push(`py:${pyView.layer}:${pyView.status ?? ''}:${pyView.code ?? ''}`);
        }
        if ((input.cli ?? bytes.length % 5) === 0) { // the Python CLI on the same bytes, on a deterministic sample
          const cli = await state.ctx.python.request({ op: 'cli', argv: ['verify', '{dir}/h.jsonl'], files: { 'h.jsonl': bytes.toString('base64') } });
          if (cli.crash) failures.push({ invariant: 'UNTYPED_CRASH', key: `PY_CRASH:cli-verify:${cli.crash.split(':')[0]}:${cli.where?.at(-1)}`, message: `python -m irontrellis verify: ${cli.crash}`, detail: cli });
          else {
            let report;
            try { report = JSON.parse(cli.stdout); } catch { report = undefined; }
            if (report === undefined || typeof report.status !== 'string') failures.push({ invariant: 'UNTYPED_CRASH', key: 'PY_CLI_OUTPUT', message: `python -m irontrellis verify printed no JSON report (exit ${cli.exit}): ${cli.stdout.slice(0, 200)} ${cli.stderr.slice(0, 200)}` });
            else if ((report.status === 'ACCEPTED') !== (cli.exit === 0)) failures.push({ invariant: 'UNTYPED_CRASH', key: 'PY_CLI_EXIT', message: `python verify: status ${report.status} with exit ${cli.exit}` });
          }
        }
      }
    } finally {
      cleanup();
    }
    return { failures, features, outcome };
  },
};
