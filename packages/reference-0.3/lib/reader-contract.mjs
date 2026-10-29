// Bounded integration contract; this does not change Core semantics.
export const LIMITS = Object.freeze({ request: 16384, config: 65536, history: 2097152,
  output: 262144, events: 256, agents: 32, workerMs: 15000, ioMs: 15000 });
export const OPERATIONS = Object.freeze(['verify', 'status', 'check', 'why', 'responsible', 'survives', 'handover_report']);
export const NOTE = 'Observation at one supplied history head, not a capability or present-world freshness. Consequential effects require current admission, pre-use checks and an enforcing adapter. Duty does not grant power; attribution does not establish truth.';
export class ReaderError extends Error {
  constructor(code) { super(code); this.name = 'ReaderError'; this.code = code; }
}
export const fail = code => { throw new ReaderError(code); };
export const record = x => x !== null && typeof x === 'object' && !Array.isArray(x);
export function closed(value, allowed, required = []) {
  if (!record(value) || Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail('INVALID_ARGUMENTS');
}
export function textField(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f]/u.test(value)) fail('INVALID_ARGUMENTS');
  return value;
}
export function decimal(value, maximum, code) {
  if (typeof value !== 'string' || value.length > 78 || !/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > maximum) fail(code);
  return BigInt(value);
}
export function validateOptions(operation, args) {
  if (!OPERATIONS.includes(operation)) fail('UNKNOWN_OPERATION');
  const ask = ['check', 'why', 'responsible'].includes(operation);
  closed(args, ['at', ...(ask ? ['actor', 'action', 'resource', 'amount'] : operation === 'survives' ? ['agent'] : [])],
    ask ? ['actor', 'action', 'resource'] : operation === 'survives' ? ['agent'] : []);
  if (ask) for (const key of ['actor', 'action', 'resource']) textField(args[key]);
  if (operation === 'survives') textField(args.agent);
  if (Object.hasOwn(args, 'at')) decimal(args.at, BigInt(Number.MAX_SAFE_INTEGER), 'INVALID_EVALUATION_TIME');
  if (Object.hasOwn(args, 'amount')) decimal(args.amount, (1n << 256n) - 1n, 'INVALID_AMOUNT');
}
export const encode = value => JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? { '$continuity.bigint': item.toString() } : item);
export function boundedResult(value) {
  const encoded = encode(value);
  if (Buffer.byteLength(encoded) > LIMITS.output) fail('OUTPUT_LIMIT_EXCEEDED');
  return value;
}
