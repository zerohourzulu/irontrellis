// A canonical dump of a replay state (r4 §5: "a rejected event leaves the state unchanged"): every field, maps and sets in
// iteration order, the shadow context of a migrated prefix (its hashes, view head and view fields), and rootAt(head).
const walk = (value, seen) => {
  if (typeof value === "bigint") return `${value}n`;
  if (typeof value === "function") return undefined;
  if (value === null || typeof value !== "object") return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString("hex");
  if (seen.has(value)) return "<cycle>";
  seen.add(value);
  const out = value instanceof Map ? { $map: [...value].map(([k, v]) => [walk(k, seen), walk(v, seen)]) }
    : value instanceof Set ? { $set: [...value].map((v) => walk(v, seen)) }
    : Array.isArray(value) ? value.map((v) => walk(v, seen))
    : Object.fromEntries(Object.keys(value).map((k) => [k, walk(value[k], seen)]));
  seen.delete(value);
  return out;
};

export const stateDump = (state) => {
  const out = {};
  for (const key of Object.keys(state)) {
    if (key === "rootLog" || key === "stateRoots") continue;
    const shadow = key === "shadow" ? state.shadow : undefined;
    out[key] = shadow === undefined ? walk(state[key], new Set())
      : { hashes: shadow.hashes.slice(), until: shadow.until, events: shadow.events?.length, view: Object.fromEntries(Object.keys(shadow.view).map((k) => [k, walk(shadow.view[k], new Set())])) };
  }
  out.root = state.events.length === 0 ? null : (state.stateRoots[state.events.length - 1] ?? null);
  return JSON.stringify(out);
};
