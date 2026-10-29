/**
 * Step 5d (P1-2; the coordinator's step 5b review, ruling): the exported type sets that enforcement reads are read-only views
 * over module-private collections. A view has the reading half of `ReadonlySet` / `ReadonlyMap` (`has`, `get`, `size`,
 * `forEach` and iteration) and is frozen: there is no `add`, `delete`, `set` or `clear`, `Set.prototype.add.call(view, …)` throws
 * (the view is not a Set), and the collection it reads cannot be reached.
 */
export function readonlySet<T>(values: Iterable<T>): ReadonlySet<T> {
  const set = new Set<T>(values);
  const view: ReadonlySet<T> = {
    has: (value: T) => set.has(value),
    get size() { return set.size; },
    forEach(callback: (value: T, value2: T, set: ReadonlySet<T>) => void, thisArg?: unknown) { for (const value of set) callback.call(thisArg, value, value, view); },
    entries: () => set.entries(),
    keys: () => set.keys(),
    values: () => set.values(),
    [Symbol.iterator]: () => set.values(),
  };
  return Object.freeze(view);
}
export function readonlyMap<K, V>(entries: Iterable<readonly [K, V]>): ReadonlyMap<K, V> {
  const map = new Map<K, V>(entries);
  const view: ReadonlyMap<K, V> = {
    has: (key: K) => map.has(key),
    get: (key: K) => map.get(key),
    get size() { return map.size; },
    forEach(callback: (value: V, key: K, map: ReadonlyMap<K, V>) => void, thisArg?: unknown) { for (const [key, value] of map) callback.call(thisArg, value, key, view); },
    entries: () => map.entries(),
    keys: () => map.keys(),
    values: () => map.values(),
    [Symbol.iterator]: () => map.entries(),
  };
  return Object.freeze(view);
}
