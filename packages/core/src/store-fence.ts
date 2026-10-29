/**
 * The format-2 fence of the public store (A-185.3; independent review JOB75-01 and step 5b §0, P1-b). Core-internal: no
 * package subpath maps here and no public module re-exports it, so the mark can only be set inside Core.
 */
/** Stores whose first write must be a format-2 batch: the public entry points' stores. */
export const FORMAT2_ONLY = new WeakSet<object>();
/** Marks `store` format-2-only. It can only restrict a store, never relax one. */
export function restrictToFormat2<T extends object>(store: T): T { FORMAT2_ONLY.add(store); return store; }
