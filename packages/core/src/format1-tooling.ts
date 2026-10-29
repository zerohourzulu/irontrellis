import { types } from "node:util";
/**
 * A-185.3 / A-194: the mark that lets the legacy and format-1 writers run. The public API writes format 2 only
 * (`createLocalOwner({format})` and every handle built from owner options refuse another format; the public store entry
 * points refuse `readOnlyFormats: false` and older genesis formats). Test tooling reaches the older writers through the
 * non-public subpath `@ramex-labs/irontrellis/internal-format1`, whose helpers put this mark on the options they pass.
 * A-206.1: an unregistered symbol, obtainable only from that subpath (a `Symbol.for` key could be built from its string by
 * any caller of the public entry). The source (`src/`) and the built (`dist/`) copies of this module each hold their own
 * mark, so a process takes the mark from the same copy as the API it calls.
 */
export const FORMAT1_TEST_TOOLING: unique symbol = Symbol("irontrellis.internal-format1.test-tooling") as never;
/**
 * Whether `options` carries the test-tooling mark: an own data property equal to `true` (an own enumerable property, so object
 * spreads keep it). A Proxy is refused before anything is read (independent review JOB75-02): any trap it has (`get`, `has`,
 * `getOwnPropertyDescriptor`) would be handed the unregistered symbol and could keep it. Only a same-realm plain record is read
 * (prototype `Object.prototype` or `null`), so an exotic object that `isProxy` does not report, such as a `vm` context's
 * global, is refused before its descriptor is asked for (independent review step 5b §3, defence in depth).
 */
export const hasFormat1TestTooling = (options: unknown): boolean => {
  if (options === null || typeof options !== "object" || types.isProxy(options)) return false;
  const proto = Object.getPrototypeOf(options);
  if (proto !== Object.prototype && proto !== null) return false;
  const descriptor = Object.getOwnPropertyDescriptor(options, FORMAT1_TEST_TOOLING);
  return descriptor !== undefined && Object.hasOwn(descriptor, "value") && descriptor.value === true;
};
