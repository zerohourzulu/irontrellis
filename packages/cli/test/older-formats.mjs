// Legacy (Continuity 0.2) and format-1 histories for the read-only tests. No CLI command creates them any more
// (SPEC §16.1, addendum A-9): they are written here through the core's test-only earlier-format writer, which a
// caller reaches only through the non-public internal-format1 entry point (A-185.3, A-194).
import { createLocalDomain } from "@ramex-labs/irontrellis";
import { createFormat1TestOwner } from "@ramex-labs/irontrellis/internal-format1";

export const LEGACY = "continuity-event/0.2";
export const FORMAT_1 = "irontrellis-event/1";

/** A history of `format` at `path` with owner `owner`: the genesis and the principal, as `init` used to write it. */
export async function olderHistory(path, format, { owner = "owner" } = {}) {
  const handle = await createFormat1TestOwner({ historyFile: path, domain: createLocalDomain({ format }), owner, controller: owner, now: () => Date.now(), format });
  handle.close();
  return path;
}
