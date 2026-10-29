/**
 * Pre-rotation: the digest a next-key commitment names for an owner key (docs/HISTORY-FORMAT.md §7.2), in a module of its
 * own so that the event schema, the owner policy rules and the owner key epochs can all use it without an import cycle.
 */
import { suiteFor } from "./crypto/suites.ts";
import { hashCanonical } from "./hash.ts";
import type { ContentHash, SignatureScheme } from "./types.ts";

export const OWNER_KEY_DIGEST_VERSION = "irontrellis-owner-key-digest/1";

/**
 * `hashCanonical({ version: "irontrellis-owner-key-digest/1", scheme, credential }, "sha256")` with the credential
 * normalised (lowercase hex). The key id is not part of it: a committed key may be revealed under any key id the rotation
 * rules allow.
 */
export function ownerKeyDigest(key: Readonly<{ scheme: SignatureScheme; credential: string }>): ContentHash {
  return hashCanonical({ version: OWNER_KEY_DIGEST_VERSION, scheme: key.scheme, credential: suiteFor(key.scheme).normalizeCredential(key.credential) }, "sha256");
}
