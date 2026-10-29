/**
 * Keccak-256 (the original Keccak padding `0x01`, as Ethereum uses it — not
 * FIPS-202 SHA3-256). Spec 04 §A.
 *
 * The 1600-bit state is 25 lanes of 64 bits, kept as 50 unsigned 32-bit words:
 * lane `i` is `words[2i]` (low half) and `words[2i+1]` (high half). Absorption is
 * little-endian, so stream byte `p` (mod 136) lands in `words[p >> 2]` at bit
 * offset `8 * (p & 3)`. Everything is plain 32-bit integer arithmetic; no BigInt.
 *
 * The incremental API mirrors the legacy engine: `finalize` never disturbs the
 * state (it pads and permutes a private copy), so a state can be finalized,
 * updated further, and finalized again — which is what prefix hashing of the
 * event history relies on.
 */

const RATE = 136; // bytes absorbed per permutation for Keccak-256 (capacity 512 bits)
const ROUNDS = 24;

// Rho rotation offsets and pi destinations, in the order the lane walk visits
// them (starting from lane 1 = words[2]). Standard tables; the walk follows the
// pi permutation (x, y) -> (y, 2x + 3y), and each visited lane is rotated by the
// triangular number offset of its step.
const RHO_OFFSETS: readonly number[] = [
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const PI_TARGETS: readonly number[] = [
  20, 14, 22, 34, 36, 6, 10, 32, 16, 42, 48, 8, 30, 46, 38, 26, 24, 4, 40, 28, 44, 18, 12, 2,
];

// Iota round constants, split into (low, high) 32-bit halves.
const IOTA_LOW: readonly number[] = [
  0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
  0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
  0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008,
];
const IOTA_HIGH: readonly number[] = [
  0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000,
  0x80000000, 0x80000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000,
];

export type KeccakState = {
  /** 50 × u32: lane i = words[2i] (low) ‖ words[2i+1] (high). */
  readonly words: Uint32Array;
  /** Next byte offset inside the current 136-byte rate block. */
  position: number;
};

// 64-bit rotate-left of the pair (high, low) by 1..63 (never 32 in our tables),
// returning the new high or low half respectively.
function rotlHigh(high: number, low: number, shift: number): number {
  return shift < 32 ? (high << shift) | (low >>> (32 - shift)) : (low << (shift - 32)) | (high >>> (64 - shift));
}
function rotlLow(high: number, low: number, shift: number): number {
  return shift < 32 ? (low << shift) | (high >>> (32 - shift)) : (high << (shift - 32)) | (low >>> (64 - shift));
}

/** Keccak-f[1600] on the 50-word state. `scratch` is a 10-word work buffer. */
function permute(s: Uint32Array, scratch: Uint32Array): void {
  for (let round = 0; round < ROUNDS; round += 1) {
    // theta: column parities, then each lane ^= C[x-1] ^ rotl(C[x+1], 1)
    for (let x = 0; x < 10; x += 1) {
      scratch[x] = s[x]! ^ s[x + 10]! ^ s[x + 20]! ^ s[x + 30]! ^ s[x + 40]!;
    }
    for (let x = 0; x < 10; x += 2) {
      const left = (x + 8) % 10;
      const right = (x + 2) % 10;
      const rightLow = scratch[right]!;
      const rightHigh = scratch[right + 1]!;
      const dLow = rotlLow(rightHigh, rightLow, 1) ^ scratch[left]!;
      const dHigh = rotlHigh(rightHigh, rightLow, 1) ^ scratch[left + 1]!;
      for (let y = 0; y < 50; y += 10) {
        s[x + y] = s[x + y]! ^ dLow;
        s[x + y + 1] = s[x + y + 1]! ^ dHigh;
      }
    }
    // rho + pi: walk the lanes, rotating each and dropping it at its pi target
    let carryLow = s[2]!;
    let carryHigh = s[3]!;
    for (let step = 0; step < 24; step += 1) {
      const shift = RHO_OFFSETS[step]!;
      const target = PI_TARGETS[step]!;
      const rotatedLow = rotlLow(carryHigh, carryLow, shift);
      const rotatedHigh = rotlHigh(carryHigh, carryLow, shift);
      carryLow = s[target]!;
      carryHigh = s[target + 1]!;
      s[target] = rotatedLow;
      s[target + 1] = rotatedHigh;
    }
    // chi: a[x] ^= ~a[x+1] & a[x+2] along each row
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x += 1) scratch[x] = s[y + x]!;
      for (let x = 0; x < 10; x += 1) {
        s[y + x] = s[y + x]! ^ (~scratch[(x + 2) % 10]! & scratch[(x + 4) % 10]!);
      }
    }
    // iota
    s[0] = s[0]! ^ IOTA_LOW[round]!;
    s[1] = s[1]! ^ IOTA_HIGH[round]!;
  }
}

const SCRATCH = new Uint32Array(10);

/** Absorbs `bytes` into `words` starting at byte offset `position`; returns the new position. */
function absorb(words: Uint32Array, position: number, bytes: Uint8Array): number {
  const length = bytes.length;
  let index = 0;
  while (index < length) {
    if ((position & 3) === 0 && index + 4 <= length) {
      // Word-aligned with a full word available: absorb 4 little-endian bytes at once.
      // (RATE is a multiple of 4, so an aligned position always has room for a word.)
      const word = bytes[index]! | (bytes[index + 1]! << 8) | (bytes[index + 2]! << 16) | (bytes[index + 3]! << 24);
      words[position >>> 2] = words[position >>> 2]! ^ word;
      index += 4;
      position += 4;
    } else {
      words[position >>> 2] = words[position >>> 2]! ^ (bytes[index]! << ((position & 3) * 8));
      index += 1;
      position += 1;
    }
    if (position === RATE) {
      permute(words, SCRATCH);
      position = 0;
    }
  }
  return position;
}

/** Pads (`0x01 … 0x80`), permutes, and reads the first 32 bytes out of `words`. Destroys `words`. */
function squeeze(words: Uint32Array, position: number): Uint8Array {
  words[position >>> 2] = words[position >>> 2]! ^ (0x01 << ((position & 3) * 8));
  words[(RATE - 1) >>> 2] = words[(RATE - 1) >>> 2]! ^ (0x80 << (((RATE - 1) & 3) * 8));
  permute(words, SCRATCH);
  const digest = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) digest[i] = (words[i >>> 2]! >>> ((i & 3) * 8)) & 0xff;
  return digest;
}

export function createKeccakState(): KeccakState {
  return { words: new Uint32Array(50), position: 0 };
}

export function updateKeccakState(state: KeccakState, bytes: Uint8Array): void {
  state.position = absorb(state.words, state.position, bytes);
}

export function cloneKeccakState(state: KeccakState): KeccakState {
  return { words: new Uint32Array(state.words), position: state.position };
}

/** Digest of everything absorbed so far. Non-destructive: the state stays usable. */
export function finalizeKeccakState(state: KeccakState): Uint8Array {
  return squeeze(new Uint32Array(state.words), state.position);
}

/** One-shot Keccak-256; 32 bytes. */
export function keccak256(bytes: Uint8Array): Uint8Array {
  const words = new Uint32Array(50);
  return squeeze(words, absorb(words, 0, bytes));
}
