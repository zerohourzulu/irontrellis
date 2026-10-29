/**
 * A small seeded PRNG (sfc32 seeded through splitmix32), dependency-free and
 * identical on every platform. Every fuzz iteration gets its own generator
 * derived from (target, campaign seed, iteration), so any input can be rebuilt
 * from those three values alone and a campaign can resume at any iteration.
 */

const splitmix32 = (state) => () => {
  state = (state + 0x9e3779b9) | 0;
  let z = state;
  z = Math.imul(z ^ (z >>> 16), 0x85ebca6b);
  z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35);
  return (z ^ (z >>> 16)) >>> 0;
};

/** FNV-1a over a string: stable 32-bit hash for seed derivation. */
export function hash32(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export class Rng {
  constructor(seed) {
    const mix = splitmix32(typeof seed === 'number' ? seed >>> 0 : hash32(String(seed)));
    this.a = mix(); this.b = mix(); this.c = mix(); this.d = mix();
    for (let i = 0; i < 12; i += 1) this.u32();
  }

  /** Derived generator for (target, seed, iteration). */
  static for(target, seed, iteration) {
    return new Rng(hash32(`${target}\u0000${seed}\u0000${iteration}`));
  }

  u32() {
    const t = (((this.a + this.b) | 0) + this.d) | 0;
    this.d = (this.d + 1) | 0;
    this.a = this.b ^ (this.b >>> 9);
    this.b = (this.c + (this.c << 3)) | 0;
    this.c = (this.c << 21) | (this.c >>> 11);
    this.c = (this.c + t) | 0;
    return t >>> 0;
  }

  /** Uniform float in [0, 1). */
  float() { return this.u32() / 4294967296; }
  /** Uniform integer in [0, n). */
  int(n) { return n <= 0 ? 0 : Math.floor(this.float() * n); }
  /** Uniform integer in [lo, hi]. */
  range(lo, hi) { return lo + this.int(hi - lo + 1); }
  chance(p) { return this.float() < p; }
  pick(list) { return list[this.int(list.length)]; }
  /** Picks from [[weight, value], ...]. */
  weighted(entries) {
    let total = 0;
    for (const [weight] of entries) total += weight;
    let r = this.float() * total;
    for (const [weight, value] of entries) {
      r -= weight;
      if (r < 0) return value;
    }
    return entries.at(-1)[1];
  }
  /** Small integers are far more likely than large ones (for counts). */
  small(max = 8) { return Math.min(max, Math.floor(-Math.log(1 - this.float()) * 1.5)); }
  bytes(n) {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 1) out[i] = this.u32() & 0xff;
    return out;
  }
  shuffle(list) {
    const copy = list.slice();
    for (let i = copy.length - 1; i > 0; i -= 1) {
      const j = this.int(i + 1);
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }
  hex(n) {
    let out = '';
    for (let i = 0; i < n; i += 1) out += '0123456789abcdef'[this.int(16)];
    return out;
  }
}
