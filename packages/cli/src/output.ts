/**
 * Terminal output in the IronTrellis brand style (BRAND-001): the Core glyph
 * `◆` in Forge marks the product name in the header; state words are always
 * spelled out and colour only reinforces them. Colour follows the open-source
 * custom (founder 4bz): `--no-color` turns it off, `NO_COLOR` with any value
 * (empty too) turns it off, `FORCE_COLOR` turns it on without a TTY (except
 * `0` or `false`, which turn it off), and otherwise colour needs a TTY and a
 * `TERM` other than `dumb`. The glyph falls back to `*` outside UTF-8 locales.
 * JSON output is one document per command, bigints spelled as decimal strings.
 */
import { createRequire } from "node:module";

export const VERSION: string = (createRequire(import.meta.url)("../package.json") as { version: string }).version;
export const TAGLINE = "agents change. the structure holds.";

/** ANSI-256 palette from the brand standard. */
export const PALETTE = Object.freeze({ forge: 208, allow: 35, deny: 203, indeterminate: 178, open: 74, secondary: 245 });
export type Tone = keyof typeof PALETTE;

export type Env = Readonly<{ isTTY: boolean; env: Readonly<Record<string, string | undefined>> }>;
const processEnv = (): Env => ({ isTTY: process.stdout.isTTY === true, env: process.env });

/** `flag`: false for `--no-color` (it wins over everything), otherwise undefined. */
export const colourEnabled = ({ isTTY, env }: Env = processEnv(), flag?: boolean): boolean => {
  if (flag === false || env.NO_COLOR !== undefined) return false;
  if (env.FORCE_COLOR !== undefined) return !/^(?:0|false)$/i.test(env.FORCE_COLOR.trim());
  return isTTY && env.TERM !== "dumb";
};

/** `◆` when the locale is UTF-8 or unset; `*` when a locale is set to something else. */
export const glyph = ({ env }: Env = processEnv()): string => {
  const locale = env.LC_ALL || env.LC_CTYPE || env.LANG;
  if (locale === undefined || locale === "") return "◆";
  return /utf-?8/i.test(locale) ? "◆" : "*";
};

/** The only words a state colour paints (BRAND-001 p. 6: state colours belong to the four state words, always printed). */
export const STATE_WORDS = Object.freeze(["ALLOW", "DENY", "INDETERMINATE", "OPEN"] as const);
export type StateWord = (typeof STATE_WORDS)[number];
/**
 * `paint` takes Forge (the product marker: the header's ◆ irontrellis, one highlight per view) and the neutral secondary;
 * the state colours are `state`'s, for the four state words only; `strong` (bold) marks any other word that needs weight
 * (FAILED, WARNING, an error code).
 */
export type Style = Readonly<{ paint(text: string, tone: "forge" | "secondary"): string; state(word: StateWord): string; strong(text: string): string; glyph: string }>;
const STATE_TONE: Readonly<Record<StateWord, Tone>> = Object.freeze({ ALLOW: "allow", DENY: "deny", INDETERMINATE: "indeterminate", OPEN: "open" });
export const style = (env: Env = processEnv(), flag?: boolean): Style => {
  const colour = colourEnabled(env, flag);
  const ansi = (text: string, tone: Tone): string => (colour ? `\u001b[38;5;${PALETTE[tone]}m${text}\u001b[0m` : text);
  return Object.freeze({
    glyph: glyph(env),
    paint: (text: string, tone: "forge" | "secondary"): string => ansi(text, tone),
    state: (word: StateWord): string => ansi(word, STATE_TONE[word]),
    strong: (text: string): string => (colour ? `\u001b[1m${text}\u001b[22m` : text),
  });
};

/** The state word coloured by its meaning; any other word stays neutral. */
export function stateWord(s: Style, word: string): string {
  return (STATE_WORDS as readonly string[]).includes(word) ? s.state(word as StateWord) : word;
}

export const header = (s: Style): string => `${s.paint(`${s.glyph} irontrellis`, "forge")} ${VERSION} ${s.paint("—", "secondary")} ${TAGLINE}`;
export const dim = (s: Style, text: string): string => s.paint(text, "secondary");

/** Timestamps in a history are host-clock milliseconds in practice; small values (tests, fixtures) are printed as they are. */
export function formatTime(value: number | undefined): string {
  if (value === undefined) return "—";
  if (value >= 1e11 && value <= 8.64e15) return new Date(value).toISOString();
  return String(value);
}

export const plural = (count: number, singular: string, pluralForm = `${singular}s`): string => `${count} ${count === 1 ? singular : pluralForm}`;

/** Decimal strings for bigints; everything else as JSON.stringify sees it. */
const jsonReplacer = (_key: string, value: unknown): unknown => (typeof value === "bigint" ? value.toString() : value);
export const toJson = (value: unknown): string => `${JSON.stringify(value, jsonReplacer, 2)}\n`;

/** A line buffer so a command's human output is written once, after it succeeded. */
export class Lines {
  readonly #lines: string[] = [];
  add(...lines: readonly string[]): void {
    this.#lines.push(...lines);
  }
  blank(): void {
    this.#lines.push("");
  }
  text(): string {
    return this.#lines.length === 0 ? "" : `${this.#lines.join("\n")}\n`;
  }
}

/** Two-column key/value rows with aligned keys (secondary colour on the keys). */
export function rows(s: Style, pairs: readonly (readonly [string, string])[], indent = "  "): string[] {
  const width = Math.max(0, ...pairs.map(([key]) => key.length));
  return pairs.map(([key, value]) => `${indent}${dim(s, key.padEnd(width))}  ${value}`);
}
