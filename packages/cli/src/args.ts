/**
 * Hand-rolled argv parsing: long options only (`--name value`, `--name=value`,
 * `--flag`, `--no-flag`), comma-separated or repeated lists, `--` to end
 * options, and positionals. Every command declares its options up front, so an
 * unknown or malformed option is a usage error before anything is opened.
 */
import { codePointLength } from "@ramex-labs/irontrellis";

export type OptionKind = "string" | "number" | "boolean" | "list";
export type OptionSpec = Readonly<{
  name: string;
  kind: OptionKind;
  help: string;
  /** Placeholder shown in help for valued options (default `<value>`). */
  value?: string;
  required?: boolean;
  /** The value (each value, for a list) is an identifier the owner API checks: see `checkIdentifier`. */
  identifier?: boolean;
}>;
export type OptionValue = string | number | boolean | readonly string[];
export type Parsed = Readonly<{ positionals: readonly string[]; options: ReadonlyMap<string, OptionValue> }>;

export class UsageError extends Error {
  readonly code = "USAGE" as const;
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

/**
 * An argument the engine would refuse as `INVALID_INPUT`, caught first so the
 * message can name the argument and the limit (the owner API's own error is a
 * bare code).
 */
export class InputError extends Error {
  readonly code = "INVALID_INPUT" as const;
  constructor(message: string) {
    super(message);
    this.name = "InputError";
  }
}

/** The owner API's identifier and list limits (packages/core/src/input.ts `identifier` / `identifiers`). */
export const MAX_IDENTIFIER_LENGTH = 128;
export const MAX_LIST_LENGTH = 32;

/** One identifier: non-empty, at most 128 characters, no control characters, well-formed Unicode. */
export function checkIdentifier(label: string, value: string): string {
  if (value.length === 0) throw new InputError(`${label} is empty`);
  const length = codePointLength(value); // characters are code points (A-89.2), as the owner API counts them
  if (length > MAX_IDENTIFIER_LENGTH) throw new InputError(`${label} is ${length} characters long; identifiers are limited to ${MAX_IDENTIFIER_LENGTH}`);
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new InputError(`${label} contains a control character`);
  if (!(value as string & { isWellFormed(): boolean }).isWellFormed()) throw new InputError(`${label} is not well-formed Unicode (an unpaired surrogate)`);
  return value;
}

/** A list of identifiers: at most 32 distinct values, each an identifier. */
export function checkIdentifiers(label: string, values: readonly string[]): readonly string[] {
  if (values.length > MAX_LIST_LENGTH) throw new InputError(`${label} has ${values.length} values; a list is limited to ${MAX_LIST_LENGTH}`);
  const seen = new Set<string>();
  for (const value of values) {
    checkIdentifier(`${label} value "${value.length > 40 ? `${value.slice(0, 40)}…` : value}"`, value);
    if (seen.has(value)) throw new InputError(`${label} lists "${value}" more than once`);
    seen.add(value);
  }
  return values;
}

const INTEGER = /^(0|[1-9][0-9]*)$/;

const convert = (spec: OptionSpec, raw: string | undefined, previous: OptionValue | undefined): OptionValue => {
  switch (spec.kind) {
    case "boolean": {
      if (raw === undefined || raw === "true") return true;
      if (raw === "false") return false;
      throw new UsageError(`--${spec.name} takes no value (or true/false), got "${raw}"`);
    }
    case "string": {
      if (raw === undefined || raw === "") throw new UsageError(`--${spec.name} needs a value`);
      return raw;
    }
    case "number": {
      if (raw === undefined || !INTEGER.test(raw) || !Number.isSafeInteger(Number(raw))) throw new UsageError(`--${spec.name} needs a non-negative integer, got "${raw ?? ""}"`);
      return Number(raw);
    }
    case "list": {
      if (raw === undefined || raw === "") throw new UsageError(`--${spec.name} needs one or more comma-separated values`);
      const items = raw.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
      if (items.length === 0) throw new UsageError(`--${spec.name} needs one or more comma-separated values`);
      return [...((previous as readonly string[] | undefined) ?? []), ...items];
    }
  }
};

/** Parse `argv` against `specs`. Positionals are returned in order; options are converted by kind. */
export function parseArgs(argv: readonly string[], specs: readonly OptionSpec[]): Parsed {
  const byName = new Map(specs.map((spec) => [spec.name, spec]));
  const options = new Map<string, OptionValue>();
  const positionals: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--") {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (!arg.startsWith("--")) {
      if (arg.startsWith("-") && arg.length > 1) throw new UsageError(`short options are not supported: "${arg}" (use --name)`);
      positionals.push(arg);
      continue;
    }
    const eq = arg.indexOf("=");
    let name = eq < 0 ? arg.slice(2) : arg.slice(2, eq);
    let raw: string | undefined = eq < 0 ? undefined : arg.slice(eq + 1);
    let negated = false;
    if (!byName.has(name) && name.startsWith("no-") && byName.get(name.slice(3))?.kind === "boolean") {
      name = name.slice(3);
      negated = true;
    }
    const spec = byName.get(name);
    if (spec === undefined) throw new UsageError(`unknown option --${name}`);
    if (negated) {
      if (raw !== undefined) throw new UsageError(`--no-${name} takes no value`);
      options.set(name, false);
      continue;
    }
    if (raw === undefined && spec.kind !== "boolean") {
      const next = argv[i + 1];
      if (next === undefined || (next.startsWith("--") && next !== "--")) throw new UsageError(`--${name} needs a value`);
      raw = next;
      i += 1;
    } else if (raw === undefined && spec.kind === "boolean" && (argv[i + 1] === "true" || argv[i + 1] === "false")) {
      raw = argv[i + 1];
      i += 1;
    }
    if (spec.kind !== "list" && options.has(name)) throw new UsageError(`--${name} given more than once`);
    options.set(name, convert(spec, raw, options.get(name)));
  }
  for (const spec of specs) {
    if (spec.required && !options.has(spec.name)) throw new UsageError(`--${spec.name} is required`);
    const value = options.get(spec.name);
    if (spec.identifier !== true || value === undefined) continue;
    if (spec.kind === "list") checkIdentifiers(`--${spec.name}`, value as readonly string[]);
    else if (spec.kind === "string") checkIdentifier(`--${spec.name}`, value as string);
  }
  return Object.freeze({ positionals: Object.freeze(positionals), options });
}

/** Typed accessors over a parsed option map. */
export const str = (p: Parsed, name: string): string | undefined => p.options.get(name) as string | undefined;
export const num = (p: Parsed, name: string): number | undefined => p.options.get(name) as number | undefined;
export const flag = (p: Parsed, name: string): boolean => p.options.get(name) === true;
export const list = (p: Parsed, name: string): readonly string[] | undefined => p.options.get(name) as readonly string[] | undefined;
export const need = (p: Parsed, name: string): string => {
  const value = str(p, name);
  if (value === undefined) throw new UsageError(`--${name} is required`);
  return value;
};

/**
 * Exactly `count` positionals, each named for the error message. They are
 * identifiers (checked as such) unless `identifiers` is false (file paths).
 */
export function positionals(p: Parsed, names: readonly string[], identifiers = true): readonly string[] {
  if (p.positionals.length < names.length) throw new UsageError(`missing <${names[p.positionals.length]}>`);
  if (p.positionals.length > names.length) throw new UsageError(`unexpected argument "${p.positionals[names.length]}"`);
  if (identifiers) p.positionals.forEach((value, index) => checkIdentifier(`<${names[index]}>`, value));
  return p.positionals;
}

/** One help block: usage line, then the options aligned in two columns. */
export function formatOptions(specs: readonly OptionSpec[]): string {
  const rows = specs.map((spec) => {
    const placeholder = spec.kind === "boolean" ? "" : ` ${spec.value ?? "<value>"}`;
    return [`--${spec.name}${placeholder}`, `${spec.help}${spec.required ? " (required)" : ""}`] as const;
  });
  const width = Math.max(0, ...rows.map(([left]) => left.length));
  return rows.map(([left, right]) => `  ${left.padEnd(width)}  ${right}`).join("\n");
}
