# IronTrellis brand kit

This folder is the brand kit of IronTrellis (formerly Continuity): the logo files, the colors, the fonts and the design tokens, with a short guide to using them. Use it whenever the name or the logo appears, on a web page, a slide, a package listing or a terminal.

The rules themselves are the IronTrellis brand standard, BRAND-001 (revision 0.1, 23 September 2026; owner: RAmEx Labs), in `IronTrellis-Brand-Standard.pdf` (9 pages). This page summarizes it and points to the files. If this page and the PDF ever disagree, the PDF wins.

> **Agents change. The structure holds.**
> Authority, duties and succession for AI agents.

## What the standard covers

| Page | Section | What it sets |
|---|---|---|
| 2 | Essence | What the name means, the tagline, the voice and the boilerplate text |
| 3 | Logo system | The six forms of the logo, and when to use each |
| 4 | Construction | The mark's geometry, its clear space and its colors by part |
| 5 | Usage | Backgrounds, minimum sizes, small sizes and misuse |
| 6 | Color | The palette, its proportions, contrast and the product state colors |
| 7 | Typography | The three typefaces, the type scale and typographic details |
| 8 | Naming | How to write the name, the tagline, trademark notation and the product family |
| 9 | Applications | The README header, the social card, the terminal, icons, diagrams and the document header |

## Contents

| Path | What is in it | Use it for |
|---|---|---|
| `IronTrellis-Brand-Standard.pdf` | The standard itself, BRAND-001 | The full rules |
| `logo/svg/` | 16 master logo files, all text converted to outlines | Anything that can take vector art: web, docs, print |
| `logo/png/` | 25 transparent PNG exports | Places that need a bitmap: slides, chat avatars, stores |
| `logo/favicon.ico` | 16, 32 and 48 px in one file | Websites and docs sites |
| `social/` | Social preview card (1280 × 640) and README header (1280 × 320, plus @2x) | GitHub social preview; top of the README |
| `tokens/` | `irontrellis.css` (CSS custom properties) and `irontrellis.tokens.json` (W3C design-token format) | Websites, docs themes, CLIs, dashboards |
| `fonts/` | Desktop TTF, web WOFF2, `fonts.css`, and the font licenses | Installing the brand fonts, or self-hosting them on the web |
| `raster-jobs.json` | The list of the 25 PNG exports: each one's source SVG, width and background | Rendering the PNGs again at the same sizes |

## Which logo file

| Situation | File |
|---|---|
| Default, on light grounds (Plate or white) | `irontrellis-lockup-horizontal.svg` |
| Default, on dark grounds (Iron or Gunmetal) | `irontrellis-lockup-horizontal-reversed.svg` |
| Square spaces, title slides | `irontrellis-lockup-stacked.svg` or `-stacked-tagline.svg` (and their `-reversed` versions) |
| The mark is already nearby | `irontrellis-wordmark.svg` / `-wordmark-reversed.svg` |
| Symbol only, 32 px and up | `irontrellis-mark.svg` / `-mark-reversed.svg` |
| Avatars and app icons | `irontrellis-badge.svg` (not on Iron) |
| 24 px and below, favicons | `irontrellis-micro.svg` or `favicon.ico` |
| Single-ink work only: engraving, embroidery, stamps | `-black` and `-white` one-color files |

Never redraw, retype, recolor, rotate, stretch or add effects to the logo, and never set it where it has too little contrast. Keep clear space of X on every side, where X is the width of the orange Core (about 0.31 × the mark height).

| Minimum size | On screen | In print |
|---|---|---|
| Primary lockup | 120 px wide | 30 mm wide |
| Stacked lockup and wordmark | 80 px wide | 20 mm wide |
| Mark and badge | 32 px | 8 mm |
| Micro mark | 16–24 px | Not for print |

## Color

| Name | Hex | Role |
|---|---|---|
| Iron | `#15181C` | Primary dark: text on light, dark surfaces, the mark on light |
| Gunmetal | `#2A3038` | Secondary dark surfaces, code blocks on dark |
| Steel | `#5C6773` | "TRELLIS" on light; secondary text on light |
| Pewter | `#9AA4AE` | "TRELLIS" on dark; secondary text on dark |
| Alloy | `#C9CFD5` | The mark on dark; rules and borders on light |
| Plate | `#F3F2EE` | Primary light background |
| Forge | `#E8692A` | The Core, one rule, one highlight. **Never text on light grounds** (2.9 : 1) |
| Ember | `#B24C14` | Orange text and links on light grounds |

The four product states have their own colors. They are for the product (CLI, UI, docs), never the logo. Always print the state word as well as the color.

| State | Meaning | On light | On dark | ANSI-256 |
|---|---|---|---|---|
| ALLOW | Permission established | `#1E6E43` | `#45B57A` | 35 |
| DENY | Refused by current rules | `#B12F29` | `#F0675D` | 203 |
| INDETERMINATE | Cannot decide from the evidence | `#8A6207` | `#D9A21B` | 178 |
| OPEN | A duty still owed | `#2A62A0` | `#6FA6DE` | 74 |

Forge in a terminal: ANSI-256 color 208.

## Type

| Voice | Family | Weights in the kit | Use |
|---|---|---|---|
| Display | Barlow Condensed | 500, 600, 700 | Wordmark, headlines, titles; uppercase, tracked +40 to +100 |
| Text | IBM Plex Sans | 400, 400 italic, 500, 600 | Body copy, docs, interfaces |
| Code and control | IBM Plex Mono | 400, 500, 600 | Code, CLI output, identifiers, labels, control banners |

Where the fonts cannot be embedded (shared slides, office files), use Arial Narrow Bold for display, Arial for text, and Consolas or Menlo for code. No other substitutes.

On the web:

```html
<link rel="stylesheet" href="fonts/fonts.css">
<link rel="stylesheet" href="tokens/irontrellis.css">
<style>
  body { background: var(--irontrellis-bg); color: var(--irontrellis-fg); font-family: var(--irontrellis-font-text); }
  code { font-family: var(--irontrellis-font-mono); }
</style>
```

The semantic tokens (`--irontrellis-bg`, `-fg`, `-fg-muted`, `-rule`, `-accent`, `-link` and the four states) follow the reader's system: in dark mode they switch to their dark values, unless the page sets `data-theme="light"`, and `data-theme="dark"` forces dark. `-accent` is Forge in both.

## Name

| Write | Where |
|---|---|
| **IronTrellis** | Running text, titles and speech: one word, capital I and T |
| IRONTRELLIS | The wordmark and control banners only |
| `irontrellis` | Code, packages, commands, URLs and repositories |

Never write "Iron Trellis" (two words), "Irontrellis" or "IRONtrellis" (altered casing), "Trellis" (shortened), or "IT", "I.T." or "ITR" (abbreviated, even in identifiers).

- **During the transition,** write "IronTrellis (formerly Continuity)" on first mention, then IronTrellis alone.
- **Components** are IronTrellis plus a plain noun, for example "IronTrellis MCP Gateway" (`@ramex-labs/irontrellis-mcp-gateway`).
- **The trademark symbol** goes on the name only at its first prominent mention in marketing, while the name is unregistered; the registered symbol comes only after registration. Never use either in code, CLI output or running documentation.

## Licenses

The fonts are licensed under the SIL Open Font License 1.1. See `fonts/OFL-BarlowCondensed.txt` and `fonts/OFL-IBMPlex.txt`. They can be bundled and redistributed with the software, but may not be sold on their own.

The IronTrellis name and logo identify the project. The software's Apache-2.0 license does not grant rights to use them as trademarks (section 6). Use them to refer to IronTrellis, following BRAND-001. The name has not yet been cleared against trademark registers.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
