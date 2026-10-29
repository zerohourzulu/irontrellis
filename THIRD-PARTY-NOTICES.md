# Third-party notices

IronTrellis-authored material is licensed under the Apache License, Version 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). The material below comes from third parties and keeps its own copyright and licence.

## Published test vectors

These vectors are copied verbatim from their published sources (fetched 25 September 2026). The files that use them name the exact source files.

| Source | Copyright and licence | Used in |
| --- | --- | --- |
| [transparency-dev/merkle](https://github.com/transparency-dev/merkle): `testonly/constants.go` (branch main) and `proof/verify_test.go` (tag v0.0.2) | Copyright 2017 and 2019 Google LLC. Apache License, Version 2.0 | `packages/core/test/transparency-merkle.test.mjs`; `conformance/transparency/vectors.json` (vectors with source `transparency-dev/merkle`) |
| [golang.org/x/mod/sumdb/note](https://github.com/golang/mod): `sumdb/note/note_test.go` (branch master) | Copyright 2019 The Go Authors. BSD-style licence (the LICENSE file of github.com/golang/mod) | `packages/core/test/transparency-note.test.mjs`; `conformance/transparency/vectors.json` (source `golang.org/x/mod/sumdb/note`) |
| [C2SP](https://github.com/C2SP/C2SP): `signed-note.md` and `tlog-checkpoint.md` (branch main), their example keys, notes and checkpoint | C2SP specifications are licensed under CC BY 4.0 | `packages/core/test/transparency-note.test.mjs`; `conformance/transparency/vectors.json` (sources `c2sp.org/signed-note`, `c2sp.org/tlog-checkpoint`) |

## Fonts

| Font | Files | Licence |
| --- | --- | --- |
| IBM Plex Sans, IBM Plex Mono | `brand/fonts/desktop/IBMPlex*.ttf`, `brand/fonts/web/IBMPlex*.woff2` | SIL Open Font License 1.1, [brand/fonts/OFL-IBMPlex.txt](brand/fonts/OFL-IBMPlex.txt) |
| Barlow Condensed | `brand/fonts/desktop/BarlowCondensed-*.ttf`, `brand/fonts/web/BarlowCondensed-*.woff2` | SIL Open Font License 1.1, [brand/fonts/OFL-BarlowCondensed.txt](brand/fonts/OFL-BarlowCondensed.txt) |

## Continuity

`packages/reference-0.2`, `packages/reference-0.3` and `conformance/legacy` keep material from Continuity (Copyright 2026 Continuity contributors, Apache License, Version 2.0). Those folders carry their own LICENSE and NOTICE.

## Dependencies

No dependency code is bundled. Dependencies are installed from `pnpm-lock.yaml` and keep their own licence files; [packages/remote-tools/THIRD-PARTY-NOTICES.md](packages/remote-tools/THIRD-PARTY-NOTICES.md) lists the remote tools' optional ones.
