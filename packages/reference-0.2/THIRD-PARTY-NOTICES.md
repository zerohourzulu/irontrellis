# Third-party notices

This folder is a frozen copy of Continuity Core 0.2.2 and the Core 0.3 preview.8.2 SDK. No third-party code is bundled in it. Its tests use `viem` 2.55.19 (MIT), installed separately as a development dependency from the workspace lockfile, with its own licence. See also the repository's [THIRD-PARTY-NOTICES.md](../../THIRD-PARTY-NOTICES.md).

## The original file

Continuity's repository-level THIRD-PARTY-NOTICES.md, unchanged (sha256 f95de4309744f45b692a03788a984405207c5ba857b88b290ce74814e7aba2cc). It describes that repository's dependencies, fonts and integrations, most of which are not in this folder; its links point into the Continuity repository.

~~~text
# Third-party dependency notices

Dependencies are installed from the pinned lockfile, not bundled as executable binaries. Their original license texts are retained below. These notices do not replace the license terms. Node, pnpm, Python and an optional compiler are separately supplied tools.

| Package | Version | Declared license | Original text |
|---|---|---|---|
| @adraffy/ens-normalize | 1.11.1 | MIT | [license](licenses/@adraffy__ens-normalize-1.11.1/LICENSE) |
| @noble/ciphers | 1.3.0 | MIT | [license](licenses/@noble__ciphers-1.3.0/LICENSE) |
| @noble/curves | 1.9.1 | MIT | [license](licenses/@noble__curves-1.9.1/LICENSE) |
| @noble/hashes | 1.8.0 | MIT | [license](licenses/@noble__hashes-1.8.0/LICENSE) |
| @scure/base | 1.2.6 | MIT | [license](licenses/@scure__base-1.2.6/LICENSE) |
| @scure/bip32 | 1.7.0 | MIT | [license](licenses/@scure__bip32-1.7.0/LICENSE) |
| @scure/bip39 | 1.6.0 | MIT | [license](licenses/@scure__bip39-1.6.0/LICENSE) |
| abitype | 1.2.3 | MIT | [license](licenses/abitype-1.2.3/LICENSE) |
| eventemitter3 | 5.0.1 | MIT | [license](licenses/eventemitter3-5.0.1/LICENSE) |
| isows | 1.0.7 | MIT | [license](licenses/isows-1.0.7/LICENSE) |
| ox | 0.14.34 | MIT | [license](licenses/ox-0.14.34/LICENSE) |
| viem | 2.55.19 | MIT | [license](licenses/viem-2.55.19/LICENSE) |
| ws | 8.21.0 | MIT | [license](licenses/ws-8.21.0/LICENSE) |

## Website assets

Original generated graffiti and authored green branding are presentation assets. The stock style-reference image is not included. The previously bundled Permanent Marker font retains its [Apache license](website/fonts/PermanentMarker-LICENSE.txt).

## Optional protected evidence MCP integration

The separately installed MCP server/client2.0.0 are MIT-licensed packages from the Model Context Protocol project. Zod4.6.5 is MIT; viem2.55.19 is MIT. Exact transitive versions/integrities are in integrations/protected-evidence-mcp/package-lock.json and their installed packages retain their licenses. No dependency code is copied into the Core SDK. These packages run only when the optional integration is installed.

## Optional LangChain recipe

The separately installed LangChain1.5.12 and @langchain/core1.2.12 packages are MIT-licensed. The recipe uses their actual agent loop with a scripted model and the separately licensed MCP client/Zod dependencies. Exact transitive packages and integrities are pinned in integrations/langchain-evidence/package-lock.json; installed dependencies retain their own license files. No framework code is bundled in the Core SDK.

The optional policy examples separately install Cedar WASM 4.13.0 and OpenFGA SDK 0.9.7 (Apache-2.0). OpenFGA server 1.21.0 is downloaded separately under its upstream license; no server binary or policy dependency is bundled into the Core SDK. See the pinned example lockfile and installed dependency notices.
~~~
