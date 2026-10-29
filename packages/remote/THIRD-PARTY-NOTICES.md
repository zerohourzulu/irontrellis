# Third-party dependencies

The base package uses Node built-ins and depends on two separately installed Apache-2.0 IronTrellis packages: the shared Core package (`@ramex-labs/irontrellis`) and `@ramex-labs/irontrellis-remote-tools`. It contains no copy of either.

The optional LangChain entry (`@ramex-labs/irontrellis-remote/langchain`) uses separately installed `@langchain/core` 1.2.12 and `zod` 4.6.5, both MIT licensed. Their packages and transitive dependencies retain their own license files. No dependency code is copied into this package.

The package ships its ES modules as written, with no build step. Node is supplied separately under its own license.
