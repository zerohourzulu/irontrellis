# Third-party dependencies

The base package uses Node built-ins and depends on the separately installed Apache-2.0 shared Core package. It contains no engine copy.

The optional LangChain entry uses separately installed `@langchain/core` (1.2.18 or a later 1.x) and `zod` 4.6.5, both MIT licensed. Their packages and transitive dependencies retain their own license files. No dependency code is copied into this package.

The package ships its ES modules and type declarations as written, with no build step. Node is supplied separately under its own license.
