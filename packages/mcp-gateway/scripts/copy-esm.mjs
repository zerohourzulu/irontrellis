#!/usr/bin/env node
// After `tsc`: copy the gateway's hand-written ES modules and their declarations from src/ to dist/. tsc compiles
// only src/**/*.ts. These files back the ./http, ./cooperative, ./tasks and ./access-http subpaths. The list is
// explicit: test files and helpers in src/ (`*-test*`) are never copied.
import { copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE = join(dirname(fileURLToPath(import.meta.url)), "..");
const FILES = [
  "access-http.mjs", "access-http-guard.mjs", "cooperative.mjs", "tasks.mjs",
  "http.mjs", "http-common.mjs", "http-private.mjs", "http-router.mjs", "http-server.mjs",
  "access-http.d.mts", "cooperative.d.mts", "tasks.d.mts", "http.d.mts", "http-router.d.mts",
];
for (const name of FILES) copyFileSync(join(PACKAGE, "src", name), join(PACKAGE, "dist", name));
