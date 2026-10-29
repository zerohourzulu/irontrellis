// Deterministic fuzz smoke run (fuzz/README.md): the irontrellis command line with valid and mutated argument
// vectors against a real history, with its regression vectors. Uses the built packages (pnpm -r build).
import { test } from "node:test";
import { registerSmokeTests } from "../../../fuzz/lib/smoke.mjs";

registerSmokeTests(test, ["cli-args"]);
