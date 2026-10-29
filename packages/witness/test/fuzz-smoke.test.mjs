// Deterministic fuzz smoke run (fuzz/README.md): HTTP requests, valid and mutated, against a live witness server,
// with its regression vectors. Uses the built packages (pnpm -r build).
import { test } from "node:test";
import { registerSmokeTests } from "../../../fuzz/lib/smoke.mjs";

registerSmokeTests(test, ["witness-http"]);
