// Deterministic fuzz smoke run (fuzz/README.md): the regression vectors and a short seeded campaign for the
// engine-level targets: canonical JSON, event validation, replay of mutated histories (TypeScript against Python
// through the conformance adapters), history stores (file, pin, anchors, side file), the witness side file against a
// live witness, and the witness wire formats. Uses the built packages (pnpm -r build).
import { test } from "node:test";
import { registerSmokeTests } from "../../../fuzz/lib/smoke.mjs";

registerSmokeTests(test, ["canonical", "events", "replay", "store", "sidefile", "transparency"]);
