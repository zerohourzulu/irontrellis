import { DeterministicSimulatedAdapter } from "../../core-0.2/src/adapters/simulated-adapter.js";
import { openLocalExecution } from "./execution.js";
export { commitTerms } from "./execution.js";
/** Effect-free, signed local execution example; no adapter injection. */
export function openLocalSimulation(options) {
    return openLocalExecution(options, new DeterministicSimulatedAdapter(), "SIMULATION");
}
