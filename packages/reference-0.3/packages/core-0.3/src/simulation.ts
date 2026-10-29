import { DeterministicSimulatedAdapter } from "../../core-0.2/src/adapters/simulated-adapter.ts";
import { openLocalExecution, type LocalExecutionOptions } from "./execution.ts";
export { commitTerms } from "./execution.ts";
export type {
  SignHash,
  LocalExecutionOptions as LocalSimulationOptions,
  LocalOperation as SimulationOperation,
} from "./execution.ts";
/** Effect-free, signed local execution example; no adapter injection. */
export function openLocalSimulation(options: LocalExecutionOptions) {
  return openLocalExecution(
    options,
    new DeterministicSimulatedAdapter(),
    "SIMULATION",
  );
}
export type LocalSimulation = ReturnType<typeof openLocalSimulation>;
