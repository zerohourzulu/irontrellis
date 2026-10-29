/**
 * `@ramex-labs/irontrellis-witness`: the IronTrellis witness server as a
 * library. The command (`irontrellis-witness`) is a thin layer over these.
 */
export { Witness, WITNESS_PROTOCOL_VERSION, epochsWire } from "./witness.ts";
export type { Reply, Logger, WitnessOptions } from "./witness.ts";
export { createWitnessServer, clientAddress, RateLimiter, BODY_LIMIT, REGISTER_BODY_LIMIT } from "./server.ts";
export type { WitnessServer, WitnessServerOptions } from "./server.ts";
export { ERROR_CODES, emptyState, applyEntry, decideRegister, decideHead, decideKeyEvent, MAX_EQUIVOCATIONS_PER_HISTORY, headOf } from "./state.ts";
export type { WitnessErrorCode, WitnessState, HistoryState, HeldHead, HeadRef, Decision, DecideContext, EntryLookup, ApplyOptions, KeyEventRoute, KeyEventRecord } from "./state.ts";
export {
  loadConfig, normalizeConfig, loadWitnessKey, initDataDir, hashToken, newAdminToken, tokenMatches, parseListen, defaultOrigin, isValidWitnessName, isValidOrigin,
  ConfigError, DEFAULTS, DEFAULT_LISTEN, KEY_FILE_VERSION,
} from "./config.ts";
export type { WitnessConfig, RateLimitConfig, WitnessKey, InitResult } from "./config.ts";
export { checkLog } from "./check.ts";
export type { CheckReport, CheckProblem } from "./check.ts";
export { DataError, LOG_FILE, CHECKPOINTS_FILE, LOCK_FILE, KEY_FILE, CONFIG_FILE, acquireServerLock } from "./log.ts";
export { main, serve, importKeyEvents, jsonLogger, VERSION, SOFTWARE, HELP, reloadAdminTokens, watchAdminTokens, serveSignals, defaultReloadIntervalMs } from "./cli.ts";
export type { ServeHandle } from "./cli.ts";
