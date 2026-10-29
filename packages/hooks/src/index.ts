/**
 * `@ramex-labs/irontrellis-hooks`: the pieces behind the `irontrellis-hook`
 * command, exported for hosts that embed the same behaviour (custom protocols,
 * tests). The command itself is `bin/irontrellis-hook.mjs` → `main`.
 */
export { main, VERSION } from "./cli.ts";
export type { CliIo } from "./cli.ts";
export { recordToolRefusal } from "./refusals.ts";
export { runHook, OWN_SKILL, openOwner, ensureAgent, admitSession, sessionStatus, sessionKeys, releaseSessionKey, sessionKeyFile, handoverFile, decideTool, writeHandover, openingContext, refusalText, endingSummary, capabilities, failOpenFor, failOpenForRoute, HANDOVER_VERSION, SESSION_KEY_VERSION } from "./hook.ts";
export type { HookIo, Admission, SessionStatus, SessionKeyRecord, DecideOptions } from "./hook.ts";
export { loadConfig, loadConfigFile, findConfigFile, validateConfig, HookConfigError, CONFIG_FILE, CONFIG_ENV, CONFIG_VERSION } from "./config.ts";
export type { HookConfig, Policy, Rule, Decisions } from "./config.ts";
export {
  protection, configProtection, guardProjects, inIronTrellisCheckout, hookEntryProgram, HOOK_WRAPPER, controlCommand, custodyCommand, custodyOf, commandSpellings, referencesProtected, protectedTargets, PROTECTED_STRINGS, CONTROL_BINARIES, CUSTODY_BINARIES, VAULT_BINARIES, VAULT_REASON, SSH_AGENT_PATTERNS, VAULT_PATTERNS, WRITING_SUBCOMMANDS, WRITING_PAIRS, WRITING_FLAGS, CONTROL_REASON, setupRefusal,
  CUSTODY_REASON, SHELL_TOOLS, FILE_TOOLS,
} from "./protect.ts";
export type { Protection } from "./protect.ts";
export { defaultStateDir, defaultStateHome, sessionsDir, handoversDir, ownerKeyPath, sessionFileName, writePrivateFile, STATE_HOME_ENV } from "./paths.ts";
export { mapTool, renderTemplate, toolMatches, mcpParts, staticCapabilities } from "./policy.ts";
export type { Mapping, TemplateContext } from "./policy.ts";
export { codexConfigFiles, codexHooksSetting, init, install, mergeSettings, planSettings, lossyNumber, writeSettingsAtomically, describeChanges, unifiedDiff, listSessions, releaseSessions, sameUserWarning, signerHeldWarning, SHELL_ACTIONS } from "./setup.ts";
export type { InitOptions, InitResult, InstallChange, InstallOptions, InstallResult, PlanOptions, SessionEntry, SettingsPlan } from "./setup.ts";
export { PROTOCOLS, protocolFor, claudeCode, codex, cursor, PROTOCOL_IDS } from "./protocols/index.ts";
export type { Protocol, ProtocolId, HookEvent, Verdict, ToolDecision, Reply, InstallEntry } from "./protocols/index.ts";
