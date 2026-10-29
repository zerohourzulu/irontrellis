import { claudeCode } from "./claude-code.ts";
import { codex } from "./codex.ts";
import { cursor } from "./cursor.ts";
import type { Protocol, ProtocolId } from "./types.ts";

export const PROTOCOLS: Readonly<Record<ProtocolId, Protocol>> = Object.freeze({ "claude-code": claudeCode, codex, cursor });

export const protocolFor = (id: string): Protocol | undefined => (Object.hasOwn(PROTOCOLS, id) ? PROTOCOLS[id as ProtocolId] : undefined);

export { claudeCode, codex, cursor };
export type { Protocol, ProtocolId, HookEvent, Verdict, ToolDecision, Reply, InstallEntry } from "./types.ts";
export { PROTOCOL_IDS } from "./types.ts";
