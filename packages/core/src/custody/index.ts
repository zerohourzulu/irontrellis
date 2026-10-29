/** Owner-key custody (docs/CUSTODY.md): key references, the signer-backend registry and the built-in backends. */
export {
  OWNER_KEY_REF_VERSION, OWNER_NEXT_KEY_REF_VERSION, parseKeyReference, keyReference, keyReferenceText, withReferenceVersion, referenceSigner, publicKeySigner,
  parsePublicKey, sshPublicKeyOf,
} from "./reference.ts";
export type { OwnerKeyReference, KeyReferenceVersion, SignerCustody } from "./reference.ts";
export { registerSignerBackend, signerBackend, signerBackendKinds, SIGN_PURPOSES } from "./registry.ts";
export type { SignerBackend, SignerSpec, SignContext, SignPurpose, ReferencedKey } from "./registry.ts";
export {
  agentSocketPath, listAgentIdentities, parseSshPublicKey, sshPublicKeyLine, sshEd25519Blob, decodeKeyBlob, openSshPrivateKey, WINDOWS_AGENT_PIPE, DEFAULT_AGENT_TIMEOUT_MS,
  ED25519_KEY_TYPE, SK_ED25519_KEY_TYPE,
} from "./ssh-agent.ts";
export type { AgentIdentity, AgentConnector } from "./ssh-agent.ts";
export { SIGN_REQUEST_VERSION, DEFAULT_COMMAND_TIMEOUT_MS, COMMAND_SIGNER_PATH, commandEnvironment, stderrTail } from "./command.ts";
export { DEFAULT_VAULT_MOUNT, DEFAULT_VAULT_TIMEOUT_MS, normalizeVaultAddress, readVaultKey, checkVaultKey, vaultTokenSource, vaultCaFile } from "./vault-transit.ts";
export type { VaultKeyInfo } from "./vault-transit.ts";
