import type { LocalOwner, LocalOwnerOptions, EvidenceToolOptions } from '@ramex-labs/irontrellis';
export type Demo = Readonly<{ configFile: string; config: Omit<EvidenceToolOptions, 'now' | 'signHash' | 'additionalPolicy'> & { keyFile: string }; ownerConfig: Omit<LocalOwnerOptions, 'now'>; owner: LocalOwner }>;
/** Creates a fresh signed format-2 synthetic case and disposable Ed25519 runtime. */
export declare function createDemo(target: string): Promise<Demo>;
