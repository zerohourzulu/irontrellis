import type { AdditionalPolicy } from '@ramex-labs/irontrellis';
/** Trusted local Cedar policy; engine errors conservatively refuse. */
export declare function cedarPolicy(source: string, record: AdditionalPolicy['record']): AdditionalPolicy;
