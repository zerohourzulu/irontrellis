import type { AdditionalPolicy } from '@ramex-labs/irontrellis';
export declare function fgaObject(type: 'agent' | 'resource', id: string): string;
export declare function openFgaPolicy(options: Readonly<{ apiUrl: string; storeId: string; modelId: string; record: AdditionalPolicy['record'] }>): AdditionalPolicy;
