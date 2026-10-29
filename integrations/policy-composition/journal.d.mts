import type { PolicyEvidence } from '@ramex-labs/irontrellis';
/** One trusted writer, private directory, 1 MiB bounded durable journal. */
export declare function policyJournal(file: string): (evidence: PolicyEvidence) => void;
