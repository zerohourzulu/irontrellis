/**
 * Trusted integration-host interface (port of Core 0.3 `adapter.ts`): the
 * engine functions an adapter author needs, without the `Portable` prefix.
 * Never expose these handles as agent tools.
 */
export {
  ADAPTER_POLICY_E5_HASH, REMOTE_SERVICE_REPORT_ADAPTER_ID, approvedAdapterProfileForPolicy, createRemoteServiceReportAcknowledgment, adapterAcknowledgmentEvidence,
} from "./adapter-editions.ts";
export type { AdapterAcknowledgment as RemoteServiceReportAcknowledgment } from "./adapter-editions.ts";
export { canonicalEncode, captureValue as immutableProtocolValue } from "./canonical.ts";
export { hashCanonical } from "./hash.ts";
export { deriveAdapterIdentity, admissionControlIsCurrent } from "./admission.ts";
export { evaluateReceiptPolicy } from "./authority.ts";
// Independent review step 5b §0: the adapter subpath hands out the public store (format 2 writes only, A-185.3), never store.ts.
export { openHistoryStore, createHistoryStore } from "./store-public.ts";
export type { HistoryStore } from "./store.ts";
export type { TransactionAdapter, AdmittedTransactionSubmission, AdapterSubmissionResult } from "./coordinators.ts";
export { openLocalExecution } from "./execution.ts";
export type { LocalExecutionOptions } from "./execution.ts";
export { captureHistory, replayHistory, observeHistory, observeState } from "./observation.ts";
export { captureData, record, identifier, requireCondition } from "./input.ts";
export type { AuthorizationDomain, CanonicalEvent, HistoryHead, ReplayState } from "./types.ts";
// Storage on format 2: the configured store, the state, and history transfer through the export view.
export {
  HISTORY_PROFILE, openConfiguredEventStore, stateOf, TRANSFER_VERSION, TRANSFER_STORAGE_LIMITS, createHistoryTransfer, openCheckpointStorage,
} from "./adapter-storage.ts";
export type {
  HistoryLocation, ConfiguredEventStore, ExportViewHeader, TransferSegment, TransferManifest, HistoryTransfer, VerifiedHistory, CheckpointStorage, CheckpointStorageHooks, TransferErrorCode,
} from "./adapter-storage.ts";
export { EXPORT_VERSION, exportView, verifyExportView } from "./export-view.ts";
export type { ExportView, ExportViewInput, ExportVerification } from "./export-view.ts";
export { capacityOf, CAPACITY_PROFILE } from "./capacity.ts";
export type { CapacityReport } from "./capacity.ts";
