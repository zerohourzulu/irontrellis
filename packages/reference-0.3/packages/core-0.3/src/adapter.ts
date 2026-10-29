/** Trusted integration-host interface. Never expose these handles as agent tools. */
export {
  PORTABLE_ADAPTER_POLICY_E5_HASH, REMOTE_SERVICE_REPORT_ADAPTER_ID,
  approvedPortableAdapterProfileForPolicy, canonicalEncode,
  createRemoteServiceReportAcknowledgment, derivePortableAdapterIdentity,
  hashCanonical, immutableProtocolValue, portableAdapterAcknowledgmentEvidence,
} from "../../core-0.2/src/core/index.ts";
export type {PortableAuthorizationDomain, PortableCanonicalEvent, PortableHistoryHead, RemoteServiceReportAcknowledgment} from "../../core-0.2/src/core/index.ts";
export {PortableFileEventStore} from "../../core-0.2/src/indexer/portable-file-event-store.ts";
export {portableAdmissionControlIsCurrent} from "../../core-0.2/src/core/portable-replay.ts";
export {evaluatePortableReceiptPolicy} from "../../core-0.2/src/core/portable-authority-engine.ts";
export {openLocalExecution} from "./execution.ts";
export type {LocalExecutionOptions} from "./execution.ts";
export {stateOf} from "./local-store.ts";
export {captureHistory} from "./observation.ts";
export {captureData, record, identifier, requireCondition} from "./input.ts";

export {capacityOf, LOCAL_CAPACITY_PROFILE} from "./capacity.ts";

export {openConfiguredEventStore, ConfiguredDirectoryEventStore, SEGMENTED_HISTORY_PROFILE, observeConfiguredStore} from "./configured-store.ts";
export {observeContinuationHistory} from "./observation.ts";

export {createHistoryTransfer, openCheckpointStorage, TRANSFER_VERSION, TRANSFER_STORAGE_LIMITS} from "./history-store/transfer.ts";
export {captureContinuationHistory, CONTINUATION_HISTORY_VERSION, exportContinuationEvents, continuationPrefix, CONTINUATION_PROFILE} from "./history.ts";

export type {HistoryLocation} from "./configured-store.ts";
export type {VerifiedHistory} from "./history.ts";
export {historyCapacity} from "./history-store/capacity.ts";
export {observeHistory} from "./observation.ts";
