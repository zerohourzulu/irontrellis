import {observeHistory, observeContinuationHistory, type ObservationOptions} from "./observation.ts";
/** Trusted host selection. Agent arguments cannot choose a store or a profile. */
import { PortableFileEventStore, PortableStoreConflictError, type PortableStoreWriter } from "../../core-0.2/src/indexer/portable-file-event-store.ts";
import type { PortableCanonicalEvent, PortableHistoryHead } from "../../core-0.2/src/core/index.ts";
import { canonicalEncode } from "../../core-0.2/src/core/index.ts";
import { ManagedLocalEventStore } from "./capacity.ts";
import { DirectoryHistoryStore, openHistoryBinding } from "./history-store/index.ts";
import { exportContinuationEvents, CONTINUATION_PROFILE } from "./history.ts";
import { ContinuityError } from "./input.ts";
export const SEGMENTED_HISTORY_PROFILE = CONTINUATION_PROFILE.version;
export type HistoryLocation = { historyFile: string; historyProfile?: undefined; historyBinding?: never } |
  { historyProfile: typeof SEGMENTED_HISTORY_PROFILE; historyBinding: string; historyFile?: never };
export class ConfiguredDirectoryEventStore extends PortableFileEventStore {
  readonly directoryStore: DirectoryHistoryStore;
  constructor(binding: string) { super(binding); this.directoryStore = openHistoryBinding(binding); }
  override readAll() { return exportContinuationEvents(this.directoryStore.snapshot().history); }
  override withExclusiveWriter<T>(callback: (writer: PortableStoreWriter) => T): T {
    return this.directoryStore.withWriter(writer => callback(Object.freeze({
      readAll: () => exportContinuationEvents(writer.snapshot().history),
      appendAtExpectedHead: (event: PortableCanonicalEvent, expected: PortableHistoryHead) => {
        const before = writer.snapshot();
        if (canonicalEncode(before.history.head) !== canonicalEncode(expected)) throw new PortableStoreConflictError(before.history.head);
        return writer.append(event, before.revision).history.head;
      },
    })));
  }
  override appendAtExpectedHead(event: PortableCanonicalEvent, expected: PortableHistoryHead) {
    return this.withExclusiveWriter(writer => writer.appendAtExpectedHead(event, expected));
  }
  override append(_event: PortableCanonicalEvent): void { throw new ContinuityError("CAPACITY_EXPECTED_HEAD_REQUIRED"); }
  override appendAll(_events: readonly PortableCanonicalEvent[]): void { throw new ContinuityError("CAPACITY_BATCH_UNSUPPORTED"); }
}
export function openConfiguredEventStore(location: {historyFile?: string; historyBinding?: string; historyProfile?: string}) {
  if (location.historyProfile === undefined) {
    if (location.historyBinding !== undefined || typeof location.historyFile !== "string") throw new ContinuityError("PROFILE_MISMATCH");
    return new ManagedLocalEventStore(location.historyFile);
  }
  if (location.historyProfile !== SEGMENTED_HISTORY_PROFILE || location.historyFile !== undefined || typeof location.historyBinding !== "string")
    throw new ContinuityError("PROFILE_MISMATCH");
  return new ConfiguredDirectoryEventStore(location.historyBinding);
}

export function observeConfiguredStore(store: PortableFileEventStore, options: ObservationOptions = {}) {
  return store instanceof ConfiguredDirectoryEventStore ? observeContinuationHistory(store.directoryStore.snapshot().history, options) : observeHistory(store.readAll(), options);
}
