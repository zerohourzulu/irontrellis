import { observeHistory, observeContinuationHistory } from "./observation.js";
/** Trusted host selection. Agent arguments cannot choose a store or a profile. */
import { PortableFileEventStore, PortableStoreConflictError } from "../../core-0.2/src/indexer/portable-file-event-store.js";
import { canonicalEncode } from "../../core-0.2/src/core/index.js";
import { ManagedLocalEventStore } from "./capacity.js";
import { openHistoryBinding } from "./history-store/index.js";
import { exportContinuationEvents, CONTINUATION_PROFILE } from "./history.js";
import { ContinuityError } from "./input.js";
export const SEGMENTED_HISTORY_PROFILE = CONTINUATION_PROFILE.version;
export class ConfiguredDirectoryEventStore extends PortableFileEventStore {
    directoryStore;
    constructor(binding) { super(binding); this.directoryStore = openHistoryBinding(binding); }
    readAll() { return exportContinuationEvents(this.directoryStore.snapshot().history); }
    withExclusiveWriter(callback) {
        return this.directoryStore.withWriter(writer => callback(Object.freeze({
            readAll: () => exportContinuationEvents(writer.snapshot().history),
            appendAtExpectedHead: (event, expected) => {
                const before = writer.snapshot();
                if (canonicalEncode(before.history.head) !== canonicalEncode(expected))
                    throw new PortableStoreConflictError(before.history.head);
                return writer.append(event, before.revision).history.head;
            },
        })));
    }
    appendAtExpectedHead(event, expected) {
        return this.withExclusiveWriter(writer => writer.appendAtExpectedHead(event, expected));
    }
    append(_event) { throw new ContinuityError("CAPACITY_EXPECTED_HEAD_REQUIRED"); }
    appendAll(_events) { throw new ContinuityError("CAPACITY_BATCH_UNSUPPORTED"); }
}
export function openConfiguredEventStore(location) {
    if (location.historyProfile === undefined) {
        if (location.historyBinding !== undefined || typeof location.historyFile !== "string")
            throw new ContinuityError("PROFILE_MISMATCH");
        return new ManagedLocalEventStore(location.historyFile);
    }
    if (location.historyProfile !== SEGMENTED_HISTORY_PROFILE || location.historyFile !== undefined || typeof location.historyBinding !== "string")
        throw new ContinuityError("PROFILE_MISMATCH");
    return new ConfiguredDirectoryEventStore(location.historyBinding);
}
export function observeConfiguredStore(store, options = {}) {
    return store instanceof ConfiguredDirectoryEventStore ? observeContinuationHistory(store.directoryStore.snapshot().history, options) : observeHistory(store.readAll(), options);
}
