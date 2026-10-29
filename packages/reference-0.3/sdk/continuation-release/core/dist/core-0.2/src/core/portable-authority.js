export * from "./portable-authority-engine.js";
import { authorizeCapturedPortableState, capturedPortableAuthorizeInputIsStructurallyValid, capturePortableAuthorityOperation, portableReplayAuthorizationIndeterminate, } from "./portable-authority-engine.js";
import { createPortableReplayKernel, isPortableReplayState, } from "./portable-replay.js";
/** Authoritative replay-bound authorization. */
export const authorizePortable = (input) => {
    const kernel = createPortableReplayKernel();
    const captured = capturePortableAuthorityOperation(input, "AUTHORIZE", kernel.visit);
    if (captured.status !== "CAPTURED") {
        return portableReplayAuthorizationIndeterminate(captured.status === "UNSUPPORTED_VERSION"
            ? "UNSUPPORTED_VERSION"
            : captured.status === "STATE_NOT_AUTHORITATIVE"
                ? "STATE_NOT_AUTHORITATIVE"
                : "INVALID_INPUT");
    }
    if (!capturedPortableAuthorizeInputIsStructurallyValid(captured.capture)) {
        return portableReplayAuthorizationIndeterminate("INVALID_INPUT");
    }
    const replay = kernel.finish();
    if (replay.status === "REJECTED") {
        const replayCode = replay.result.status === "REJECTED"
            ? replay.result.code
            : undefined;
        return portableReplayAuthorizationIndeterminate(replayCode === "UNSUPPORTED_VERSION" ||
            replayCode === "UNSUPPORTED_EVENT_SCHEMA" ||
            replayCode === "UNSUPPORTED_EVENT_TYPE"
            ? "UNSUPPORTED_VERSION"
            : "STATE_NOT_AUTHORITATIVE");
    }
    if (!isPortableReplayState(replay.state)) {
        return portableReplayAuthorizationIndeterminate("STATE_NOT_AUTHORITATIVE");
    }
    return authorizeCapturedPortableState(captured.capture, replay.state);
};
