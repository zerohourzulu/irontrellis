export function selectInput(inputDirectory: any): any;
export function createPacketExecutor({ inputDirectory, outputDirectory, selection, termsCommitment, resource, domain, intentId: configuredIntentId }: {
    inputDirectory: any;
    outputDirectory: any;
    selection: any;
    termsCommitment: any;
    resource: any;
    domain: any;
    intentId: any;
}): Readonly<{
    adapterProfile: Readonly<{
        profileId: "adapter:simulated" | "adapter:local-evidence-packet" | "adapter:local-synthetic-endpoint-state" | "adapter:local-document-release" | "adapter:remote-service-report";
        profileVersion: "1";
        descriptorHash: import("../../../core-0.2/src/core/canonical.ts").ContentHash;
    }>;
    submit: (submission: any) => Promise<any>;
    reconcile: (submission: any) => any;
    inspect: () => any;
}>;
