#!/usr/bin/env node
/** Explicit operator maintenance; never expose these filesystem commands as agent tools. */
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { DirectoryHistoryStore, readSnapshot, prepareMigration, stageMigration, activateMigration, inspectMigration, recoverLock, lockRecord } from './index.ts';
import { read } from './files.ts';
import { parse, exact, fail } from './codec.ts';
function operatorJson(path: string) {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(read(path, 32768)));
}
function main() {
    const [command, ...args] = process.argv.slice(2);
    const print = (v: unknown) => process.stdout.write(JSON.stringify(v, null, 2) + '\n');
    if (command === '--help') {
        console.log('continuity-history-store: inspect DIR | prepare-migration CONFIG.json | stage PLAN.json --quiesced | activate PLAN.json --quiesced | migration-status PLAN.json | lock-info DIR [NAME] | recover-lock DIR SHA256 [NAME] | orphans DIR | cleanup-orphans DIR INVENTORY.json');
        return;
    }
    if (command === '--version' && args.length === 0) {
        console.log(JSON.parse(readFileSync(new URL('../../../../package.json', import.meta.url), 'utf8')).version);
        return;
    }
    if (command === 'inspect' && args.length === 1) {
        const s = readSnapshot(args[0]!, true);
        print({ phase: s.manifest.phase, revision: s.revision, capacity: s.capacity, scope: 'CAPTURED_HISTORY_ONLY', executionCapability: false });
        return;
    }
    if (command === 'prepare-migration' && args.length === 1) {
        const data = operatorJson(args[0]!);
        exact(data, ['sourceFile', 'targetDirectory', 'planFile', 'expectedHead', 'configurationFiles', 'artifactFiles', 'quiesced']);
        print(prepareMigration(data as Parameters<typeof prepareMigration>[0]));
        return;
    }
    if ((command === 'stage' || command === 'activate') && args.length === 2 && args[1] === '--quiesced') {
        const result = (command === 'stage' ? stageMigration : activateMigration)(args[0]!, { quiesced: true });
        print({ phase: result.manifest.phase, revision: result.revision });
        return;
    }
    if (command === 'migration-status' && args.length === 1) {
        print(inspectMigration(args[0]!));
        return;
    }
    if (command === 'lock-info' && (args.length === 1 || args.length === 2)) {
        const name = args[1] ?? '.writer-lock';
        if (name.includes('/') || name.includes('\\'))
            fail('PATH_INVALID');
        const lock = lockRecord(join(args[0]!, name));
        print({ record: lock.record, sha256: lock.sha256 });
        return;
    }
    if (command === 'recover-lock' && (args.length === 2 || args.length === 3)) {
        recoverLock(args[0]!, args[1]!, args[2] ?? '.writer-lock');
        print({ recovered: true });
        return;
    }
    if (command === 'orphans' && args.length === 1) {
        const store = new DirectoryHistoryStore(args[0]!);
        print({ revision: store.snapshot().revision, orphans: store.inspectOrphans() });
        return;
    }
    if (command === 'cleanup-orphans' && args.length === 2) {
        const selected = operatorJson(args[1]!);
        exact(selected, ['revision', 'orphans']);
        print({ removed: new DirectoryHistoryStore(args[0]!).cleanupOrphans(selected.revision, selected.orphans) });
        return;
    }
    fail('USAGE_ERROR');
}
try {
    main();
}
catch (error) {
    process.stderr.write('continuity-history-store: ' + ((error as any)?.code ?? 'OPERATION_FAILED') + '\n');
    process.exitCode = 1;
}
