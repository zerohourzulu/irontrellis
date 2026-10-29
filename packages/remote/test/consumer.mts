import {createToolRegistry, REFERENCE_TOOLS, type CooperativeExecutor, type CooperativeClient} from '@ramex-labs/irontrellis-remote';
import {createIronTrellisTool} from '@ramex-labs/irontrellis-remote/langchain';
import {createLocalOwner, createLocalDomain} from '@ramex-labs/irontrellis-remote/local';
import {openLocalRuntime} from '@ramex-labs/irontrellis-remote/runtime';
import {openLocalAttemptRecorder} from '@ramex-labs/irontrellis-remote/attempts';
const registry=createToolRegistry({serviceId:'typed-service',account:'synthetic',tools:REFERENCE_TOOLS});
declare const executor: CooperativeExecutor;
declare const client: CooperativeClient;
createIronTrellisTool({registry,executor,tool:'notes.create',operationId:'typed-op',businessKey:'typed-case'});
executor.run({operationId:'typed-op',businessKey:'typed-case',tool:'notes.create',arguments:{title:'hello'}});
void createLocalOwner; void createLocalDomain; void openLocalRuntime; void openLocalAttemptRecorder;
// Removed legacy APIs must not be accepted by the installed declaration surface.
// @ts-expect-error inline checkpoint arrays have no format-2 authentication boundary
client.checkpoint([]);
// @ts-expect-error legacy history migration is deliberately unsupported
import {migrateDestinationHistory} from '@ramex-labs/irontrellis-remote';
