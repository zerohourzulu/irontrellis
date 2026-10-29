import { createAgent, fakeModel } from 'langchain';
import type * as z from 'zod';
import { Client } from '@modelcontextprotocol/client';
import { cedarPolicy } from '@ramex-labs/irontrellis-policy-composition/cedar';
import { openFgaPolicy, fgaObject } from '@ramex-labs/irontrellis-policy-composition/openfga';
import { policyJournal } from '@ramex-labs/irontrellis-policy-composition/journal';
import { createDemo, type Demo } from '@ramex-labs/irontrellis-protected-evidence-mcp/setup';
import { loadGateway } from '@ramex-labs/irontrellis-protected-evidence-mcp/config';
import { createGatewayServer, serveGateway } from '@ramex-labs/irontrellis-protected-evidence-mcp/server';
import { evidenceTool } from '@ramex-labs/irontrellis-langchain-evidence';
import type { AdditionalPolicy, LocalEvidenceTool } from '@ramex-labs/irontrellis';
const cedar: AdditionalPolicy = cedarPolicy('permit(principal, action, resource);', policyJournal('/tmp/audit'));
const fga: AdditionalPolicy = openFgaPolicy({apiUrl:'http://127.0.0.1:8080',storeId:'01AAAAAAAAAAAAAAAAAAAAAAAA',modelId:'01BBBBBBBBBBBBBBBBBBBBBBBB',record:policyJournal('/tmp/audit')});
const demo: Promise<Demo> = createDemo('/tmp/new-case');
const gateway: LocalEvidenceTool = loadGateway('/tmp/gateway.json', {additionalPolicy:cedar});
createGatewayServer(gateway);
void serveGateway;
void demo;
void fga;
fgaObject('agent','bea');
// @ts-expect-error There is no untrusted user/context tuple mapping.
fgaObject('group','bea');
const client = new Client({name:'declaration-consumer',version:'1'});
const tool = evidenceTool(client, {operationId:'stable',resource:'incident:42'});
createAgent({model:fakeModel(),tools:[tool]});
void tool.invoke({resource:'incident:42'});
// @ts-expect-error The schema has no model-provided operation ID.
const extra: z.input<typeof tool.schema> = {resource:'incident:42',operationId:'invented'};
void extra;
// @ts-expect-error The resource is selected by the trusted application.
void tool.invoke({resource:'other'});
