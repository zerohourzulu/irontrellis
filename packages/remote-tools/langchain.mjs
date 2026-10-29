import {DynamicStructuredTool} from '@langchain/core/tools';
import * as z from 'zod';
import {identifier,record,requireCondition} from '@ramex-labs/irontrellis/adapter';

const decimalPattern=/^(0|[1-9][0-9]{0,77})$/;
const decimalAmount=z.string().regex(decimalPattern,'Use whole units as decimal text, without signs, fractions, exponents or separators.')
  .refine(value=>!decimalPattern.test(value)||BigInt(value)<(1n<<256n),
    'Amount must be at most 2^256 - 1 whole units.')
  .describe('Whole units as decimal text; no sign, fraction, exponent or separators.');
const controlFree=/^[^\u0000-\u001f\u007f]+$/;
const textField=z.string().min(1).max(1024).regex(controlFree,'Text cannot contain control characters.');
const identifierField=z.string().min(1).max(128).regex(controlFree,'Identifiers cannot contain control characters.');
const integerField=z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)
  .refine(value=>!Object.is(value,-0),'Use zero rather than negative zero.');

/** One application-owned business operation, exposed as an ordinary LangChain tool. */
export function createIronTrellisTool(options) {
  const {registry,executor}=options;
  const settings=record({tool:options.tool,operationId:options.operationId,businessKey:options.businessKey,
    ...(Object.hasOwn(options,'name')?{name:options.name}:{})},['tool','operationId','businessKey'],['name']);
  for(const name of ['tool','operationId','businessKey'])identifier(settings[name]);
  const definition=registry.tools.find(x=>x.id===settings.tool);
  requireCondition(definition,'UNKNOWN_TOOL');
  requireCondition(typeof executor.run==='function','INVALID_CONFIGURATION');
  const name=Object.hasOwn(settings,'name')?settings.name:definition.id.replaceAll('.','_');
  requireCondition(typeof name==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(name),'INVALID_TOOL_NAME');
  const fields={};
  for(const [name,type] of Object.entries(definition.fields)) {
    fields[name]=Array.isArray(type)?z.enum(type):type==='text'?textField:
      type==='identifier'?identifierField:type==='integer'?integerField:
      type==='boolean'?z.boolean():decimalAmount;
  }
  return new DynamicStructuredTool({
    name,
    description:`Request ${definition.id} for one application-assigned business operation. Refusal or uncertainty does not permit a new operation ID. Report the returned status; it is not proof of an outside outcome.`,
    schema:z.object(fields).strict(),
    async func(input) {
      const args={...input};
      // JSON tool calls carry exact decimal text. Conversion is explicit here;
      // the core/destination API still accepts only a bounded bigint amount.
      for(const [name,type] of Object.entries(definition.fields))if(type==='amount')args[name]=BigInt(args[name]);
      const result=await executor.run({operationId:settings.operationId,businessKey:settings.businessKey,tool:settings.tool,arguments:args});
      return JSON.stringify({operationId:settings.operationId,status:result.execution.status,
        lastReportedServiceState:result.serviceReport?.result.state??'REPORT_UNAVAILABLE',
        invocation:result.execution.invocation?.status??result.execution.result?.status??null,
        externalOutcome:result.externalOutcome,revocationBoundary:result.revocationBoundary});
    },
  });
}

/** Build one host-selected tool list, refusing ambiguous framework names. */
export function createIronTrellisTools(options) {
  const {registry,executor}=options;
  const {operations}=record({operations:options.operations},['operations']);
  requireCondition(Array.isArray(operations)&&operations.length>0&&operations.length<=32,'INVALID_TOOL_OPERATIONS');
  const tools=operations.map(value=>{
    const operation=record(value,['tool','operationId','businessKey'],['name']);
    return createIronTrellisTool({registry,executor,...operation});
  });
  requireCondition(new Set(tools.map(tool=>tool.name)).size===tools.length,'DUPLICATE_TOOL_NAME');
  return Object.freeze(tools);
}
