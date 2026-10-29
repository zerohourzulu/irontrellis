import type {AuthorizationDomain,LocalExecutionOptions} from '@ramex-labs/irontrellis/adapter';
import type {ToolDefinition,createCooperativeClient} from '@ramex-labs/irontrellis-remote';
import type {GatewayResult,ToolListing,RunOptions} from './gateway.js';
export type CooperativeOptions=Readonly<{local:LocalExecutionOptions;storage:string;registry:Readonly<{serviceId:string;account:string;tools:readonly ToolDefinition[]}>;destination:Parameters<typeof createCooperativeClient>[0];operations:readonly Readonly<{name:string;tool:string;businessKey:string;role:string;tenure:string}>[]}>;
export interface CooperativeGateway {
 tools():readonly ToolListing[];
 run(name:string,input:unknown,options?:RunOptions&Readonly<{onProgress?:(phase:'checkpoint'|'prepare'|'commit')=>void}>):Promise<GatewayResult>;
 recover(name:string,options?:RunOptions):Promise<GatewayResult>;
 cancel(name:string,options?:RunOptions):Promise<GatewayResult>;
 observe(name:string,options?:RunOptions):Promise<GatewayResult>;
 checkCancellation(name:string):void;
 status(name:string):GatewayResult;
 why(name:string):GatewayResult;
 close():Promise<void>;
}
export declare function cancellationIdentity(domain:AuthorizationDomain,businessKey:string):string;
export declare function createCooperativeGateway(options:CooperativeOptions):Promise<CooperativeGateway>;
