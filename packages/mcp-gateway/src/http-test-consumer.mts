import {serveGatewayHttp,serveGatewayBackend,serveGatewayRouter,type HttpOptions,type BackendOptions,type RouterOptions} from '@ramex-labs/irontrellis-mcp-gateway/http';
import {createCooperativeGateway,cancellationIdentity,type CooperativeOptions} from '@ramex-labs/irontrellis-mcp-gateway/cooperative';
import {createTaskManager,routeTaskRequest,TASKS_EXTENSION} from '@ramex-labs/irontrellis-mcp-gateway/tasks';
import {createAccessVerifier,type HttpAccess} from '@ramex-labs/irontrellis-mcp-gateway/access-http';
import {createLocalDomain} from '@ramex-labs/irontrellis';
function consume(http:HttpOptions,backend:BackendOptions,router:RouterOptions,cooperative:CooperativeOptions,access:HttpAccess){
 void serveGatewayHttp(http);void serveGatewayBackend(backend);void serveGatewayRouter(router);access.assertCurrent();
 void createCooperativeGateway(cooperative).then(gateway=>{const manager=createTaskManager({gateway,config:cooperative,binding:{id:'a',subject:'alice',clientId:'client'}});void routeTaskRequest(manager,{},{},access.assertCurrent);});
 const key:string=cancellationIdentity(createLocalDomain(),'job');return key;
}
void consume;void TASKS_EXTENSION;void createAccessVerifier;
