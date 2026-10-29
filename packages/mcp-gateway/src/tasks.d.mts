import type {CooperativeGateway,CooperativeOptions} from './cooperative.mjs';
export declare const TASKS_EXTENSION:'io.modelcontextprotocol/tasks';
export type TaskGuard=()=>void;
export type TaskView=Readonly<{resultType:'complete'|'task';taskId:string;status:'working'|'completed'|'cancelled'|'failed';createdAt:string;lastUpdatedAt:string;ttlMs:null;pollIntervalMs:number;statusMessage?:string;result?:Readonly<Record<string,unknown>>}>;
export interface TaskManager {hasTool(name:string):boolean;start(name:string,args:unknown,guard:TaskGuard):Promise<TaskView>;get(taskId:string,guard:TaskGuard):Promise<TaskView>;cancel(taskId:string,guard:TaskGuard):Promise<Readonly<{resultType:'complete'}>>;update(taskId:string,inputResponses:unknown,guard:TaskGuard):Readonly<{resultType:'complete'}>;close():Promise<void>}
export declare function createTaskManager(options:Readonly<{gateway:CooperativeGateway;config:CooperativeOptions;binding:Readonly<{id:string;subject:string;clientId:string}>;now?:()=>number;assertOwned?:TaskGuard}>):TaskManager;
export declare function routeTaskRequest(manager:TaskManager,request:Readonly<Record<string,unknown>>,headers:Readonly<Record<string,string|string[]|undefined>>,guard:TaskGuard):Promise<Readonly<Record<string,unknown>>|null>;
