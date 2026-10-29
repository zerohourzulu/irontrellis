import {types} from 'node:util';
import {check} from './data.js';
/** Host guards are synchronous void assertions. Accidentally async guards must fail closed. */
export function assertSynchronous(guard){
 check(typeof guard==='function','ACCESS_NOT_CURRENT');
 const result=guard();
 if(types.isPromise(result))void result.catch(()=>{});
 check(result===undefined,'ACCESS_NOT_CURRENT');
}
