// Demo/test-only network fault fixture. Does not authenticate or decide authority.
import {createServer} from 'node:http';
export async function lossyRelay(destination){
 const behavior={},counts={checkpoint:0,prepare:0,commit:0,status:0,cancel:0};
 const server=createServer(async(req,res)=>{
  try{
   const chunks=[];for await(const chunk of req)chunks.push(chunk);const bytes=Buffer.concat(chunks);
   // Inspect only the operation tag in this fixture's tagged transport envelope.
   const tagged=JSON.parse(bytes),body=tagged[1].find(pair=>pair[0]==='body')[1];
   const operation=body[1].find(pair=>pair[0]==='operation')[1][1];counts[operation]++;
   if(behavior.before)await behavior.before(operation);
   if(behavior.dropBefore===operation){res.destroy();return;}
   const response=await fetch(new URL('/cooperative',destination),{method:'POST',headers:{'content-type':'application/json',connection:'close'},body:bytes});
   const reply=Buffer.from(await response.arrayBuffer());
   if(behavior.after)await behavior.after(operation);
   if(behavior.dropAfter===operation){res.destroy();return;}
   res.writeHead(response.status,{'content-type':'application/json','connection':'close'});res.end(reply);
  }catch{res.destroy();}
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 return {url:`http://127.0.0.1:${server.address().port}/`,behavior,counts,async close(){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}};
}
