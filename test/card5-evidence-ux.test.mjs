import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const code=fs.readFileSync(new URL('../client/card5.js',import.meta.url),'utf8');
const flush=async()=>{for(let n=0;n<8;n++)await new Promise(r=>setImmediate(r));};
function mock({accountId=1,loggedIn=true,leak=false,records=[]}={}){
 const dom=new Map(),listeners=new Map();
 class E{
  constructor(){this.textContent='';this.disabled=false;this.callbacks={};}
  addEventListener(t,cb){this.callbacks[t]=cb;}
 }
 const el=id=>{if(!dom.has(id))dom.set(id,new E());return dom.get(id);};
 const accounts=()=>accountId;
 const requestCount={save:0,proofStatus:0,privateReads:0};
 const fetch=async(url,{method,body,credentials}={})=>{
  if(url==='/api/auth'){
   return {status:200,json:async()=>loggedIn?
    ({authenticated:true,ownerId:accounts(),accountName:accounts()===1?'owner':'owner2',
      passkeyName:accounts()===1?'horse':'owner2-key'}):({authenticated:false})};
  }
  if(url==='/api/card5-evidence'){
   const data=JSON.parse(body);
   if(!loggedIn)return {status:401,json:async()=>({error:'authentication_required'})};
   if(data.action==='status'){
    requestCount.proofStatus++;
    return{status:200,json:async()=>({records})};
   }
   requestCount.save++;
   if(data.action!=='save'||data.proof.accountId!==accounts())throw Error('bad proof submission');
   records.splice(records.findIndex(x=>x.accountId===accounts()),records.some(x=>x.accountId===accounts())?1:0);
   records.push({...data.proof,timestamp:new Date().toISOString()});
   return{status:200,json:async()=>({saved:true,records:[...records]})};
  }
  if(url.startsWith('/api/private')){
   requestCount.privateReads++;
   if(credentials==='omit')return{status:401,json:async()=>({error:'authentication_required'})};
   const u=new URL(url,'https://my-intro-t08.vercel.app');
   const target=u.searchParams.get('account');
   if(target&&Number(target)!==accounts())
    return leak?{status:200,json:async()=>({items:[{title:'OTHER USER DATA'}],accountId:Number(target)})}
     :{status:403,json:async()=>({error:'other_account_forbidden'})};
   return{status:200,json:async()=>({accountId:accounts(),items:[
     {title:'SECRET 1',body:'Private A'},
     {title:'SECRET 2',body:'Private B'},
     {title:'SECRET 3',body:'Private C'}]})};
  }
  throw Error('unknown path '+url);
 };
 const window={addEventListener(t,fn){listeners.set(t,fn);}};
 const navigator={clipboard:{writeText:async()=>{}}};
 const context={window,document:{getElementById:el},navigator,fetch,Date,URL,console,Object};
 vm.createContext(context);vm.runInContext(code,context);
 return {el,records,requestCount,
  async fireLogin(next=true){loggedIn=next;listeners.get('t08-auth-state')?.({detail:{authenticated:next}});await flush();},
  async click(){await el('card5RunChecks').callbacks.click();await flush();},
  get currentAccount(){return accountId;}
 };
}
test('logged-in owner displays live HTTP 403 proof automatically, replacing static login prompt',async()=>{
 const a=mock();await flush();
 assert.match(a.el('card5Evidence').textContent,/실서버 HTTP 검사/);
 assert.match(a.el('card5Evidence').textContent,/상대 계정 자료 요청 → HTTP 403/);
 assert.match(a.el('card5Progress').textContent,/1\/2/);
 assert.equal(a.requestCount.save,1);
 assert.ok(!a.el('card5Evidence').textContent.includes('SECRET 1'));
 assert.ok(!JSON.stringify(a.records).includes('Private A'));
});
test('two independent browser profile contexts combine proof summaries on server into 2/2',async()=>{
 const records=[];
 const a=mock({accountId:1,records});await flush();
 assert.match(a.el('card5Progress').textContent,/1\/2/);
 const b=mock({accountId:2,records});await flush();
 assert.match(b.el('card5Progress').textContent,/2\/2/);
 const fresh=mock({accountId:1,records});await flush();
 assert.match(fresh.el('card5Progress').textContent,/2\/2/);
 assert.match(fresh.el('card5Evidence').textContent,/owner↔owner2|최종:/);
 assert.equal(records.length,2);
 for(const p of records){assert.equal(p.denyHttp,403);assert.equal(p.before,p.after);}
});
test('no false pass when other account documents are leaked',async()=>{
 const x=mock({leak:true});await flush();
 assert.match(x.el('card5Evidence').textContent,/검증 실패/);
 assert.match(x.el('card5Progress').textContent,/검사 실패/);
 assert.equal(x.requestCount.save,0);
});
test('logout hides old proof and next login automatically runs verification',async()=>{
 const x=mock();await flush();
 await x.fireLogin(false);
 assert.match(x.el('card5Evidence').textContent,/로그아웃되어/);
 assert.match(x.el('card5Progress').textContent,/로그인 후/);
 await x.fireLogin(true);
 assert.match(x.el('card5Evidence').textContent,/실서버 HTTP 검사/);
});
test('HTML has dynamic, accessible verification output rather than permanent stale prompt',()=>{
 const html=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
 assert.ok(html.includes('id="card5Evidence" role="status" aria-live="polite"'));
 assert.ok(!html.includes('먼저 패스키로 로그인해 주세요. 계정 분리가 완료되기 전에는'));
 assert.ok(code.includes("window.addEventListener('t08-auth-state'"));
 assert.ok(code.includes('initOrRestore()'));
});
test('redacted evidence write is authenticated and server scopes owner identity',()=>{
 const edge=fs.readFileSync(new URL('../supabase/functions/t08-evidence/index.ts',import.meta.url),'utf8');
 const gateway=fs.readFileSync(new URL('../api/card5-evidence.js',import.meta.url),'utf8');
 assert.ok(gateway.includes("getSession(req)"));
 assert.ok(gateway.includes("origin!==ORIGIN"));
 assert.ok(edge.includes("eq('credential_id',session.credential_id)"));
 assert.ok(edge.includes("p.accountId===session.owner_id"));
 assert.ok(edge.includes("p.denyHttp===403"));
 assert.ok(edge.includes("p.before===p.after"));
 assert.ok(edge.includes("t08_card5_evidence"));
 assert.ok(!gateway.includes('SUPABASE_SERVICE_ROLE_KEY'));
});
