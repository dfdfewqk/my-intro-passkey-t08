import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import privateHandler from '../api/private.js';
const site='https://my-intro-t08.vercel.app';
const a='a'.repeat(64),b='b'.repeat(64);
const notes1=[{title:'Owner A 1',body:'fabricated A'},{title:'Owner A 2',body:'fabricated A'},{title:'Owner A 3',body:'fabricated A'}];
const notes2=[{title:'Owner B 1',body:'fabricated B'},{title:'Owner B 2',body:'fabricated B'},{title:'Owner B 3',body:'fabricated B'}];
async function withTestData(fn){
 const oldFetch=globalThis.fetch;
 const savedA=process.env.T08_PRIVATE_NOTES_JSON;
 const savedB=process.env.T08_PRIVATE_NOTES_OWNER2_JSON;
 process.env.T08_PRIVATE_NOTES_JSON=JSON.stringify(notes1);
 process.env.T08_PRIVATE_NOTES_OWNER2_JSON=JSON.stringify(notes2);
 globalThis.fetch=async(_url,{body}={})=>{
  const action=JSON.parse(body||'{}');
  if(action.action!=='validate')throw Error('unexpected edge action');
  if(action.session===a)return{status:200,json:async()=>({authenticated:true,ownerId:1})};
  if(action.session===b)return{status:200,json:async()=>({authenticated:true,ownerId:2})};
  return{status:401,json:async()=>({error:'session_expired_or_revoked'})};
 };
 try{return await fn();}finally{
  globalThis.fetch=oldFetch;
  if(savedA===undefined)delete process.env.T08_PRIVATE_NOTES_JSON;else process.env.T08_PRIVATE_NOTES_JSON=savedA;
  if(savedB===undefined)delete process.env.T08_PRIVATE_NOTES_OWNER2_JSON;else process.env.T08_PRIVATE_NOTES_OWNER2_JSON=savedB;
 }
}
async function read(path,session='',method='GET'){
 const state={status:200,body:null,headers:{},ended:false};
 const res={
  setHeader(n,v){state.headers[n]=v;return res;},
  status(code){state.status=code;return res;},
  json(obj){state.body=obj;return res;},
  end(){state.ended=true;return res;}
 };
 await privateHandler({method,url:'/api/private'+path,headers:session?{cookie:'__Host-t08_session='+session}:{}},res);
 return state;
}
test('C37: owner cannot read owner2 private notes, including after success',()=>withTestData(async()=>{
 const good=await read('?account=1',a);
 const denied=await read('?account=2',a);
 const again=await read('?account=1',a);
 assert.equal(good.status,200);
 assert.equal(good.body.accountId,1);
 assert.equal(good.body.items.length,3);
 assert.equal(denied.status,403);
 assert.equal(denied.body.error,'other_account_forbidden');
 assert.equal(denied.body.items,undefined);
 assert.equal(again.status,200);
 assert.deepEqual(again.body.items,good.body.items);
}));
test('C38: owner2 cannot read owner private notes',()=>withTestData(async()=>{
 const good=await read('?account=2',b);
 const denied=await read('?account=1',b);
 const again=await read('?account=2',b);
 assert.equal(good.status,200);
 assert.equal(denied.status,403);
 assert.equal(denied.body.items,undefined);
 assert.equal(again.body.items.length,good.body.items.length);
 assert.deepEqual(again.body.items,good.body.items);
}));
test('C39: denied A→B and B→A attempts preserve both private record counts',()=>withTestData(async()=>{
 const beforeA=await read('',a),beforeB=await read('',b);
 await read('?account=2',a);await read('?account=1',b);
 const afterA=await read('',a),afterB=await read('',b);
 assert.equal(beforeA.body.items.length,afterA.body.items.length);
 assert.equal(beforeB.body.items.length,afterB.body.items.length);
 assert.notDeepEqual(afterA.body.items,afterB.body.items);
}));
test('C40: forged owner_id in URL never overrides server validated signed account',()=>withTestData(async()=>{
 const aResult=await read('?owner_id=2&requestedOwner=2',a);
 const bResult=await read('?owner_id=1&requestedOwner=1',b);
 assert.equal(aResult.status,200);
 assert.equal(aResult.body.accountId,1);
 assert.equal(bResult.status,200);
 assert.equal(bResult.body.accountId,2);
 assert.notDeepEqual(aResult.body.items,bResult.body.items);
}));
test('unauthenticated private URL and invalid credential session remain blocked',()=>withTestData(async()=>{
 const loggedOut=await read('?account=2');
 const forged=await read('?account=1','c'.repeat(64));
 assert.equal(loggedOut.status,401);
 assert.equal(forged.status,401);
 assert.equal(loggedOut.body.items,undefined);
}));
test('private endpoint refuses POST and does not disclose notes',()=>withTestData(async()=>{
 const r=await read('?account=2',a,'POST');
 assert.equal(r.status,405);
 assert.equal(r.body.items,undefined);
}));
test('C41 tenant isolation is server-side, credential owners come from verified assertions',()=>{
 const priv=fs.readFileSync(new URL('../api/private.js',import.meta.url),'utf8');
 const edge=fs.readFileSync(new URL('../supabase/functions/t08-login/index.ts',import.meta.url),'utf8');
 const keys=fs.readFileSync(new URL('../supabase/functions/t08-keys/index.ts',import.meta.url),'utf8');
 assert.ok(priv.includes("await edge('validate',{session})"));
 assert.ok(priv.includes("account!==String(ownerId)"));
 assert.ok(priv.includes("other_account_forbidden"));
 assert.ok(priv.includes("ownerId===1?'T08_PRIVATE_NOTES_JSON':'T08_PRIVATE_NOTES_OWNER2_JSON'"));
 assert.ok(edge.includes("verifyAuthenticationResponse({"));
 assert.ok(edge.includes("ownerId:keyRow.owner_id"));
 assert.ok(edge.includes("in('owner_id',[1,2])"));
 assert.ok(keys.includes("eq('owner_id',active.owner_id)"));
 assert.ok(keys.includes("t08_split_horse2_to_owner2"));
});
test('split requires current horse2 owner signed session and user confirmation on page',()=>{
 const page=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
 const client=fs.readFileSync(new URL('../client/keys.js',import.meta.url),'utf8');
 const migration=fs.readFileSync(new URL('../supabase/migrations/20261020_card5_two_site_accounts.sql',import.meta.url),'utf8');
 assert.ok(page.includes('id="accountSplitButton"'));
 assert.ok(client.includes("window.confirm('카드 5 계정 분리:"));
 assert.ok(client.includes("info.passkeyName!=='horse2'"));
 assert.ok(client.includes("ownerId!==1"));
 assert.ok(migration.includes("the_name<>'horse2'"));
 assert.ok(migration.includes("keys_in_owner<2"));
 assert.ok(migration.includes("second_account_already_has_passkey"));
 assert.ok(migration.includes("revoked_at=now()"));
});
