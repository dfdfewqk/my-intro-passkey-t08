import test from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/auth.js';
const token='a'.repeat(64);
const origin='https://my-intro-t08.vercel.app';
function run(action,cookie='',other={}){
 const input={method:'POST',headers:{origin,cookie},body:{action,...other}};
 const data={status:200,headers:{},body:null};
 const res={setHeader(k,v){data.headers[k]=v;return res;},
  status(n){data.status=n;return res;},json(o){data.body=o;return res;}};
 return {input,res,data};
}
test('authenticated cookie yields verified key name without token exposure',async()=>{
 const old=globalThis.fetch;
 globalThis.fetch=async()=>({status:200,json:async()=>({authenticated:true,ownerId:1,passkeyName:'horse2'})});
 try{
  const p=run('status','__Host-t08_session='+token);
  await handler(p.input,p.res);
  assert.equal(p.data.status,200);
  assert.equal(p.data.body.passkeyName,'horse2');
  assert.equal(p.data.body.authenticated,true);
  assert.ok(!JSON.stringify(p.data.body).includes(token));
 }finally{globalThis.fetch=old;}
});
test('temporary backend failure returns HTTP 503 rather than false logout state',async()=>{
 const old=globalThis.fetch;
 globalThis.fetch=async()=>({status:503,json:async()=>({error:'storage_unavailable'})});
 try{
  const p=run('status','__Host-t08_session='+token);
  await handler(p.input,p.res);
  assert.equal(p.data.status,503);
  assert.equal(p.data.body.error,'authentication_server_unavailable');
 }finally{globalThis.fetch=old;}
});
test('revoked cookie never reveals passkey name and always rejects protected access',async()=>{
 const old=globalThis.fetch;
 globalThis.fetch=async()=>({status:401,json:async()=>({error:'session_expired_or_revoked'})});
 try{
  const p=run('status','__Host-t08_session='+token);
  await handler(p.input,p.res);
  assert.equal(p.data.status,200);
  assert.equal(p.data.body.authenticated,false);
  assert.equal(p.data.body.passkeyName,undefined);
 }finally{globalThis.fetch=old;}
});
test('successful passkey verify returns name but never returns the raw session',async()=>{
 const old=globalThis.fetch;
 globalThis.fetch=async()=>({status:200,json:async()=>({authenticated:true,session:token,
  expiresAt:'2030-01-01T00:00:00Z',passkeyName:'horse'})});
 try{
  const p=run('verify','',{challengeId:'mock',response:{id:'hardware'}});
  await handler(p.input,p.res);
  assert.equal(p.data.status,200);
  assert.equal(p.data.body.passkeyName,'horse');
  assert.equal(p.data.body.signatureVerified,true);
  assert.match(p.data.headers['Set-Cookie'],/HttpOnly; Secure; SameSite=Strict/);
  assert.ok(!JSON.stringify(p.data.body).includes(token));
 }finally{globalThis.fetch=old;}
});
