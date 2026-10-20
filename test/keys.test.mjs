import test from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/keys.js';
const cookie='__Host-t08_session='+('b'.repeat(64));
const req=(action,{origin='https://my-intro-t08.vercel.app',c=cookie,payload={}}={})=>
 ({method:'POST',headers:{origin,cookie:c},
   body:{action,...payload}});
function capture(){
 const data={status:200,json:null,headers:{}};
 const r={setHeader:(n,v)=>{data.headers[n]=v;return r;},
  status:(s)=>{data.status=s;return r;},json:(o)=>{data.json=o;return r;}};
 return {data,r};
}
test('key list denied when no validated browser session',async()=>{
 const {data,r}=capture();await handler(req('list',{c:''}),r);
 assert.equal(data.status,401);assert.equal(data.json.error,'authentication_required');
});
test('cross-origin requests cannot add or delete keys',async()=>{
 const {data,r}=capture();await handler(req('remove',{origin:'https://attack.example',payload:{credentialId:'x'}}),r);
 assert.equal(data.status,403);
});
test('GET is never allowed to mutate key inventory',async()=>{
 const {data,r}=capture();await handler({...req('remove'),method:'GET'},r);
 assert.equal(data.status,405);
});
test('malformed action never reaches privileged edge function',async()=>{
 const {data,r}=capture();await handler(req('arbitraryAdminAction'),r);
 assert.equal(data.status,400);
});
test('authenticated passkey management forwards cookie session, not client-supplied token',async()=>{
 const saved=globalThis.fetch;
 const calls=[];
 globalThis.fetch=async (url,opts)=>{
  calls.push({url,body:JSON.parse(opts.body)});
  return {status:200,json:async()=>({passkeys:[{name:'horse',createdAt:'2026-10-20T00:55:49Z'}]})};
 };
 try{
  const {data,r}=capture();await handler(req('list',{payload:{session:'injected'}}),r);
  assert.equal(data.status,200);
  assert.equal(calls.length,1);
  assert.ok(calls[0].url.endsWith('/functions/v1/t08-keys'));
  assert.equal(calls[0].body.session,'b'.repeat(64));
  assert.notEqual(calls[0].body.session,'injected');
 }finally{globalThis.fetch=saved;}
});
test('deletion is rejected when server reports last key protected',async()=>{
 const saved=globalThis.fetch;
 globalThis.fetch=async()=>({status:409,json:async()=>({error:'last_passkey_protected'})});
 try{
  const {data,r}=capture();
  await handler(req('remove',{payload:{credentialId:'last-key-id'}}),r);
  assert.equal(data.status,409);assert.equal(data.json.error,'last_passkey_protected');
 }finally{globalThis.fetch=saved;}
});
test('deleted credential ID can only be removed under verified session',async()=>{
 const saved=globalThis.fetch;
 globalThis.fetch=async()=>{throw Error('offline');};
 try{const {data,r}=capture();
  await handler(req('remove',{payload:{credentialId:'known'}}),r);
  assert.equal(data.status,503);assert.equal(data.json.error,'key_management_unavailable');
 }finally{globalThis.fetch=saved;}
});
test('no password input fields exist in the static HTML',async()=>{
 const fs=await import('node:fs');
 const html=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
 assert.ok(!/<input\\s[^>]*type=["']password/i.test(html));
});