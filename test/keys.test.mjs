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
 assert.ok(!/<input\s[^>]*type=["']password/i.test(html));
});

test('registration options forwards the requested authenticator mode',async()=>{
 const original=globalThis.fetch;let captured=null;
 globalThis.fetch=async (_url,opts)=>{
   captured=JSON.parse(opts.body);
   return {status:200,json:async()=>({challengeId:'test',options:{hints:['security-key']}})};
 };
 try{
   const {data,r}=capture();
   await handler(req('options',{payload:{storageProvider:'security_key',session:'malicious-browser-token'}}),r);
   assert.equal(data.status,200);
   assert.equal(captured.action,'options');
   assert.equal(captured.storageProvider,'security_key');
   assert.equal(captured.session,'b'.repeat(64));
   assert.notEqual(captured.session,'malicious-browser-token');
 }finally{globalThis.fetch=original;}
});
test('server requests physical security key and Windows platform with WebAuthn options, retaining duplicate protection',async()=>{
 const fs=await import('node:fs');
 const source=fs.readFileSync(new URL('../supabase/functions/t08-keys/index.ts',import.meta.url),'utf8');
 assert.ok(source.includes("'cross-platform'"));
 assert.ok(source.includes("'platform'"));
 assert.ok(source.includes("'security-key'"));
 assert.ok(source.includes("'client-device'"));
 assert.ok(source.includes("authenticatorAttachment:attachment"));
 assert.ok(source.includes('registrationHandle=crypto.getRandomValues'));
 assert.ok(source.includes('requested_mode:mode'));
 assert.ok(source.includes("!==issued.requested_mode"));
});
test('client reports browser-selected authenticator and explains Google duplicate error',async()=>{
 const fs=await import('node:fs');
 const source=fs.readFileSync(new URL('../client/keys.js',import.meta.url),'utf8');
 assert.ok(source.includes("keysApi('options',{storageProvider:provider,name})"));
 assert.ok(source.includes("credential.authenticatorAttachment"));
 assert.ok(source.includes("e.name==='InvalidStateError'"));
 assert.ok(source.includes('기존 패스키 중복'));
});


test('phone option requests hybrid smartphone credential and binds the requested storage mode',async()=>{
 const fs=await import('node:fs');
 const edge=fs.readFileSync(new URL('../supabase/functions/t08-keys/index.ts',import.meta.url),'utf8');
 const client=fs.readFileSync(new URL('../client/keys.js',import.meta.url),'utf8');
 const html=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
 assert.match(html,/<option value="phone">/);
 assert.ok(edge.includes("mode==='security_key'?'cross-platform':mode==='device'?'platform':undefined"));
 assert.ok(!edge.includes("mode==='security_key'||mode==='phone'?'cross-platform'"));
 assert.ok(edge.includes("mode==='phone'?['hybrid']"));
 assert.ok(edge.includes('registration_user_handle:registrationHandle64'));
 assert.ok(edge.includes('requested_mode:mode'));
 assert.ok(edge.includes("!==issued.requested_mode"));
 assert.ok(edge.includes("'phone','bitwarden','unknown'"));
 assert.ok(client.includes("provider==='phone'"));
 assert.ok(client.includes("mode==='phone'"));
 assert.ok(client.includes('USB 보안 키 삽입 창'));
 assert.ok(client.includes('QR'));
 assert.ok(html.includes('value="phone"'));
});
test('phone registration passes the selected mode using the existing authorized API',async()=>{
 const original=globalThis.fetch;let body;
 globalThis.fetch=async(_url,request)=>{
  body=JSON.parse(request.body);
  return {status:200,json:async()=>({options:{hints:['hybrid']}})};
 };
 try{
  const {data,r}=capture();
  await handler(req('options',{payload:{storageProvider:'phone'}}),r);
  assert.equal(data.status,200);
  assert.equal(body.storageProvider,'phone');
  assert.equal(body.session,'b'.repeat(64));
  assert.deepEqual(data.json.options.hints,['hybrid']);
 }finally{globalThis.fetch=original;}
});


test('independent Bitwarden extension mode requests native-compatible WebAuthn without external hardware',async()=>{
 const fs=await import('node:fs');
 const server=fs.readFileSync(new URL('../supabase/functions/t08-keys/index.ts',import.meta.url),'utf8');
 const client=fs.readFileSync(new URL('../client/keys.js',import.meta.url),'utf8');
 const html=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
 assert.ok(server.includes("'phone','bitwarden'].includes"));
 assert.ok(server.includes("'phone','bitwarden','unknown'].includes"));
 assert.ok(server.includes("mode==='device'?'platform':undefined"));
 assert.ok(server.includes("mode==='device'?['client-device']:[]"));
 assert.ok(html.includes('value="google" selected'));
 assert.ok(html.includes('value="bitwarden"'));
 assert.ok(client.includes("mode==='bitwarden'"));
 assert.ok(client.includes("provider==='bitwarden'"));
 assert.ok(server.includes('p_user_handle:issued.registration_user_handle'));
 assert.ok(server.includes('requested_mode:mode'));
});
