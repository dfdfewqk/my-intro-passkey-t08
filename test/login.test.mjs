import test from 'node:test';
import assert from 'node:assert/strict';
import handler, {getSession} from '../api/auth.js';
import privateHandler from '../api/private.js';
const token='a'.repeat(64);
function req(action,extras={},cookie=''){
 return {method:'POST',headers:{origin:'https://my-intro-t08.vercel.app',cookie},
  body:{action,...extras}};
}
function res(){
 const state={status:200,data:null,headers:{}};
 const r={setHeader(n,v){state.headers[n]=v;return r;},
  status(code){state.status=code;return r;},
  json(data){state.data=data;return r;},
  end(){return r;}};
 return {state,r};
}
test('does not accept forged cookies as authenticated sessions',()=>{
 assert.equal(getSession({headers:{cookie:'__Host-t08_session=forged'}}),null);
 assert.equal(getSession({headers:{cookie:'__Host-t08_session='+token}}),token);
});
test('cross-site origin rejected before authentication',async()=>{
 const {state,r}=res();
 await handler({...req('options'),headers:{origin:'https://example.com'}},r);
 assert.equal(state.status,403);
});
test('invalid signature does not create browser cookie',async()=>{
 const fetchOriginal=globalThis.fetch;
 globalThis.fetch=async()=>({status:401,json:async()=>({error:'invalid_signature'})});
 try{
  const {state,r}=res();
  await handler(req('verify',{challengeId:'x',response:{id:'forged'}}),r);
  assert.equal(state.status,401);
  assert.equal(state.headers['Set-Cookie'],undefined);
 }finally{globalThis.fetch=fetchOriginal;}
});
test('verified upstream response uses secure HttpOnly cookie and redacted body',async()=>{
 const fetchOriginal=globalThis.fetch;
 globalThis.fetch=async()=>({status:200,json:async()=>({authenticated:true,session:token,expiresAt:'2040-01-01T00:00:00Z'})});
 try{
  const {state,r}=res();
  await handler(req('verify',{challengeId:'x',response:{id:'hardware'}}),r);
  assert.equal(state.status,200);
  assert.match(state.headers['Set-Cookie'],/HttpOnly; Secure; SameSite=Strict/);
  assert.ok(!JSON.stringify(state.data).includes(token));
  assert.equal(state.data.signatureVerified,true);
 }finally{globalThis.fetch=fetchOriginal;}
});
test('logout revokes and rechecks the same token; never returns token',async()=>{
 const fetchOriginal=globalThis.fetch;
 const actions=[];
 globalThis.fetch=async(_url,options)=>{
  const body=JSON.parse(options.body);actions.push(body);
  return body.action==='logout'
   ?{status:200,json:async()=>({loggedOut:true})}
   :{status:401,json:async()=>({error:'session_expired_or_revoked'})};
 };
 try{
  const {state,r}=res();
  await handler(req('logout',{},'__Host-t08_session='+token),r);
  assert.equal(state.status,200);
  assert.equal(state.data.reuseStatus,401);
  assert.deepEqual(actions.map(x=>x.action),['logout','validate']);
  assert.equal(actions[0].session,actions[1].session);
  assert.ok(!JSON.stringify(state.data).includes(token));
  assert.match(state.headers['Set-Cookie'],/Max-Age=0/);
 }finally{globalThis.fetch=fetchOriginal;}
});
test('private API returns no notes to anonymous users',async()=>{
 const {state,r}=res();
 await privateHandler({method:'GET',headers:{}},r);
 assert.equal(state.status,401);
});
test('private API denies revoked token after server verification',async()=>{
 const fetchOriginal=globalThis.fetch;
 globalThis.fetch=async()=>({status:401,json:async()=>({error:'session_expired_or_revoked'})});
 try{
  const {state,r}=res();
  await privateHandler({method:'GET',headers:{cookie:'__Host-t08_session='+token}},r);
  assert.equal(state.status,401);
 }finally{globalThis.fetch=fetchOriginal;}
});
test('private notes are returned only after successful server validation',async()=>{
 const fetchOriginal=globalThis.fetch;
 const saved=process.env.T08_PRIVATE_NOTES_JSON;
 process.env.T08_PRIVATE_NOTES_JSON=JSON.stringify([
  {title:'test 1',body:'fixture A'},{title:'test 2',body:'fixture B'},{title:'test 3',body:'fixture C'}]);
 globalThis.fetch=async()=>({status:200,json:async()=>({authenticated:true,ownerId:1})});
 try{
  const {state,r}=res();
  await privateHandler({method:'GET',headers:{cookie:'__Host-t08_session='+token}},r);
  assert.equal(state.status,200);
  assert.equal(state.data.items.length,3);
 }finally{
  globalThis.fetch=fetchOriginal;
  if(saved===undefined)delete process.env.T08_PRIVATE_NOTES_JSON;
  else process.env.T08_PRIVATE_NOTES_JSON=saved;
 }
});
