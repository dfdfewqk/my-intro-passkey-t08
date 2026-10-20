import test from 'node:test';
import assert from 'node:assert/strict';
import gateway from '../api/enroll.js';
function fake(body,method='POST'){
 return {method,headers:{'content-length':String(JSON.stringify(body).length)},body};
}
function capture(){
 const info={status:200,body:null,headers:{}};
 const res={setHeader(k,v){info.headers[k]=v;return res;},
 status(code){info.status=code;return res;},
 json(payload){info.body=payload;return res;}};
 return {info,res};
}
test('gateway refuses GET',async()=>{
 const {info,res}=capture();
 await gateway(fake({},'GET'),res);
 assert.equal(info.status,405);
});
test('gateway refuses non-object input',async()=>{
 const {info,res}=capture();
 await gateway(fake([]),res);
 assert.equal(info.status,400);
});
test('gateway does not invent successful registration on upstream failure',async()=>{
 const old=globalThis.fetch;
 globalThis.fetch=async()=>{throw Error('offline');};
 try{
  const {info,res}=capture();
  await gateway(fake({action:'status'}),res);
  assert.equal(info.status,502);
 }finally{globalThis.fetch=old;}
});
test('gateway forwards only to dedicated edge function',async()=>{
 const old=globalThis.fetch;let target='';
 globalThis.fetch=async (url)=>{target=url;return {status:403,json:async()=>({error:'invite_required'})};};
 try{
  const {info,res}=capture();
  await gateway(fake({action:'options',invite:'invalid'}),res);
  assert.equal(info.status,403);
  assert.equal(target,'https://bcwzllejypavwgsfqfbm.supabase.co/functions/v1/t08-register');
 }finally{globalThis.fetch=old;}
});
