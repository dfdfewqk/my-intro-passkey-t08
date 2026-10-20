import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import handler from '../api/private.js';
import status from '../api/status.js';

function call(fn, method='GET', headers={}) {
 const data={status:200,headers:{},body:null};
 const res={setHeader:(name,v)=>{data.headers[name]=v;return res;},
  status:(v)=>{data.status=v;return res;},
  json:(v)=>{data.body=v;return res;}};
 fn({method,headers},res);
 return data;
}
test('anonymous protected API returns 401 with no private content',()=>{
 const r=call(handler);
 assert.equal(r.status,401);
 assert.deepEqual(r.body,{error:'authentication_required'});
 assert.match(r.headers['Cache-Control'],/no-store/);
});
test('spoofed session cookie does not authorize',()=>{
 assert.equal(call(handler,'GET',{cookie:'passkeySession=forged'}).status,401);
});
test('private API does not permit write methods',()=>{
 assert.equal(call(handler,'POST').status,405);
});
test('public status only exposes record count, never content',()=>{
 const old=process.env.T08_PRIVATE_NOTES_JSON;
 process.env.T08_PRIVATE_NOTES_JSON=JSON.stringify([
  {label:'프로젝트 메모',body:'테스트 더미A'},
  {label:'지원 준비 목록',body:'테스트 더미B'},
  {label:'주간 회고',body:'테스트 더미C'}
 ]);
 const r=call(status); assert.equal(r.status,200);
 assert.equal(r.body.privateItemCount,3);
 assert.ok(!JSON.stringify(r.body).includes('테스트 더미'));
 if(old===undefined) delete process.env.T08_PRIVATE_NOTES_JSON;
 else process.env.T08_PRIVATE_NOTES_JSON=old;
});
test('static public page does not contain private text',()=>{
 const html=fs.readFileSync(path.join(import.meta.dirname,'../index.html'),'utf8');
 for(const secret of ['테스트 더미A','테스트 더미B','테스트 더미C']) assert.ok(!html.includes(secret));
});
