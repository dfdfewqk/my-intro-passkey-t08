import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import handler from '../api/profile.js';

const token='a'.repeat(64);
const cookie='__Host-t08_session='+('b'.repeat(64));
function request(action,{origin='https://my-intro-t08.vercel.app',cookieHeader='',extra={}}={}){
 return {method:'POST',headers:{origin,cookie:cookieHeader},body:{action,...extra}};
}
function reply(){
 const out={status:200,body:null,headers:{}};
 const res={setHeader(n,v){out.headers[n]=v;return res;},
 status(status){out.status=status;return res;},
 json(payload){out.body=payload;return res;}};
 return {out,res};
}
test('only logged-in owner may issue a second-profile registration ticket',async()=>{
 const {out,res}=reply();
 await handler(request('issue',{extra:{name:'horse2'}}),res);
 assert.equal(out.status,401);
 assert.equal(out.body.error,'authentication_required');
});
test('cross-site requests cannot issue or redeem tickets',async()=>{
 for(const action of ['issue','options','verify']){
  const {out,res}=reply();
  await handler(request(action,{origin:'https://untrusted.example',
    cookieHeader:cookie,extra:{ticket:token}}),res);
  assert.equal(out.status,403);
 }
});
test('invalid ticket cannot start enrollment in another profile',async()=>{
 const {out,res}=reply();
 await handler(request('options',{extra:{ticket:'not-a-valid-link'}}),res);
 assert.equal(out.status,403);
 assert.equal(out.body.error,'link_required');
});
test('owner issued ticket only receives the server-owned session cookie, never an injected body value',async()=>{
 const old=globalThis.fetch;let captured;
 globalThis.fetch=async(_url,options)=>{
  captured=JSON.parse(options.body);
  return {status:200,json:async()=>({ticket:token,expiresInSeconds:300})};
 };
 try{
  const {out,res}=reply();
  await handler(request('issue',{cookieHeader:cookie,extra:{name:'horse2',session:'forged'}}),res);
  assert.equal(out.status,200);
  assert.equal(captured.session,'b'.repeat(64));
  assert.notEqual(captured.session,'forged');
  assert.equal(captured.name,'horse2');
 }finally{globalThis.fetch=old;}
});
test('different Chrome profile redeems a ticket with no session, only limited enrollment actions',async()=>{
 const old=globalThis.fetch;let captured;
 globalThis.fetch=async(url,options)=>{
  captured={url,body:JSON.parse(options.body)};
  return {status:200,json:async()=>({challengeId:'challenge-id',options:{user:{id:'unique-handle'}}})};
 };
 try{
  const {out,res}=reply();
  await handler(request('options',{extra:{ticket:token}}),res);
  assert.equal(out.status,200);
  assert.equal(captured.body.ticket,token);
  assert.equal(captured.body.session,undefined);
  assert.ok(captured.url.endsWith('/functions/v1/t08-profile'));
  assert.equal(out.body.options.user.id,'unique-handle');
 }finally{globalThis.fetch=old;}
});
test('gateway disallows unrelated actions, method misuse, and tokenless verification',async()=>{
 let v=reply();
 await handler(request('list',{extra:{ticket:token}}),v.res);
 assert.equal(v.out.status,400);
 v=reply();
 await handler({...request('issue'),method:'GET'},v.res);
 assert.equal(v.out.status,405);
 v=reply();
 await handler(request('verify',{extra:{ticket:''}}),v.res);
 assert.equal(v.out.status,403);
});
test('server only finalizes after verified WebAuthn signature and atomically consumes one-time ticket',()=>{
 const source=fs.readFileSync(new URL('../supabase/functions/t08-profile/index.ts',import.meta.url),'utf8');
 assert.ok(source.includes('verifyRegistrationResponse({'));
 assert.ok(source.includes('expectedChallenge:row.challenge'));
 assert.ok(source.includes('expectedOrigin:ORIGIN,expectedRPID:RP'));
 assert.ok(source.includes('requireUserPresence:true,requireUserVerification:false'));
 assert.ok(source.includes("'t08_finalize_profile_enrollment'"));
 assert.ok(source.includes(".delete().eq('ticket_hash',ticket.token_hash).eq('id',input.challengeId)"));
 assert.ok(source.includes('registration_user_handle:handleEncoded'));
 assert.ok(source.includes('consumed_at'));
 assert.ok(source.includes('issuing_session_hash'));
});
test('Chrome profile B only gets registration from one-time fragment, no public key deletion access',()=>{
 const page=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
 const client=fs.readFileSync(new URL('../client/profile.js',import.meta.url),'utf8');
 assert.ok(page.includes('id="googleProfilePanel"'));
 assert.ok(page.includes('id="profileIssue"'));
 assert.ok(page.includes('id="profileEnrollBtn"'));
 assert.ok(page.includes('href="#googleProfilePanel"'));
 assert.ok(client.includes("'#profileEnroll='+result.data.ticket"));
 assert.ok(client.includes("history.replaceState(null,'',location.pathname+location.search)"));
 assert.ok(client.includes("await profileAPI('status',{ticket})"));
 assert.ok(client.includes("profileAPI('verify',{ticket:profileTicket"));
 assert.ok(client.includes("profileAPI('issue',{name})"));
 assert.ok(!client.includes("profileAPI('remove'"));
});


test('the normal card 4 registration form directly offers another existing Google account',()=>{
 const page=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
 const keys=fs.readFileSync(new URL('../client/keys.js',import.meta.url),'utf8');
 const profile=fs.readFileSync(new URL('../client/profile.js',import.meta.url),'utf8');
 assert.ok(page.includes('<option value="google_other" selected>'));
 assert.ok(page.includes('다른 Google 계정(B)에 패스키 저장'));
 const form=page.indexOf('id="additionalKeyProvider"');
 const panel=page.indexOf('id="googleProfilePanel"');
 const report=page.indexOf('등록·삭제 검증 기록');
 assert.ok(form>=0&&panel>form&&report>panel);
 assert.ok(keys.includes("if(provider==='google_other')"));
 assert.ok(keys.includes("window.t08IssueProfileTicket"));
 assert.ok(keys.includes("keyEl('profileNewName').value=name"));
 assert.ok(profile.includes('window.t08IssueProfileTicket=issueLink'));
 assert.ok(profile.includes("e('googleProfilePanel').scrollIntoView"));
 assert.ok(keys.indexOf("if(provider==='google_other')")<keys.indexOf("navigator.credentials?.create"));
 assert.ok(profile.includes("await getOwnerLogin()"));
 assert.ok(profile.includes("const result=await profileAPI('issue',{name})"));
});
