import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const script=fs.readFileSync(new URL('../client/login.js',import.meta.url),'utf8');
const flush=async()=>{await new Promise(r=>setImmediate(r));await new Promise(r=>setImmediate(r));};
function harness({missingPrivate=false,outage=false}={}){
 let loggedIn=false,asks=0,privateReads=0,logins=0;
 const els=new Map(),listeners=new Map(),records=[];
 class Element{
  constructor(){this.disabled=false;this.hidden=false;this.dataset={};this.textContent='';this.children=[];this.events={};}
  addEventListener(t,fn){this.events[t]=fn;}
  replaceChildren(...children){this.children=children;}
  append(...children){this.children.push(...children);}
 }
 function el(id){if(!els.has(id))els.set(id,new Element());return els.get(id);}
 const fetch=async (url,{body}={})=>{
  if(url==='/api/private'){
   privateReads++;
   return missingPrivate?{status:503,ok:false,json:async()=>({error:'private_notes_not_configured'})}:
    {status:200,ok:true,json:async()=>({private:true,items:[
     {title:'A',body:'1'},{title:'B',body:'2'},{title:'C',body:'3'}]})};
  }
  const request=JSON.parse(body||'{}');
  records.push(request.action);
  if(request.action==='status'){
   if(outage)return {status:503,json:async()=>({error:'authentication_server_unavailable'})};
   return {status:200,json:async()=>({
    authenticated:loggedIn,...(loggedIn?{passkeyName:'horse2'}:{})})};
  }
  if(request.action==='options'){
   asks++;
   return {status:200,json:async()=>({challengeId:'valid-id',
    challengeFingerprint:'abcd1234',options:{challenge:'Y2hhbGxlbmdl',
     allowCredentials:[],userVerification:'discouraged'}})};
  }
  if(request.action==='verify'){
   loggedIn=true;logins++;
   return {status:200,json:async()=>({authenticated:true,signatureVerified:true,passkeyName:'horse2'})};
  }
  if(request.action==='cancel')return {status:200,json:async()=>({canceled:true})};
  if(request.action==='logout'){
   loggedIn=false;
   return {status:200,json:async()=>({loggedOut:true,reuseStatus:401})};
  }
  throw Error('Unexpected '+request.action);
 };
 const window={isSecureContext:true,
  addEventListener(t,fn){if(!listeners.has(t))listeners.set(t,[]);listeners.get(t).push(fn);},
  dispatchEvent(e){for(const fn of listeners.get(e.type)||[])fn(e);}
 };
 const document={getElementById:el,createElement:()=>new Element()};
 const navigator={credentials:{get:async({publicKey})=>{
  assert.ok(publicKey.challenge);
  return {toJSON:()=>({id:'known-credential',rawId:'a25vd24',type:'public-key',
   response:{authenticatorData:'ZGF0YQ',clientDataJSON:'ZGF0YQ',signature:'c2ln',
   userHandle:'dXNlcg'}})};
 }}};
 const context={window,document,navigator,fetch,Date,AbortController,CustomEvent:
  class CustomEvent{constructor(type,options){this.type=type;this.detail=options?.detail;}},
  console,atob,btoa,PublicKeyCredential:class PublicKeyCredential{}};
 vm.createContext(context);vm.runInContext(script,context);
 return {el,window,context,records,
  get info(){return {asks,privateReads,logins,loggedIn};}};
}
test('horse2 signed login updates source credential and actually renders three private records',async()=>{
 const h=harness();
 await flush();
 assert.match(h.el('loginState').textContent,/로그아웃/);
 const accepted=await h.el('loginPasskey').events.click();
 await flush();
 assert.equal(accepted,true);
 assert.equal(h.info.logins,1);
 assert.equal(h.info.asks,1);
 assert.ok(h.info.privateReads>=1);
 assert.match(h.el('loginState').textContent,/horse2/);
 assert.match(h.el('loginMessage').textContent,/로그인 성공: horse2/);
 assert.match(h.el('loginMessage').textContent,/비공개 자료 3건/);
 assert.equal(h.el('vault').children.length,3);
 assert.equal(h.el('logoutPasskey').dataset.logged,'yes');
 assert.match(h.el('sessionProof').textContent,/HttpOnly/);
});
test('signed login remains visibly successful if private API is down',async()=>{
 const h=harness({missingPrivate:true});
 await flush();
 const success=await h.el('loginPasskey').events.click();
 assert.equal(success,true);
 assert.match(h.el('loginState').textContent,/horse2/);
 assert.match(h.el('loginMessage').textContent,/로그인 성공: horse2/);
 assert.match(h.el('loginMessage').textContent,/비공개 자료 조회 실패/);
});
test('authentication service outage is not mislabeled as logged out',async()=>{
 const h=harness({outage:true});await flush();
 assert.match(h.el('loginState').textContent,/일시 오류/);
 assert.doesNotMatch(h.el('loginState').textContent,/로그아웃 상태/);
 assert.match(h.el('loginMessage').textContent,/HTTP 503/);
 assert.equal(h.el('vault').children.length,1);
});
test('logout revokes auth and locks the vault despite earlier successful signature',async()=>{
 const h=harness();
 await flush();
 await h.el('loginPasskey').events.click();
 await flush();
 assert.equal(h.el('vault').children.length,3);
 await h.el('logoutPasskey').events.click();
 await flush();
 assert.equal(h.info.loggedIn,false);
 assert.match(h.el('loginState').textContent,/로그아웃/);
 assert.equal(h.el('logoutPasskey').disabled,true);
 assert.equal(h.el('vault').children.length,1);
 assert.match(h.el('vault').children[0].textContent,/잠김|로그인/);
});
test('live WebAuthn verification code requires server signature before inserting a session',()=>{
 const s=fs.readFileSync(new URL('../supabase/functions/t08-login/index.ts',import.meta.url),'utf8');
 assert.ok(s.includes('verifyAuthenticationResponse({'));
 assert.ok(s.includes('expectedChallenge:issued.challenge'));
 assert.ok(s.includes('expectedOrigin:ORIGIN, expectedRPID:RP_ID'));
 assert.ok(s.includes('t08_open_login_session'));
 assert.ok(s.indexOf('verifyAuthenticationResponse({')<s.indexOf("db.rpc('t08_open_login_session'"));
 assert.ok(s.includes('session_credential_removed'));
});
