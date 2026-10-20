import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
const keyCode=fs.readFileSync(new URL('../client/keys.js',import.meta.url),'utf8');
const loginCode=fs.readFileSync(new URL('../client/login.js',import.meta.url),'utf8');
const enrollCode=fs.readFileSync(new URL('../client/enroll.js',import.meta.url),'utf8');

function simulatedClient({holdInitial=false,loginSucceeds=true,holdCreate=false,initialKeys=1,staleRemoval=false,confirmDeletion=true}={}){
 const elements=new Map(), listeners=new Map();
 class FakeElement{
  constructor(id=''){
   this.id=id;this.disabled=false;this.hidden=false;this.textContent='';
   this.children=[];this.handlers={};this.focused=false;this.className='';
   this.value=id==='additionalKeyName'?'horse2':id==='additionalKeyProvider'?'device':'';
  }
  addEventListener(type,fn){this.handlers[type]=fn;}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=items;}
  focus(){this.focused=true;}
 }
 const el=id=>{if(!elements.has(id))elements.set(id,new FakeElement(id));return elements.get(id);};
 let signedIn=false,firstResolve,requestCount=0,authPrompts=0,createCalls=0,cancelCalls=0,removeCalls=0;
 const confirmations=[];
 let created=0,pendingCreateResolve;
 const validKeys=[{id:'credential-horse',name:'horse',createdAt:'2026-10-20T00:55:49Z',storageProvider:'google'}];
 for(let i=1;i<initialKeys;i++)validKeys.push({id:'credential-horse2-'+i,name:'horse2',
  createdAt:'2026-10-20T02:12:00Z',storageProvider:'google'});
 const getJson=(status,body)=>({status,json:async()=>body});
 const fakeFetch=async(_url,{body}={})=>{
  const request=JSON.parse(body||'{}');
  if(request.action==='list'){
   requestCount++;
   if(holdInitial&&requestCount===1)return new Promise(resolve=>{firstResolve=resolve;});
   return signedIn?getJson(200,{passkeys:validKeys}):getJson(401,{error:'authentication_required'});
  }
  if(request.action==='options'){
   assert.equal(signedIn,true,'options require verified owner session');
   return getJson(200,{challengeId:'11111111-2222-4333-8444-555555555555',
    challengeFingerprint:'abc123',options:{challenge:'Y2hhbGxlbmdl',
    user:{id:'dDgtb3duZXItdjE',name:'owner',displayName:'Owner'},
    rp:{id:'my-intro-t08.vercel.app',name:'Intro'},pubKeyCredParams:[{type:'public-key',alg:-7}],
    excludeCredentials:[]}});
  }
  if(request.action==='cancel'){
   cancelCalls++;return getJson(200,{canceled:true});
  }
  if(request.action==='remove'){
   removeCalls++;
   if(staleRemoval&&removeCalls===1)return getJson(403,{error:'recent_login_required'});
   if(validKeys.length<=1)return getJson(409,{error:'last_passkey_protected'});
   const idx=validKeys.findIndex(k=>k.id===request.credentialId);
   if(idx<0)return getJson(404,{error:'credential_not_found'});
   validKeys.splice(idx,1);
   return getJson(200,{removed:true,remaining:validKeys.length,sessionRevoked:false});
  }
  if(request.action==='verify'){
   assert.equal(signedIn,true);
   assert.equal(request.name,'horse2');
   assert.equal(request.storageProvider,'device');
   created++;validKeys.push({id:'new-credential',name:'horse2',createdAt:'2026-10-20T02:12:00Z'});
   return getJson(200,{verified:true,passkeyStored:true,totalPasskeys:validKeys.length});
  }
  throw Error('Unexpected API action: '+request.action);
 };
 const window={
   PublicKeyCredential:class{},
   isSecureContext:true,
   confirm(text){confirmations.push(text);return confirmDeletion;},
   addEventListener(type,fn){if(!listeners.has(type))listeners.set(type,[]);listeners.get(type).push(fn);},
   dispatchEvent(event){for(const fn of listeners.get(event.type)||[])fn(event);},
   t08StartLogin:async()=>{authPrompts++;if(!loginSucceeds)return false;
     signedIn=true;window.dispatchEvent({type:'t08-auth-state',detail:{authenticated:true}});return true;}
 };
 const navigator={credentials:{create:async ({signal})=>{
   createCalls++;
   if(holdCreate)return new Promise((resolve,reject)=>{
     pendingCreateResolve=resolve;
     signal.addEventListener('abort',()=>{const error=new Error('Aborted');error.name='AbortError';reject(error);});
   });
   return {id:'new-credential',toJSON:()=>({
     id:'new-credential',rawId:'bmV3',type:'public-key',
     response:{attestationObject:'b2s',clientDataJSON:'b2s',transports:['internal']},
     clientExtensionResults:{}
   })};
 }}};
 const document={getElementById:el,createElement(tag){return new FakeElement(tag);}};
 const values=new Map();
 const sessionStorage={getItem(k){return values.get(k)||null;},setItem(k,v){values.set(k,v);}};
 const context={window,document,fetch:fakeFetch,Date,console,sessionStorage,
  AbortController,DOMException,navigator,location:{origin:'https://my-intro-t08.vercel.app'},
  PublicKeyCredential:class{},CustomEvent:class{},setTimeout,atob};
 vm.createContext(context);
 vm.runInContext(keyCode,context);
 return {el,window,context,setBusy:context.setKeyBusy,
  setSignedIn(value){signedIn=value;window.dispatchEvent({type:'t08-auth-state',detail:{authenticated:value}});},
  get stats(){return {authPrompts,createCalls,cancelCalls,created,removeCalls,confirmations,remaining:validKeys.length};},
  releaseInitial:()=>firstResolve?.(getJson(401,{error:'authentication_required'})),
  releaseCreate:()=>pendingCreateResolve?.(null)};
}
const flush=async()=>{await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));};

test('New credential form remains editable and Add clickable without a session',()=>{
 assert.match(html,/id="keyAdd"(?![^>]*disabled)/);
 assert.match(html,/id="keyEnrollmentFields"(?![^>]*disabled)/);
 assert.match(html,/id="keyUnlock"/);
 assert.match(html,/id="registerPanel" hidden/);
});
test('Old bootstrap enrollment is hidden after first key registration',()=>{
 assert.ok(enrollCode.includes("el('registerPanel').hidden=true"));
 assert.ok(enrollCode.includes("sessionStorage.removeItem('t08_owner_invitation')"));
});
test('Anonymous user can type details and start Add, which authenticates and registers a second key',async()=>{
 const env=simulatedClient();
 await flush();
 assert.equal(env.el('keyGate').hidden,false);
 assert.equal(env.el('keyAdd').disabled,false);
 assert.equal(env.el('keyEnrollmentFields').disabled,false);
 await env.el('keyAdd').handlers.click();
 await flush();
 assert.equal(env.stats.authPrompts,1);
 assert.equal(env.stats.createCalls,1);
 assert.equal(env.stats.created,1);
 assert.equal(env.el('keyAdd').disabled,false);
 assert.equal(env.el('keyEnrollmentFields').disabled,false);
 assert.equal(env.el('keyCountDetailed').textContent,'등록된 패스키: 2개');
});
test('Canceling WebAuthn login preserves name and does not start credential creation',async()=>{
 const env=simulatedClient({loginSucceeds:false});
 await flush();
 await env.el('keyAdd').handlers.click();
 await flush();
 assert.equal(env.stats.authPrompts,1);
 assert.equal(env.stats.createCalls,0);
 assert.equal(env.stats.created,0);
 assert.equal(env.el('additionalKeyName').value,'horse2');
 assert.equal(env.el('keyAdd').disabled,false);
 assert.equal(env.el('keyEnrollmentFields').disabled,false);
});
test('Expired session transparently asks for passkey login before creating new credential',async()=>{
 const env=simulatedClient();
 await flush();
 env.setSignedIn(true);
 await flush();
 env.setSignedIn(false);
 await flush();
 await env.el('keyAdd').handlers.click();
 await flush();
 assert.equal(env.stats.authPrompts,1);
 assert.equal(env.stats.created,1);
});
test('A delayed earlier 401 cannot re-lock add controls after successful authentication',async()=>{
 const env=simulatedClient({holdInitial:true});
 await flush();
 await env.el('keyAdd').handlers.click();
 await flush();
 env.releaseInitial();
 await flush();
 assert.equal(env.stats.created,1);
 assert.equal(env.el('keyAdd').disabled,false);
 assert.equal(env.el('keyEnrollmentFields').disabled,false);
});
test('Add is briefly disabled while an authenticator registration is pending; Cancel stays active',async()=>{
 const env=simulatedClient({holdCreate:true});
 await flush();
 const submit=env.el('keyAdd').handlers.click();
 await flush();
 assert.equal(env.el('keyAdd').disabled,true);
 assert.equal(env.el('keyCancel').disabled,false);
 assert.equal(env.el('keyEnrollmentFields').disabled,false);
 await env.el('keyCancel').handlers.click();
 await submit;
 await flush();
 assert.equal(env.stats.created,0);
 assert.ok(env.stats.cancelCalls>=1);
 assert.equal(env.el('keyAdd').disabled,false);
 assert.equal(env.el('keyEnrollmentFields').disabled,false);
});
test('Login returns a definite result so add flow cannot treat cancellation as success',()=>{
 assert.ok(loginCode.includes("return true;"));
 assert.ok(loginCode.includes("return false;"));
 assert.ok(keyCode.includes('const ok=await login();'));
});
test('Stale private data fetches are ignored and old vault contents are locked after logout',()=>{
 assert.ok(loginCode.includes('revision!==authRevision'));
 assert.ok(loginCode.includes('privateRequest.abort()'));
 assert.ok(loginCode.includes('if(!ok)lockVault()'));
});


test('duplicate horse2 keys display distinct credential IDs and delete buttons',async()=>{
 const env=simulatedClient({initialKeys:4});
 await flush();
 env.setSignedIn(true);
 await flush();
 const list=env.el('keyListDetailed').children;
 assert.equal(list.length,4);
 const names=list.slice(1).map(c=>c.children[0].children[0].textContent);
 const deletes=list.slice(1).map(c=>c.children[0].children[1].textContent);
 assert.equal(new Set(names).size,3);
 assert.equal(new Set(deletes).size,3);
 assert.ok(names.every(x=>x.includes('ID creden…')));
});
test('stale login on deletion automatically reauthenticates and deletes only confirmed credential',async()=>{
 const env=simulatedClient({initialKeys:4,staleRemoval:true});
 await flush();
 env.setSignedIn(true);
 await flush();
 const article=env.el('keyListDetailed').children[2];
 const button=article.children[0].children[1];
 await button.handlers.click();
 await flush();
 assert.equal(env.stats.removeCalls,2);
 assert.equal(env.stats.authPrompts,1);
 assert.equal(env.stats.confirmations.length,1);
 assert.ok(env.stats.confirmations[0].includes('creden…'));
 assert.equal(env.stats.remaining,3);
 assert.ok(env.el('keyManagementMessage').textContent.includes('삭제했습니다'));
});
test('canceling reauthentication never deletes the selected key',async()=>{
 const env=simulatedClient({initialKeys:4,staleRemoval:true,loginSucceeds:false});
 await flush();
 env.setSignedIn(true);
 await flush();
 await env.el('keyListDetailed').children[1].children[0].children[1].handlers.click();
 await flush();
 assert.equal(env.stats.removeCalls,1);
 assert.equal(env.stats.authPrompts,1);
 assert.equal(env.stats.remaining,4);
});
test('declining deletion confirmation never calls delete API',async()=>{
 const env=simulatedClient({initialKeys:4,confirmDeletion:false});
 await flush();
 env.setSignedIn(true);
 await flush();
 await env.el('keyListDetailed').children[1].children[0].children[1].handlers.click();
 await flush();
 assert.equal(env.stats.removeCalls,0);
 assert.equal(env.stats.remaining,4);
});
test('last passkey always has disabled delete button',async()=>{
 const env=simulatedClient({initialKeys:1});
 await flush();
 env.setSignedIn(true);
 await flush();
 const button=env.el('keyListDetailed').children[0].children[0].children[1];
 assert.equal(button.disabled,true);
 assert.ok(button.textContent.includes('보호됨'));
});
