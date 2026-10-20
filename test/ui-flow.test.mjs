import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');
const keyCode=fs.readFileSync(new URL('../client/keys.js',import.meta.url),'utf8');
const loginCode=fs.readFileSync(new URL('../client/login.js',import.meta.url),'utf8');
const enrollCode=fs.readFileSync(new URL('../client/enroll.js',import.meta.url),'utf8');

function simulatedClient({holdInitial=false}={}){
 const elements=new Map(), listeners=new Map();
 class FakeElement {
   constructor(id='') { this.id=id;this.disabled=id==='keyAdd'||id==='keyEnrollmentFields';this.hidden=false;this.textContent='';this.children=[];this.handlers={};this.focused=false;this.className='';this.value=''; }
   addEventListener(type,fn){this.handlers[type]=fn;}
   append(...items){this.children.push(...items);}
   replaceChildren(...items){this.children=items;}
   focus(){this.focused=true;}
 }
 const el=id=>{if(!elements.has(id))elements.set(id,new FakeElement(id));return elements.get(id);};
 let signedIn=false, firstResolve, requestCount=0;
 const validKeys=[{id:'credential-test-only',name:'horse',createdAt:'2026-10-20T00:55:49Z',storageProvider:'google'}];
 const fakeFetch=async (_url,{body}={})=>{
   const request=JSON.parse(body||'{}');
   if(request.action!=='list') throw Error('Only inventory list is permitted by this UI mock');
   requestCount++;
   if(holdInitial&&requestCount===1) return new Promise(resolve=>{firstResolve=resolve;});
   return {status:signedIn?200:401,json:async()=>signedIn?{passkeys:validKeys}:{error:'authentication_required'}};
 };
 const window={
   addEventListener(type,fn){if(!listeners.has(type))listeners.set(type,[]);listeners.get(type).push(fn);},
   dispatchEvent(event){for(const fn of listeners.get(event.type)||[])fn(event);},
   t08StartLogin:async()=>{signedIn=true;window.dispatchEvent({type:'t08-auth-state',detail:{authenticated:true}});}
 };
 const document={getElementById:el,createElement(tag){return new FakeElement(tag);}};
 const sessionStorage={getItem(){return null;},setItem(){}};
 const context={window,document,fetch:fakeFetch,Date,console,sessionStorage,AbortController,PublicKeyCredential:class{},navigator:{},location:{origin:'https://my-intro-t08.vercel.app'},CustomEvent:class{},setTimeout};
 vm.runInNewContext(keyCode,context);
 return {el,window,releaseInitial:()=>firstResolve?.({status:401,json:async()=>({error:'authentication_required'})})};
}
const flush=async()=>{await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));};

test('Card 4 has a direct sign-in step before the initially disabled additional credential form',()=>{
 assert.ok(html.indexOf('id="keyGate"')<html.indexOf('id="keyEnrollmentFields"'));
 assert.match(html,/id="keyUnlock"/);
 assert.match(html,/id="keyEnrollmentFields" disabled/);
 assert.match(html,/id="registerPanel" hidden/);
 assert.match(html,/id="keyAdd" disabled/);
});
test('Consumed first enrollment stays out of the active UI',()=>{
 assert.ok(enrollCode.includes("el('registerPanel').hidden=true"));
 assert.ok(enrollCode.includes("sessionStorage.removeItem('t08_owner_invitation')"));
});
test('Unauthenticated UI locks the form; in-panel WebAuthn login unlocks it',async()=>{
 const env=simulatedClient();
 await flush();
 assert.equal(env.el('keyAdd').disabled,true);
 assert.equal(env.el('keyGate').hidden,false);
 assert.equal(env.el('keyEnrollmentFields').disabled,true);
 await env.el('keyUnlock').handlers.click();
 await flush();
 assert.equal(env.el('keyGate').hidden,true);
 assert.equal(env.el('keyAdd').disabled,false);
 assert.equal(env.el('keyEnrollmentFields').disabled,false);
 assert.equal(env.el('additionalKeyName').focused,true);
 assert.ok(env.el('keyListDetailed').children.length>0);
});
test('An old 401 inventory response cannot re-lock the UI after successful login',async()=>{
 const env=simulatedClient({holdInitial:true});
 await flush();
 await env.el('keyUnlock').handlers.click();
 await flush();
 env.releaseInitial();
 await flush();
 assert.equal(env.el('keyGate').hidden,true);
 assert.equal(env.el('keyAdd').disabled,false);
});
test('Cross-session auth checks abort stale private data retrieval and hide previous vault data',()=>{
 assert.ok(loginCode.includes('revision!==authRevision'));
 assert.ok(loginCode.includes('privateRequest.abort()'));
 assert.ok(loginCode.includes('if(!ok)lockVault()'));
 assert.ok(loginCode.includes('window.t08StartLogin=login'));
});
