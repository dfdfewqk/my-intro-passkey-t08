// Task 08 Card 3: verify signed WebAuthn assertions against enrolled public keys.
// Server alone holds login challenges and session hashes. Never write raw tokens to logs.
import { createClient } from 'npm:@supabase/supabase-js@2.118.0';
import { generateAuthenticationOptions, verifyAuthenticationResponse } from 'npm:@simplewebauthn/server@14.0.3';

const ORIGIN='https://my-intro-t08.vercel.app';
const RP_ID='my-intro-t08.vercel.app';
const url=Deno.env.get('SUPABASE_URL')||'';
let key=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')||'';
if(!key){
  try{key=JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS')||'{}').default||'';}catch{}
}
const db=url&&key?createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}}):null;
function send(obj:unknown,status=200){
  return new Response(JSON.stringify(obj),{status,headers:{
    'Content-Type':'application/json; charset=utf-8',
    'Cache-Control':'private, no-store, max-age=0',
    'X-Content-Type-Options':'nosniff'
  }});
}
async function hash(s:string){
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));
  return [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
function fromB64(s:string){
  const b=s.replaceAll('-','+').replaceAll('_','/');
  const bin=atob(b+'='.repeat((4-b.length%4)%4));
  return Uint8Array.from(bin,c=>c.charCodeAt(0));
}
function randToken(){
  const bytes=crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('');
}
async function audit(type:'issued'|'canceled'|'rejected'|'verified'|'replayed'|'logout',challenge?:string){
  if(!db)return;
  await db.from('t08_login_audit').insert({
    event_type:type,challenge_sha256:challenge?await hash(challenge):null
  });
}
function isValidSessionToken(token:unknown){
  return typeof token==='string'&&/^[0-9a-f]{64}$/.test(token);
}
Deno.serve(async req=>{
 if(!db)return send({error:'storage_unavailable'},503);
 if(req.method!=='POST')return send({error:'method_not_allowed'},405);
 if(Number(req.headers.get('content-length')||0)>40000)return send({error:'payload_too_large'},413);
 let body:Record<string,unknown>;
 try{
  const raw=await req.text();
  if(raw.length>40000)return send({error:'payload_too_large'},413);
  body=JSON.parse(raw);
  if(!body||typeof body!=='object'||Array.isArray(body))throw Error('invalid');
 }catch{return send({error:'invalid_json'},400);}
 const action=body.action;

 if(action==='validate'||action==='logout'){
  if(!isValidSessionToken(body.session))return send({error:'authentication_required'},401);
  const sessionHash=await hash(body.session as string);
  if(action==='logout'){
   const {data,error}=await db.from('t08_login_sessions')
    .update({revoked_at:new Date().toISOString()})
    .eq('session_hash',sessionHash).is('revoked_at',null)
    .select('session_hash').maybeSingle();
   if(error)return send({error:'storage_unavailable'},503);
   if(!data)return send({error:'session_expired_or_revoked'},401);
   await audit('logout');
   return send({loggedOut:true});
  }
  const {data,error}=await db.from('t08_login_sessions')
   .select('owner_id').eq('session_hash',sessionHash)
   .is('revoked_at',null).gt('expires_at',new Date().toISOString()).maybeSingle();
  if(error)return send({error:'storage_unavailable'},503);
  if(!data||data.owner_id!==1)return send({error:'session_expired_or_revoked'},401);
  return send({authenticated:true,ownerId:1});
 }

 if(action==='options'){
  const {data:keys,error}=await db.from('t08_passkeys')
    .select('credential_id,transports').eq('owner_id',1);
  if(error)return send({error:'storage_unavailable'},503);
  if(!keys?.length)return send({error:'no_registered_passkey'},409);
  const options=await generateAuthenticationOptions({
   rpID:RP_ID, userVerification:'required', timeout:120000,
   allowCredentials:keys.map(k=>({
    id:k.credential_id,
    transports:Array.isArray(k.transports)?k.transports:undefined
   }))
  });
  const {data:row,error:saveError}=await db.from('t08_login_challenges')
   .insert({challenge:options.challenge,expires_at:new Date(Date.now()+120000).toISOString()})
   .select('id').single();
  if(saveError||!row)return send({error:'challenge_storage_failed'},503);
  await audit('issued',options.challenge);
  return send({options,challengeId:row.id,challengeFingerprint:(await hash(options.challenge)).slice(0,16)});
 }

 const challengeId=typeof body.challengeId==='string'?body.challengeId:'';
 if(!/^[0-9a-f-]{36}$/i.test(challengeId))return send({error:'invalid_challenge_id'},400);

 if(action==='cancel'){
  const {data,error}=await db.from('t08_login_challenges')
   .delete().eq('id',challengeId).select('challenge').maybeSingle();
  if(error)return send({error:'storage_unavailable'},503);
  if(data)await audit('canceled',data.challenge);
  return send({canceled:true});
 }

 if(action==='verify'){
  // Atomic consumption: one issued challenge may only be checked once.
  const {data:issued,error:consumeError}=await db.from('t08_login_challenges')
   .delete().eq('id',challengeId).gt('expires_at',new Date().toISOString())
   .select('challenge').maybeSingle();
  if(consumeError)return send({error:'storage_unavailable'},503);
  if(!issued){
   await audit('replayed');
   return send({error:'challenge_expired_or_replayed'},409);
  }
  const response=body.response as Record<string,unknown>|undefined;
  const id=response&&typeof response.id==='string'?response.id:'';
  if(!id){await audit('rejected',issued.challenge);return send({error:'invalid_signature'},401);}
  const {data:keyRow,error:keyErr}=await db.from('t08_passkeys')
   .select('credential_id,public_key_base64url,counter,transports')
   .eq('credential_id',id).eq('owner_id',1).maybeSingle();
  if(keyErr)return send({error:'storage_unavailable'},503);
  if(!keyRow){await audit('rejected',issued.challenge);return send({error:'unknown_credential'},401);}
  let updatedCounter:number;
  try{
   const result=await verifyAuthenticationResponse({
    response:response as Parameters<typeof verifyAuthenticationResponse>[0]['response'],
    expectedChallenge:issued.challenge, expectedOrigin:ORIGIN, expectedRPID:RP_ID,
    credential:{id:keyRow.credential_id,publicKey:fromB64(keyRow.public_key_base64url),
     counter:Number(keyRow.counter),transports:keyRow.transports||[]},
    requireUserVerification:true
   });
   if(!result.verified||!result.authenticationInfo?.userVerified)throw Error('not_verified');
   updatedCounter=result.authenticationInfo.newCounter;
  }catch{
   await audit('rejected',issued.challenge);
   return send({error:'invalid_signature'},401);
  }
  const session=randToken();
  const expiresAt=new Date(Date.now()+12*60*60*1000).toISOString();
  const {error:storeErr}=await db.rpc('t08_open_login_session',{
    p_credential_id:keyRow.credential_id,
    p_new_counter:updatedCounter,p_session_hash:await hash(session),p_expires_at:expiresAt
  });
  if(storeErr){
   await audit('rejected',issued.challenge);
   return send({error:'session_creation_failed'},409);
  }
  await audit('verified',issued.challenge);
  return send({authenticated:true,session,expiresAt,sessionType:'server_session'});
 }
 return send({error:'unknown_action'},400);
});
