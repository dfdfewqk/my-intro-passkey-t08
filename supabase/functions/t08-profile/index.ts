// Card 4: owner-authorized, one-time cross-Chrome-profile Google passkey registration.
// Never expose the Google account selector as if WebAuthn could control it.
import {createClient} from 'npm:@supabase/supabase-js@2.118.0';
import {generateRegistrationOptions,verifyRegistrationResponse} from 'npm:@simplewebauthn/server@14.0.3';
const RP='my-intro-t08.vercel.app';
const ORIGIN='https://my-intro-t08.vercel.app';
const url=Deno.env.get('SUPABASE_URL')||'';
let secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')||'';
if(!secret){try{secret=JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS')||'{}').default||'';}catch{}}
const db=url&&secret?createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}}):null;
function send(data:unknown,status=200){return new Response(JSON.stringify(data),{status,headers:{
 'Content-Type':'application/json; charset=utf-8',
 'Cache-Control':'no-store,private,max-age=0','X-Content-Type-Options':'nosniff'
}});}
async function sha256(text:string){
 const raw=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));
 return [...new Uint8Array(raw)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function randomToken(){
 return [...crypto.getRandomValues(new Uint8Array(32))].map(b=>b.toString(16).padStart(2,'0')).join('');
}
function base64url(data:Uint8Array){
 return btoa(String.fromCharCode(...data)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}
function validToken(t:unknown){return typeof t==='string'&&/^[0-9a-f]{64}$/.test(t);}
function isUUID(t:unknown){return typeof t==='string'&&/^[0-9a-f-]{36}$/i.test(t);}
async function validIssuer(sessionHash:string){
 const {data,error}=await db!.from('t08_login_sessions').select('owner_id')
  .eq('session_hash',sessionHash).eq('owner_id',1).is('revoked_at',null)
  .gt('expires_at',new Date().toISOString()).maybeSingle();
 if(error)throw Error('storage_unavailable');
 return !!data;
}
async function validTicket(token:unknown){
 if(!validToken(token))return null;
 const tokenHash=await sha256(token as string);
 const {data,error}=await db!.from('t08_profile_enroll_tickets')
  .select('token_hash,display_name,issuing_session_hash')
  .eq('token_hash',tokenHash).is('consumed_at',null)
  .gt('expires_at',new Date().toISOString()).maybeSingle();
 if(error)throw Error('storage_unavailable');
 if(!data||!await validIssuer(data.issuing_session_hash))return null;
 return data;
}
Deno.serve(async(req)=>{
 if(!db)return send({error:'storage_unavailable'},503);
 if(req.method!=='POST')return send({error:'method_not_allowed'},405);
 let input:Record<string,unknown>;
 try{
  const raw=await req.text();
  if(raw.length>45000)return send({error:'payload_too_large'},413);
  input=JSON.parse(raw);
  if(!input||typeof input!=='object'||Array.isArray(input))throw Error('invalid');
 }catch{return send({error:'invalid_json'},400);}
 try{
  const action=input.action;
  if(action==='issue'){
   // Origin gateway derives this from the HttpOnly cookie; client cannot supply a session.
   if(!validToken(input.session))return send({error:'authentication_required'},401);
   const sessionHash=await sha256(input.session as string);
   if(!await validIssuer(sessionHash))return send({error:'session_expired_or_revoked'},401);
   const name=typeof input.name==='string'?input.name.trim():'';
   if(name.length<2||name.length>48)return send({error:'invalid_display_name'},400);
   const {count,error:countError}=await db.from('t08_passkeys')
    .select('credential_id',{head:true,count:'exact'}).eq('owner_id',1);
   if(countError)return send({error:'storage_unavailable'},503);
   if(!count)return send({error:'no_registered_passkey'},409);
   if(count>=10)return send({error:'too_many_passkeys'},409);
   // Only the newest ticket issued from the current session remains usable.
   const {error:dropError}=await db.from('t08_profile_enroll_tickets')
    .delete().eq('issuing_session_hash',sessionHash).is('consumed_at',null);
   if(dropError)return send({error:'storage_unavailable'},503);
   const token=randomToken(), expiresAt=new Date(Date.now()+5*60*1000).toISOString();
   const {error}=await db.from('t08_profile_enroll_tickets')
    .insert({token_hash:await sha256(token),issuing_session_hash:sessionHash,
       display_name:name,expires_at:expiresAt});
   if(error)return send({error:'ticket_issue_failed'},503);
   return send({ticket:token,expiresAt,name,expiresInSeconds:300});
  }
  const ticket=await validTicket(input.ticket);
  if(!ticket)return send({error:'link_expired_used_or_invalid'},403);
  if(action==='status')return send({allowed:true,name:ticket.display_name,provider:'google',expiresInSecondsMax:300});
  if(action==='options'){
   const {data:keys,error}=await db.from('t08_passkeys')
    .select('credential_id,transports').eq('owner_id',1);
   if(error)return send({error:'storage_unavailable'},503);
   if(!keys?.length)return send({error:'no_registered_passkey'},409);
   if(keys.length>=10)return send({error:'too_many_passkeys'},409);
   // Each credential is independent even if both live in the same Google
   // Password Manager. They all belong to the same site's owner_id=1.
   const handle=crypto.getRandomValues(new Uint8Array(32));
   const handleEncoded=base64url(handle);
   const options=await generateRegistrationOptions({
     rpName:'내 소개 · 개인 자료실',rpID:RP,
     userName:'owner-'+handleEncoded.slice(0,12),userDisplayName:ticket.display_name,
     userID:handle,attestationType:'none',
     authenticatorSelection:{residentKey:'preferred',userVerification:'discouraged'},
     supportedAlgorithmIDs:[-7,-257],timeout:120000
     // An existing passkey belongs to a different authenticator user handle;
     // excluding it would reject creating a second credential in the same manager.
   });
   const {data:row,error:saveError}=await db.from('t08_profile_enroll_challenges')
    .insert({ticket_hash:ticket.token_hash,challenge:options.challenge,
      registration_user_handle:handleEncoded,
      expires_at:new Date(Date.now()+120000).toISOString()}).select('id').single();
   if(saveError||!row)return send({error:'challenge_storage_failed'},503);
   return send({options,challengeId:row.id,displayName:ticket.display_name,
     challengeFingerprint:(await sha256(options.challenge)).slice(0,16)});
  }
  if(!isUUID(input.challengeId))return send({error:'invalid_challenge_id'},400);
  if(action==='cancel'){
   const {error}=await db.from('t08_profile_enroll_challenges')
    .delete().eq('ticket_hash',ticket.token_hash).eq('id',input.challengeId);
   return error?send({error:'storage_unavailable'},503):send({canceled:true,passkeyStored:false});
  }
  if(action==='verify'){
   const {data:row,error}=await db.from('t08_profile_enroll_challenges')
    .delete().eq('ticket_hash',ticket.token_hash).eq('id',input.challengeId)
    .gt('expires_at',new Date().toISOString()).select('challenge,registration_user_handle').maybeSingle();
   if(error)return send({error:'storage_unavailable'},503);
   if(!row)return send({error:'challenge_expired_or_reused'},409);
   if(typeof row.registration_user_handle!=='string'||!row.registration_user_handle)
     return send({error:'legacy_challenge_restart_required'},409);
   let verified;
   try{
     verified=await verifyRegistrationResponse({
       response:input.response as Parameters<typeof verifyRegistrationResponse>[0]['response'],
       expectedChallenge:row.challenge,expectedOrigin:ORIGIN,expectedRPID:RP,
       requireUserPresence:true,requireUserVerification:false
     });
     if(!verified.verified||!verified.registrationInfo)throw Error('invalid');
   }catch{return send({error:'invalid_registration_response',passkeyStored:false},401);}
   const {credential,credentialDeviceType,credentialBackedUp}=verified.registrationInfo!;
   const {data:finish,error:saveError}=await db.rpc('t08_finalize_profile_enrollment',{
     p_ticket_hash:ticket.token_hash,p_credential_id:credential.id,
     p_public_key:base64url(credential.publicKey),
     p_user_handle:row.registration_user_handle,
     p_counter:credential.counter,p_device_type:credentialDeviceType,
     p_backed_up:credentialBackedUp,p_transports:credential.transports||[]
   });
   if(saveError)return send({error:'save_rejected_or_link_consumed',passkeyStored:false},409);
   return send({verified:true,passkeyStored:true,displayName:finish.name,
     totalPasskeys:finish.count,privateKeyReceived:false});
  }
  return send({error:'unknown_action'},400);
 }catch{return send({error:'profile_enrollment_unavailable'},503);}
});