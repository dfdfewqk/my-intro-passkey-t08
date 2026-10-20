// Card 5: create a THIRD independent passkey for site owner2.
import {createClient} from 'npm:@supabase/supabase-js@2.118.0';
import {generateRegistrationOptions,verifyRegistrationResponse} from 'npm:@simplewebauthn/server@14.0.3';
const RP='my-intro-t08.vercel.app',ORIGIN='https://my-intro-t08.vercel.app';
const url=Deno.env.get('SUPABASE_URL')||'';
let secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')||'';
if(!secret){try{secret=JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS')||'{}').default||'';}catch{}}
const db=url&&secret?createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}}):null;
const reply=(obj:unknown,status=200)=>new Response(JSON.stringify(obj),{status,headers:{
 'Content-Type':'application/json; charset=utf-8','Cache-Control':'private, no-store',
 'X-Content-Type-Options':'nosniff'}});
async function sha(value:string){
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));
 return [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
const b64=(buf:Uint8Array)=>btoa(String.fromCharCode(...buf))
 .replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
Deno.serve(async(req)=>{
 if(!db)return reply({error:'storage_unavailable'},503);
 if(req.method!=='POST')return reply({error:'method_not_allowed'},405);
 let data:Record<string,unknown>;
 try{
  const raw=await req.text();
  if(raw.length>45000)return reply({error:'payload_too_large'},413);
  data=JSON.parse(raw);if(!data||Array.isArray(data)||typeof data!=='object')throw Error('bad');
 }catch{return reply({error:'invalid_json'},400);}
 if(typeof data.session!=='string'||!/^[0-9a-f]{64}$/.test(data.session))return reply({error:'authentication_required'},401);
 const sessionHash=await sha(data.session);
 const {data:s,error:sessionError}=await db.from('t08_login_sessions')
  .select('owner_id,credential_id,created_at').eq('session_hash',sessionHash)
  .is('revoked_at',null).gt('expires_at',new Date().toISOString()).maybeSingle();
 if(sessionError)return reply({error:'storage_unavailable'},503);
 if(!s||s.owner_id!==1)return reply({error:'original_owner_auth_required'},403);
 const {data:key,error:keyError}=await db.from('t08_passkeys')
  .select('credential_id').eq('credential_id',s.credential_id).eq('owner_id',1).maybeSingle();
 if(keyError)return reply({error:'storage_unavailable'},503);
 if(!key)return reply({error:'session_expired_or_revoked'},401);
 if(data.action==='status'){
  const {count,error}=await db.from('t08_passkeys')
   .select('credential_id',{head:true,count:'exact'}).eq('owner_id',2);
  return error?reply({error:'storage_unavailable'},503):reply({owner2Ready:(count||0)>0});
 }
 if(new Date(s.created_at).getTime()<Date.now()-15*60*1000)return reply({error:'recent_login_required'},403);
 const {count:owner2Count,error:owner2Error}=await db.from('t08_passkeys')
  .select('credential_id',{head:true,count:'exact'}).eq('owner_id',2);
 if(owner2Error)return reply({error:'storage_unavailable'},503);
 if(owner2Count)return reply({error:'second_account_already_has_passkey'},409);
 const {count:ownerCount,error:ownerError}=await db.from('t08_passkeys')
  .select('credential_id',{head:true,count:'exact'}).eq('owner_id',1);
 if(ownerError)return reply({error:'storage_unavailable'},503);
 if((ownerCount||0)<2)return reply({error:'owner_needs_two_passkeys'},409);
 if(data.action==='options'){
  const name=typeof data.name==='string'?data.name.trim():'';
  if(name.length<2||name.length>48)return reply({error:'invalid_display_name'},400);
  const handle=crypto.getRandomValues(new Uint8Array(32));
  const opts=await generateRegistrationOptions({
   rpName:'내 소개 · 개인 자료실',rpID:RP,
   userName:'owner2-'+b64(handle).slice(0,12),userDisplayName:'owner2 / '+name,
   userID:handle,attestationType:'none',supportedAlgorithmIDs:[-7,-257],
   authenticatorSelection:{residentKey:'preferred',userVerification:'discouraged'},timeout:120000
  });
  const {error:deleteError}=await db.from('t08_owner2_enroll_challenges')
   .delete().eq('session_hash',sessionHash);
  if(deleteError)return reply({error:'storage_unavailable'},503);
  const {data:row,error}=await db.from('t08_owner2_enroll_challenges')
   .insert({session_hash:sessionHash,challenge:opts.challenge,
    registration_user_handle:b64(handle),display_name:name,
    expires_at:new Date(Date.now()+120000).toISOString()})
   .select('id').single();
  if(error||!row)return reply({error:'challenge_storage_failed'},503);
  return reply({challengeId:row.id,options:opts});
 }
 const challengeId=typeof data.challengeId==='string'?data.challengeId:'';
 if(!/^[0-9a-f-]{36}$/i.test(challengeId))return reply({error:'invalid_challenge_id'},400);
 if(data.action==='cancel'){
  const {error}=await db.from('t08_owner2_enroll_challenges')
   .delete().eq('id',challengeId).eq('session_hash',sessionHash);
  return error?reply({error:'storage_unavailable'},503):reply({canceled:true});
 }
 if(data.action==='verify'){
  const {data:issued,error}=await db.from('t08_owner2_enroll_challenges')
   .delete().eq('id',challengeId).eq('session_hash',sessionHash)
   .gt('expires_at',new Date().toISOString())
   .select('challenge,registration_user_handle,display_name').maybeSingle();
  if(error)return reply({error:'storage_unavailable'},503);
  if(!issued)return reply({error:'challenge_expired_or_consumed'},409);
  let checked;
  try{
   checked=await verifyRegistrationResponse({
    response:data.response as Parameters<typeof verifyRegistrationResponse>[0]['response'],
    expectedChallenge:issued.challenge,expectedOrigin:ORIGIN,expectedRPID:RP,
    requireUserPresence:true,requireUserVerification:false
   });
   if(!checked.verified||!checked.registrationInfo)throw Error('invalid');
  }catch{return reply({error:'invalid_registration_response'},401);}
  const {credential,credentialDeviceType,credentialBackedUp}=checked.registrationInfo!;
  const {data:saved,error:saveError}=await db.rpc('t08_initialize_owner2_passkey',{
   p_session_hash:sessionHash,p_credential_id:credential.id,p_name:issued.display_name,
   p_public_key:b64(credential.publicKey),p_user_handle:issued.registration_user_handle,
   p_counter:credential.counter,p_device_type:credentialDeviceType,
   p_backed_up:credentialBackedUp,p_transports:credential.transports||[]
  });
  if(saveError)return reply({error:'owner2_registration_rejected'},409);
  return reply({passkeyStored:true,verified:true,accountName:'owner2',
   displayName:issued.display_name,ownerKeyCount:saved.remainingOriginal});
 }
 return reply({error:'unknown_action'},400);
});