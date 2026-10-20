// Card 4: authenticated enrollment and key management only; service role never leaves Supabase.
import {createClient} from 'npm:@supabase/supabase-js@2.118.0';
import {generateRegistrationOptions,verifyRegistrationResponse} from 'npm:@simplewebauthn/server@14.0.3';
const RP='my-intro-t08.vercel.app', ORIGIN='https://my-intro-t08.vercel.app';
const url=Deno.env.get('SUPABASE_URL')||'';
let secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')||'';
if(!secret){try{secret=JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS')||'{}').default||'';}catch{}}
const db=secret&&url?createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}}):null;
const json=(x:unknown,s=200)=>new Response(JSON.stringify(x),{status:s,headers:{
 'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private',
 'X-Content-Type-Options':'nosniff'
}});
async function sha256(v:string){const x=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(v));
 return [...new Uint8Array(x)].map(b=>b.toString(16).padStart(2,'0')).join('');}
function toB64(bytes:Uint8Array){return btoa(String.fromCharCode(...bytes))
 .replaceAll('+','-').replaceAll('/','_').replaceAll('=','');}
function classifyError(message:string){
 if(message.includes('last_passkey_protected'))return [409,'last_passkey_protected'];
 if(message.includes('recent_login_required'))return [403,'recent_login_required'];
 if(message.includes('duplicate_credential')||message.includes('23505'))return [409,'duplicate_credential'];
 if(message.includes('session_expired_or_revoked'))return [401,'session_expired_or_revoked'];
 if(message.includes('credential_not_found'))return [404,'credential_not_found'];
 if(message.includes('too_many_passkeys'))return [409,'too_many_passkeys'];
 return [503,'database_operation_failed'];
}
Deno.serve(async(req)=>{
 if(!db)return json({error:'storage_unavailable'},503);
 if(req.method!=='POST')return json({error:'method_not_allowed'},405);
 let input:Record<string,unknown>;
 try{const body=await req.text();if(body.length>45000) return json({error:'payload_too_large'},413);
  input=JSON.parse(body);if(!input||typeof input!=='object'||Array.isArray(input))throw Error('invalid');
 }catch{return json({error:'invalid_request'},400);}
 const session=input.session;
 if(typeof session!=='string'||!/^[0-9a-f]{64}$/.test(session))return json({error:'authentication_required'},401);
 const sessionHash=await sha256(session);
 const {data:active,error:sessionError}=await db.from('t08_login_sessions')
  .select('owner_id,created_at').eq('session_hash',sessionHash)
  .is('revoked_at',null).gt('expires_at',new Date().toISOString()).maybeSingle();
 if(sessionError)return json({error:'storage_unavailable'},503);
 if(!active||active.owner_id!==1)return json({error:'session_expired_or_revoked'},401);
 const action=input.action;
 if(action==='list'){
  const {data,error}=await db.from('t08_passkeys')
   .select('credential_id,display_name,created_at,storage_provider,device_type,backed_up')
   .eq('owner_id',1).order('created_at',{ascending:true});
  if(error)return json({error:'storage_unavailable'},503);
  return json({passkeys:(data||[]).map(k=>({
    id:k.credential_id,name:k.display_name,createdAt:k.created_at,
    storageProvider:k.storage_provider,deviceType:k.device_type,backedUp:k.backed_up
   })),lastKeyDeletionBlocked:true});
 }
 if(action==='options'){
  const {data:keys,error}=await db.from('t08_passkeys')
   .select('credential_id,transports').eq('owner_id',1);
  if(error)return json({error:'storage_unavailable'},503);
  if(!keys?.length)return json({error:'account_has_no_passkeys'},409);
  if(keys.length>=10)return json({error:'too_many_passkeys'},409);
  const mode=['google','device','security_key','phone'].includes(String(input.storageProvider))
    ? String(input.storageProvider):'';
  if(!mode)return json({error:'storage_mode_required'},400);
  // 'google' lets Chrome display its regular chooser (site cannot select a Google account).
  // Local Windows Hello and roaming security-key modes are genuine WebAuthn
  // authenticator criteria, not just labels in the site's UI.
  const attachment: 'platform'|'cross-platform'|undefined =
    mode==='security_key'?'cross-platform':mode==='device'?'platform':undefined;
  const recommendedHints=mode==='phone'?['hybrid']:
    mode==='security_key'?['security-key']:
    mode==='device'?['client-device']:[];
  const optionsBase=await generateRegistrationOptions({
   rpName:'내 소개 · 개인 자료실',rpID:RP,userName:'owner',userDisplayName:'Owner',
   userID:new TextEncoder().encode('t08-owner-v1'),
   attestationType:'none',supportedAlgorithmIDs:[-7,-257],
   authenticatorSelection:{residentKey:'required',userVerification:'required',
    ...(attachment?{authenticatorAttachment:attachment}:{})},
   timeout:120000,
   excludeCredentials:keys.map(k=>({id:k.credential_id,
    transports:Array.isArray(k.transports)?k.transports:undefined}))
  });
  // The 'phone' mode deliberately avoids forcing cross-platform attachment.
  // Windows' native security dialog can otherwise default to USB keys,
  // while 'hybrid' remains only an advisory browser hint, not a QR guarantee.
  // A separate device may need to open the URL directly for enrollment.
  // Always keep excludeCredentials to prevent adding the same authenticator again.
  const options={...optionsBase,hints:recommendedHints};
  const {data:issued,error:saveError}=await db.from('t08_add_challenges')
   .insert({challenge:options.challenge,session_hash:sessionHash,requested_mode:mode,
    expires_at:new Date(Date.now()+3*60*1000).toISOString()})
   .select('id').single();
  if(saveError||!issued)return json({error:'challenge_storage_failed'},503);
  return json({options,requestedMode:mode,challengeId:issued.id,
    challengeFingerprint:(await sha256(options.challenge)).slice(0,16)});
 }
 if(action==='remove'){
  const id=typeof input.credentialId==='string'?input.credentialId:'';
  if(!id||id.length>2000)return json({error:'invalid_credential_id'},400);
  const {data,error}=await db.rpc('t08_remove_owner_passkey',{
   p_session_hash:sessionHash,p_credential_id:id
  });
  if(error){const [status,code]=classifyError(error.message);return json({error:code},Number(status));}
  return json({...data,removedCredential:id,sessionTokenRedacted:true});
 }
 const challengeId=typeof input.challengeId==='string'?input.challengeId:'';
 if(!/^[0-9a-f-]{36}$/i.test(challengeId))return json({error:'invalid_challenge_id'},400);
 if(action==='cancel'){
  const {error}=await db.from('t08_add_challenges')
   .delete().eq('session_hash',sessionHash).eq('id',challengeId);
  if(error)return json({error:'storage_unavailable'},503);
  return json({canceled:true,credentialStored:false});
 }
 if(action==='verify'){
  const name=typeof input.name==='string'?input.name.trim():'';
  if(name.length<2||name.length>48)return json({error:'invalid_display_name'},400);
  const storageProvider=['google','device','security_key','phone','unknown'].includes(String(input.storageProvider))
   ?String(input.storageProvider):'unknown';
  const {data:issued,error}=await db.from('t08_add_challenges')
   .delete().eq('id',challengeId).eq('session_hash',sessionHash)
   .gt('expires_at',new Date().toISOString()).select('challenge,requested_mode').maybeSingle();
  if(error)return json({error:'storage_unavailable'},503);
  if(!issued)return json({error:'challenge_expired_or_consumed'},409);
  if(String(input.storageProvider)!==issued.requested_mode)
    return json({error:'selected_storage_mode_changed',passkeyStored:false},400);
  let verified;
  try{
   verified=await verifyRegistrationResponse({
    response:input.response as Parameters<typeof verifyRegistrationResponse>[0]['response'],
    expectedChallenge:issued.challenge,expectedOrigin:ORIGIN,expectedRPID:RP,
    requireUserPresence:true,requireUserVerification:true,
   });
   if(!verified.verified||!verified.registrationInfo)throw Error('invalid');
  }catch{return json({error:'invalid_registration_response',passkeyStored:false},401);}
  const {credential,credentialDeviceType,credentialBackedUp}=verified.registrationInfo!;
  const {data:saved,error:saveError}=await db.rpc('t08_add_owner_passkey',{
    p_session_hash:sessionHash,p_credential_id:credential.id,p_name:name,
    p_public_key:toB64(credential.publicKey),
    p_user_handle:toB64(new TextEncoder().encode('t08-owner-v1')),
    p_counter:credential.counter,p_device_type:credentialDeviceType,
    p_backed_up:credentialBackedUp,p_transports:credential.transports||[],
    p_storage_provider:storageProvider
  });
  if(saveError){const [status,code]=classifyError(saveError.message);
   return json({error:code,passkeyStored:false},Number(status));}
  // authenticatorAttachment is a browser-reported category, not proof of a
  // specific physical vendor, device or Google account.
  const claimedAttachment=(input.response&&typeof input.response==='object'
    ?(input.response as {authenticatorAttachment?:unknown}).authenticatorAttachment:null);
  const attachmentLabel=claimedAttachment==='platform'||claimedAttachment==='cross-platform'
    ?claimedAttachment:'unknown';
  return json({verified:true,passkeyStored:true,credentialId:credential.id,
   displayName:name,totalPasskeys:saved.count,privateKeyReceived:false,
   requestedMode:issued.requested_mode,reportedAttachment:attachmentLabel});
 }
 return json({error:'unknown_action'},400);
});