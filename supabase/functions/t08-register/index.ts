// Card 2: registration only. Never store authenticator private keys.
// Authenticator-generated credential public keys are verified cryptographically.
import { createClient } from 'npm:@supabase/supabase-js@2.118.0';
import { generateRegistrationOptions, verifyRegistrationResponse } from 'npm:@simplewebauthn/server@14.0.3';

const origin = 'https://my-intro-t08.vercel.app';
const rpID = 'my-intro-t08.vercel.app';
const supaURL = Deno.env.get('SUPABASE_URL') || '';
let secret = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || '';
if (!secret) {
  try { secret = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') || '{}').default || ''; }
  catch { /* Fail closed below. */ }
}
const db = secret && supaURL ? createClient(supaURL, secret, {
  auth: { persistSession: false, autoRefreshToken: false },
}) : null;

const json = (payload: unknown, status = 200) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, private', 'X-Content-Type-Options': 'nosniff' },
  });
async function sha256(value: string) {
  const data = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(data), n => n.toString(16).padStart(2,'0')).join('');
}
function toB64URL(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}
function cleanName(value: unknown) {
  return typeof value === 'string' ? value.trim().slice(0,48) : '';
}
async function record(type: 'issued'|'canceled'|'verified'|'rejected', challenge: string) {
  if (!db) return;
  await db.from('t08_registration_audit').insert({
    event_type:type, challenge_sha256: await sha256(challenge),
  });
}
Deno.serve(async (req) => {
  if (!db) return json({error:'storage_not_configured'},503);
  if (req.method !== 'POST') return json({error:'method_not_allowed'},405);
  if (Number(req.headers.get('content-length')||0)>40000) return json({error:'payload_too_large'},413);
  let data: Record<string, unknown>;
  try {
    const raw=await req.text();
    if(raw.length>40000) return json({error:'payload_too_large'},413);
    data=JSON.parse(raw);
    if(!data||typeof data!=='object'||Array.isArray(data)) throw Error('bad json');
  } catch { return json({error:'invalid_json'},400); }
  const action=data.action;
  if (action === 'status') {
    const {count,error}=await db.from('t08_passkeys')
      .select('credential_id',{head:true,count:'exact'});
    if(error) return json({error:'storage_error'},503);
    return json({card:2,registeredCount:count||0,passwordUsed:false});
  }
  const invite=typeof data.invite==='string'?data.invite:'';
  if (!/^[a-f0-9]{64}$/i.test(invite)) return json({error:'invite_required'},403);
  const tokenHash=await sha256(invite.toLowerCase());
  const now=new Date().toISOString();
  const {data:row,error:inviteError}=await db.from('t08_enrollment_invites')
    .select('token_hash,expires_at,consumed_at')
    .eq('token_hash',tokenHash).gt('expires_at',now).maybeSingle();
  if(inviteError) return json({error:'storage_error'},503);
  if(!row) return json({error:'invite_invalid_or_expired'},403);

  if(action==='list') {
    // The setup token can read only non-sensitive metadata while it is valid.
    const {data:list,error}=await db.from('t08_passkeys')
      .select('credential_id,display_name,public_key_base64url,storage_provider,created_at')
      .order('created_at',{ascending:true});
    if(error) return json({error:'storage_error'},503);
    return json({passkeys:(list||[]).map((x)=>({
      id:x.credential_id, name:x.display_name,
      publicKey:x.public_key_base64url, storageProvider:x.storage_provider,
      createdAt:x.created_at,
    }))});
  }

  if (row.consumed_at) return json({error:'invite_already_used'},403);

  if(action==='options') {
    const {count,error:countError}=await db.from('t08_passkeys')
      .select('credential_id',{head:true,count:'exact'});
    if(countError) return json({error:'storage_error'},503);
    if((count||0)>0) return json({error:'owner_already_registered'},409);
    try {
      const options=await generateRegistrationOptions({
        rpName:'내 소개 · 패스키 자료실',rpID,
        userName:'owner',userDisplayName:'Owner',
        userID:new TextEncoder().encode('t08-owner-v1'),
        attestationType:'none',
        authenticatorSelection:{residentKey:'required',userVerification:'required'},
        timeout:120000,supportedAlgorithmIDs:[-7,-257],
      });
      const expiresAt=new Date(Date.now()+3*60*1000).toISOString();
      const {data:challenge,error}=await db.from('t08_registration_challenges')
        .insert({token_hash:tokenHash,challenge:options.challenge,expires_at:expiresAt})
        .select('id').single();
      if(error||!challenge) return json({error:'challenge_not_saved'},503);
      await record('issued',options.challenge);
      return json({options,challengeId:challenge.id,expiresAt,
        challengeFingerprint:(await sha256(options.challenge)).slice(0,16)});
    } catch { return json({error:'registration_options_failed'},500); }
  }

  const challengeId=typeof data.challengeId==='string' ? data.challengeId:'';
  if(!/^[0-9a-f-]{36}$/i.test(challengeId))
    return json({error:'invalid_challenge_id'},400);

  if(action==='cancel') {
    const {data:discard,error}=await db.from('t08_registration_challenges')
      .delete().eq('id',challengeId).eq('token_hash',tokenHash)
      .select('challenge').maybeSingle();
    if(error) return json({error:'storage_error'},503);
    if(discard) await record('canceled',discard.challenge);
    return json({canceled:true,passkeySaved:false});
  }

  if(action==='verify') {
    const name=cleanName(data.name);
    const storageProvider=['google','device','security_key','unknown'].includes(String(data.storageProvider))
      ? String(data.storageProvider):'unknown';
    if(name.length<2) return json({error:'name_too_short'},400);
    const response=data.response;
    if (!response||typeof response!=='object')
      return json({error:'missing_webauthn_response'},400);
    // Atomic deletion means the challenge cannot be reused by a second request.
    const {data:challenge,error:challengeError}=await db.from('t08_registration_challenges')
      .delete().eq('id',challengeId).eq('token_hash',tokenHash)
      .gt('expires_at',now).select('challenge').maybeSingle();
    if(challengeError) return json({error:'storage_error'},503);
    if(!challenge) return json({error:'challenge_expired_or_consumed'},409);
    let verified;
    try {
      verified=await verifyRegistrationResponse({
        response:response as Parameters<typeof verifyRegistrationResponse>[0]['response'],
        expectedChallenge:challenge.challenge,
        expectedOrigin:origin,expectedRPID:rpID,
        requireUserPresence:true,requireUserVerification:true,
      });
      if(!verified.verified||!verified.registrationInfo)
        throw new Error('not_verified');
    } catch {
      await record('rejected',challenge.challenge);
      return json({error:'invalid_registration_response',passkeySaved:false},400);
    }
    const {credential,credentialDeviceType,credentialBackedUp}=verified.registrationInfo!;
    const pubkey=toB64URL(credential.publicKey);
    const {error:saveError}=await db.rpc('t08_finalize_registration',{
      p_token_hash:tokenHash,p_credential_id:credential.id,
      p_name:name,p_public_key:pubkey,
      p_user_handle:toB64URL(new TextEncoder().encode('t08-owner-v1')),
      p_counter:credential.counter,
      p_device_type:credentialDeviceType,
      p_backed_up:credentialBackedUp,
      p_transports:credential.transports||[],
      p_storage_provider:storageProvider,
    });
    if(saveError) {
      await record('rejected',challenge.challenge);
      return json({error:'public_key_not_saved',passkeySaved:false},409);
    }
    await record('verified',challenge.challenge);
    return json({verified:true,passkeySaved:true,
      passkey:{id:credential.id,name,publicKey:pubkey,
        publicKeyFormat:'COSE public key (base64url)',
        storageProvider,counter:credential.counter,
        deviceType:credentialDeviceType,backedUp:credentialBackedUp},
      requestBodyFields:['action','invite','challengeId','name','storageProvider',
        'response.id','response.rawId','response.type',
        'response.response.attestationObject','response.response.clientDataJSON',
        'response.response.transports','response.clientExtensionResults'],
      privateKeyReceived:false,
    });
  }
  return json({error:'unknown_action'},400);
});