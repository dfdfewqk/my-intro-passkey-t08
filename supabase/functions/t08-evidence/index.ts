// Stores redacted HTTP proof collected from authenticated browser requests across Chrome profiles.
// The site owner comes ONLY from an active WebAuthn-issued server session, not client input.
import {createClient} from 'npm:@supabase/supabase-js@2.118.0';
const url=Deno.env.get('SUPABASE_URL')||'';
let secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')||'';
if(!secret){try{secret=JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS')||'{}').default||'';}catch{}}
const db=url&&secret?createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}}):null;
const respond=(obj:unknown,status=200)=>new Response(JSON.stringify(obj),{status,headers:{
 'Content-Type':'application/json; charset=utf-8','Cache-Control':'private, no-store',
 'X-Content-Type-Options':'nosniff'
}});
async function hash(value:string){
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));
 return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function isNatural(n:unknown){return Number.isSafeInteger(n)&&Number(n)>=0&&Number(n)<=10000;}
Deno.serve(async(req)=>{
 if(!db)return respond({error:'storage_unavailable'},503);
 if(req.method!=='POST')return respond({error:'method_not_allowed'},405);
 let body:Record<string,unknown>;
 try{
  const txt=await req.text();if(txt.length>2400)return respond({error:'payload_too_large'},413);
  body=JSON.parse(txt);
  if(!body||typeof body!=='object'||Array.isArray(body))throw Error('bad');
 }catch{return respond({error:'invalid_json'},400);}
 if(typeof body.session!=='string'||!/^[0-9a-f]{64}$/.test(body.session))return respond({error:'authentication_required'},401);
 const digest=await hash(body.session);
 const {data:session,error:sessionError}=await db.from('t08_login_sessions')
  .select('owner_id,credential_id').eq('session_hash',digest).is('revoked_at',null)
  .gt('expires_at',new Date().toISOString()).maybeSingle();
 if(sessionError)return respond({error:'storage_unavailable'},503);
 if(!session||![1,2].includes(session.owner_id))return respond({error:'session_expired_or_revoked'},401);
 const {data:credential,error:keyError}=await db.from('t08_passkeys')
  .select('display_name').eq('credential_id',session.credential_id)
  .eq('owner_id',session.owner_id).maybeSingle();
 if(keyError)return respond({error:'storage_unavailable'},503);
 if(!credential)return respond({error:'session_credential_removed'},401);
 const fetchRecords=async()=>{
  const cutoff=new Date(Date.now()-24*3600*1000).toISOString();
  const {data,error}=await db!.from('t08_card5_evidence')
   .select('owner_id,observed_at,passkey_name,own_http,other_http,deny_error,after_http,spoof_http,spoof_owner_id,anonymous_http,before_count,after_count')
   .gte('observed_at',cutoff).order('owner_id',{ascending:true});
  if(error)return {error:true,records:[]};
  return {error:false,records:(data||[]).map(x=>({
   accountId:x.owner_id,timestamp:x.observed_at,passkeyName:x.passkey_name,
   ownHttp:x.own_http,denyHttp:x.other_http,denyError:x.deny_error,
   afterHttp:x.after_http,spoofHttp:x.spoof_http,spoofAccount:x.spoof_owner_id,
   anonymousHttp:x.anonymous_http,before:x.before_count,after:x.after_count,passed:true
  }))};
 };
 if(body.action==='status'){
  const result=await fetchRecords();
  return result.error?respond({error:'storage_unavailable'},503):
   respond({accountId:session.owner_id,records:result.records});
 }
 if(body.action==='save'){
  const proof=body.proof;
  if(!proof||typeof proof!=='object'||Array.isArray(proof))return respond({error:'invalid_evidence'},400);
  const p=proof as Record<string,unknown>;
  // The browser must run and check all five real HTTP requests first.
  // Reject incomplete/mismatched results; never persist raw notes, credentials or cookies.
  const isValid=
   p.accountId===session.owner_id&&p.ownHttp===200&&p.denyHttp===403&&
   p.denyError==='other_account_forbidden'&&p.afterHttp===200&&
   p.spoofHttp===200&&p.spoofAccount===session.owner_id&&p.anonymousHttp===401&&
   isNatural(p.before)&&isNatural(p.after)&&p.before===p.after&&p.passed===true;
  if(!isValid)return respond({error:'evidence_conditions_not_met'},422);
  const {error}=await db.from('t08_card5_evidence').upsert({
   owner_id:session.owner_id,observed_at:new Date().toISOString(),passkey_name:credential.display_name,
   own_http:200,other_http:403,deny_error:'other_account_forbidden',after_http:200,
   spoof_http:200,spoof_owner_id:session.owner_id,anonymous_http:401,
   before_count:p.before,after_count:p.after
  },{onConflict:'owner_id'});
  if(error)return respond({error:'storage_unavailable'},503);
  const result=await fetchRecords();
  return result.error?respond({error:'storage_unavailable'},503):
   respond({saved:true,accountId:session.owner_id,records:result.records});
 }
 return respond({error:'unknown_action'},400);
});