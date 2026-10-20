// Task 08 Card 3. The Vercel server owns the HttpOnly browser session cookie.
const BACKEND='https://bcwzllejypavwgsfqfbm.supabase.co/functions/v1/t08-login';
const COOKIE='__Host-t08_session';
const ORIGIN='https://my-intro-t08.vercel.app';
export function getSession(req){
 const cookies=String(req.headers?.cookie||'').split(';');
 const pair=cookies.map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='));
 const value=pair?.slice(COOKIE.length+1)||'';
 return /^[0-9a-f]{64}$/.test(value)?value:null;
}
export async function edge(action,fields={}){
 try {
  const upstream=await fetch(BACKEND,{
   method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},
   body:JSON.stringify({action,...fields}),signal:AbortSignal.timeout(12000)
  });
  const payload=await upstream.json().catch(()=>({error:'invalid_auth_server_response'}));
  return {status:upstream.status,data:payload};
 }catch{return {status:503,data:{error:'authentication_server_unavailable'}};}
}
function noCache(res){
 res.setHeader('Cache-Control','private, no-store, max-age=0');
 res.setHeader('X-Content-Type-Options','nosniff');
}
function clearCookie(res){
 res.setHeader('Set-Cookie',COOKIE+'=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
}
export default async function handler(req,res){
 noCache(res);
 if(req.method!=='POST'){
  res.setHeader('Allow','POST');
  return res.status(405).json({error:'method_not_allowed'});
 }
 if(req.headers?.origin!==ORIGIN)return res.status(403).json({error:'origin_not_allowed'});
 const body=req.body;
 if(!body||typeof body!=='object'||Array.isArray(body)||JSON.stringify(body).length>40000)
  return res.status(400).json({error:'invalid_json'});
 const action=body.action;
 if(action==='status'){
  const session=getSession(req);
  if(!session)return res.status(200).json({authenticated:false,sessionType:'server_session'});
  const result=await edge('validate',{session});
  if(result.status>=500)return res.status(503).json({error:'authentication_server_unavailable',authenticated:false});
  const authenticated=result.status===200&&result.data.authenticated===true;
  return res.status(200).json({authenticated,sessionType:'server_session',
   ...(authenticated?{passkeyName:result.data.passkeyName||'등록된 패스키'}:{})});
 }
 if(action==='logout'){
  const session=getSession(req);
  let result={status:401,data:{error:'authentication_required'}};
  if(session)result=await edge('logout',{session});
  // Demonstrate C33 server-side: reuse the very same opaque session after revocation.
  // Neither cookie contents nor token hashes leave the server response.
  const replay=session&&result.status===200?await edge('validate',{session}):null;
  clearCookie(res);
  return res.status(result.status).json(result.status===200?
    {loggedOut:true,reuseStatus:replay?.status??null,sessionRedacted:'[REDACTED]'}:
    {...result.data,loggedOut:false});
 }
 if(action==='options'||action==='cancel'){
  const fields=action==='cancel'?{challengeId:body.challengeId}:{};
  const result=await edge(action,fields);
  return res.status(result.status).json(result.data);
 }
 if(action==='verify'){
  if(!body.challengeId||!body.response)return res.status(400).json({error:'missing_assertion'});
  const result=await edge('verify',{challengeId:body.challengeId,response:body.response});
  if(result.status!==200||result.data.authenticated!==true||!/^[0-9a-f]{64}$/.test(result.data.session||'')){
   return res.status(result.status===200?502:result.status).json({error:result.data.error||'login_verification_failed'});
  }
  res.setHeader('Set-Cookie',COOKIE+'='+result.data.session+'; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Strict');
  return res.status(200).json({authenticated:true,sessionType:'server_session',
   expiresAt:result.data.expiresAt,signatureVerified:true,
   passkeyName:result.data.passkeyName||'등록된 패스키'});
 }
 return res.status(400).json({error:'unknown_action'});
}
