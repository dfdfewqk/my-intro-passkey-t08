// Card 4: same-origin passkey management. Only HttpOnly authenticated sessions may act.
import {getSession} from './auth.js';
const BACKEND='https://bcwzllejypavwgsfqfbm.supabase.co/functions/v1/t08-keys';
const ORIGIN='https://my-intro-t08.vercel.app';
export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store, private, max-age=0');
 res.setHeader('X-Content-Type-Options','nosniff');
 if(req.method!=='POST'){
  res.setHeader('Allow','POST');return res.status(405).json({error:'method_not_allowed'});
 }
 if(req.headers?.origin!==ORIGIN)return res.status(403).json({error:'origin_not_allowed'});
 const session=getSession(req);
 if(!session)return res.status(401).json({error:'authentication_required'});
 const body=req.body;
 if(!body||typeof body!=='object'||Array.isArray(body)||JSON.stringify(body).length>45000)
  return res.status(400).json({error:'invalid_json'});
 const action=body.action;
 if(!['list','options','verify','cancel','remove'].includes(action))
  return res.status(400).json({error:'unknown_action'});
 const allowed={action,session};
 if(action==='verify'){
  allowed.challengeId=body.challengeId;
  allowed.response=body.response;
  allowed.name=body.name;
  allowed.storageProvider=body.storageProvider;
 }else if(action==='cancel')allowed.challengeId=body.challengeId;
 else if(action==='options')allowed.storageProvider=body.storageProvider;
 else if(action==='remove')allowed.credentialId=body.credentialId;
 try{
  const r=await fetch(BACKEND,{
   method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},
   body:JSON.stringify(allowed),signal:AbortSignal.timeout(18000)
  });
  const value=await r.json().catch(()=>({error:'invalid_upstream_response'}));
  return res.status(r.status).json(value);
 }catch{return res.status(503).json({error:'key_management_unavailable'});}
}