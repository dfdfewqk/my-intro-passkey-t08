// Task 08: cross-Chrome-profile passkey enrollment gateway.
// A current owner session may issue a 5-minute link. Only registration uses its token.
import {getSession} from './auth.js';
const BACKEND='https://bcwzllejypavwgsfqfbm.supabase.co/functions/v1/t08-profile';
const ORIGIN='https://my-intro-t08.vercel.app';
export default async function handler(req,res){
 res.setHeader('Cache-Control','private,no-store,max-age=0');
 res.setHeader('X-Content-Type-Options','nosniff');
 res.setHeader('Referrer-Policy','no-referrer');
 if(req.method!=='POST'){res.setHeader('Allow','POST');return res.status(405).json({error:'method_not_allowed'});}
 if(req.headers?.origin!==ORIGIN)return res.status(403).json({error:'origin_not_allowed'});
 const body=req.body;
 if(!body||typeof body!=='object'||Array.isArray(body)||JSON.stringify(body).length>45000)
  return res.status(400).json({error:'invalid_json'});
 const action=body.action;
 const fields={action};
 if(action==='issue'){
  const session=getSession(req);
  if(!session)return res.status(401).json({error:'authentication_required'});
  fields.session=session;
  fields.name=body.name;
 }else if(['options','status','verify','cancel'].includes(action)){
  if(typeof body.ticket!=='string'||!/^[0-9a-f]{64}$/.test(body.ticket))
   return res.status(403).json({error:'link_required'});
  fields.ticket=body.ticket;
  if(action==='verify'||action==='cancel')fields.challengeId=body.challengeId;
  if(action==='verify')fields.response=body.response;
 }else return res.status(400).json({error:'unknown_action'});
 try{
  const response=await fetch(BACKEND,{method:'POST',
    headers:{'Content-Type':'application/json','Accept':'application/json'},
    body:JSON.stringify(fields),signal:AbortSignal.timeout(20000)});
  const data=await response.json().catch(()=>({error:'invalid_enrollment_server_response'}));
  return res.status(response.status).json(data);
 }catch{return res.status(503).json({error:'profile_registration_server_unavailable'});}
}