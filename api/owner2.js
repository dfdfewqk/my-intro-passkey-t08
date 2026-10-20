// Card 5: owner2 creation requires a recent owner WebAuthn session.
import {getSession} from './auth.js';
const BACKEND='https://bcwzllejypavwgsfqfbm.supabase.co/functions/v1/t08-owner2';
const ORIGIN='https://my-intro-t08.vercel.app';
export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store, private,max-age=0');
 res.setHeader('X-Content-Type-Options','nosniff');
 if(req.method!=='POST')return res.status(405).json({error:'method_not_allowed'});
 if(req.headers?.origin!==ORIGIN)return res.status(403).json({error:'origin_not_allowed'});
 const session=getSession(req);
 if(!session)return res.status(401).json({error:'authentication_required'});
 const body=req.body;
 if(!body||typeof body!=='object'||Array.isArray(body)||JSON.stringify(body).length>45000)
  return res.status(400).json({error:'invalid_request'});
 if(!['status','options','verify','cancel'].includes(body.action))
  return res.status(400).json({error:'unknown_action'});
 const fields={action:body.action,session};
 if(body.action==='options')fields.name=body.name;
 if(body.action==='cancel'||body.action==='verify')fields.challengeId=body.challengeId;
 if(body.action==='verify')fields.response=body.response;
 try{
  const r=await fetch(BACKEND,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(fields),signal:AbortSignal.timeout(18000)});
  return res.status(r.status).json(await r.json().catch(()=>({error:'invalid_backend_response'})));
 }catch{return res.status(503).json({error:'owner2_service_unavailable'});}
}