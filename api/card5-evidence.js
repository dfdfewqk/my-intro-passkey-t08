// Card 5 cross-profile evidence gateway. Cookie-derived session only; no browser secrets are logged.
import {getSession} from './auth.js';
const ORIGIN='https://my-intro-t08.vercel.app';
const UPSTREAM='https://bcwzllejypavwgsfqfbm.supabase.co/functions/v1/t08-evidence';
export default async function handler(req,res){
 res.setHeader('Cache-Control','private, no-store, max-age=0');
 res.setHeader('X-Content-Type-Options','nosniff');
 if(req.method!=='POST'){
  res.setHeader('Allow','POST');
  return res.status(405).json({error:'method_not_allowed'});
 }
 if(req.headers?.origin!==ORIGIN)return res.status(403).json({error:'origin_not_allowed'});
 const session=getSession(req);
 if(!session)return res.status(401).json({error:'authentication_required'});
 const body=req.body;
 if(!body||typeof body!=='object'||Array.isArray(body)||JSON.stringify(body).length>2000)
  return res.status(400).json({error:'invalid_evidence_request'});
 if(!['status','save'].includes(body.action))return res.status(400).json({error:'unknown_action'});
 const forwarded={action:body.action,session};
 if(body.action==='save')forwarded.proof=body.proof;
 try{
  const upstream=await fetch(UPSTREAM,{
   method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},
   body:JSON.stringify(forwarded),signal:AbortSignal.timeout(12000)
  });
  const data=await upstream.json().catch(()=>({error:'invalid_backend_response'}));
  return res.status(upstream.status).json(data);
 }catch{return res.status(503).json({error:'evidence_server_unavailable'});}
}
