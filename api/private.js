// Task 08 Card 3: load server-only private notes AFTER checking a live database session.
import {getSession,edge} from './auth.js';
export default async function handler(req,res){
 res.setHeader('Cache-Control','private, no-store, max-age=0');
 res.setHeader('Pragma','no-cache');
 res.setHeader('X-Content-Type-Options','nosniff');
 if(!['GET','HEAD'].includes(req.method)){
  res.setHeader('Allow','GET, HEAD');return res.status(405).json({error:'method_not_allowed'});
 }
 const token=getSession(req);
 if(!token)return res.status(401).json({error:'authentication_required'});
 const check=await edge('validate',{session:token});
 if(check.status!==200||check.data.authenticated!==true)
  return res.status(check.status>=500?503:401).json({error:check.status>=500?'auth_server_unavailable':'authentication_required'});
 let notes;
 try{
  notes=JSON.parse(process.env.T08_PRIVATE_NOTES_JSON||'[]');
  if(!Array.isArray(notes)||notes.length<3)throw Error('missing_private_notes');
 }catch{return res.status(503).json({error:'private_notes_not_configured'});}
 if(req.method==='HEAD')return res.status(200).end();
 return res.status(200).json({private:true,items:notes});
}