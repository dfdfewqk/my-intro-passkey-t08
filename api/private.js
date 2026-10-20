// Card 5: server-validated site account ownership; never trust client account IDs.
import {getSession,edge} from './auth.js';
export default async function handler(req,res){
 res.setHeader('Cache-Control','private, no-store, max-age=0');
 res.setHeader('Pragma','no-cache');
 res.setHeader('X-Content-Type-Options','nosniff');
 if(!['GET','HEAD'].includes(req.method)){
  res.setHeader('Allow','GET, HEAD');return res.status(405).json({error:'method_not_allowed'});
 }
 const session=getSession(req);
 if(!session)return res.status(401).json({error:'authentication_required'});
 const verified=await edge('validate',{session});
 if(verified.status!==200||verified.data.authenticated!==true)
  return res.status(verified.status>=500?503:401)
   .json({error:verified.status>=500?'auth_server_unavailable':'authentication_required'});
 const ownerId=verified.data.ownerId;
 if(![1,2].includes(ownerId))return res.status(403).json({error:'account_not_authorized'});
 // Explicit target account requests may only refer to the signed-in account.
 // Query values owner_id/requestedOwner/owner are intentionally never authority.
 const url=new URL(req.url||'/api/private','https://my-intro-t08.vercel.app');
 const account=url.searchParams.get('account');
 if(account!==null&&account!==String(ownerId))
  return res.status(403).json({error:'other_account_forbidden',ownAccountId:ownerId});
 let notes;
 try{
  const key=ownerId===1?'T08_PRIVATE_NOTES_JSON':'T08_PRIVATE_NOTES_OWNER2_JSON';
  notes=JSON.parse(process.env[key]||'[]');
  if(!Array.isArray(notes)||notes.length<3)throw Error('missing_private_notes');
 }catch{return res.status(503).json({error:'private_notes_not_configured'});}
 if(req.method==='HEAD')return res.status(200).end();
 return res.status(200).json({private:true,accountId:ownerId,
  accountName:ownerId===1?'owner':'owner2',items:notes});
}
