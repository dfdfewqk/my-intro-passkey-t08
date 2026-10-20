// Task 08 Card 2: same-origin gateway; Supabase credentials remain in Edge runtime.
const BACKEND='https://bcwzllejypavwgsfqfbm.supabase.co/functions/v1/t08-register';
export default async function handler(req,res){
  res.setHeader('Cache-Control','private, no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  if(req.method!=='POST'){
    res.setHeader('Allow','POST');
    return res.status(405).json({error:'method_not_allowed'});
  }
  const size=Number(req.headers['content-length']||0);
  if(size>40000)return res.status(413).json({error:'payload_too_large'});
  if(!req.body||typeof req.body!=='object'||Array.isArray(req.body)||JSON.stringify(req.body).length>40000)
    return res.status(400).json({error:'invalid_json'});
  try{
    const r=await fetch(BACKEND,{
      method:'POST',
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      body:JSON.stringify(req.body),
      signal:AbortSignal.timeout(18000)
    });
    const payload=await r.json().catch(()=>({error:'upstream_invalid_response'}));
    return res.status(r.status).json(payload);
  }catch{
    return res.status(502).json({error:'registration_server_unavailable'});
  }
}