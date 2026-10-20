export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') return res.status(405).json({error:'method_not_allowed'});
  let count=0;
  try {
    const records=JSON.parse(process.env.T08_PRIVATE_NOTES_JSON || '[]');
    if (Array.isArray(records)) count=records.length;
  } catch (_) { /* Never return the records themselves. */ }
  return res.status(200).json({
    publicPage: true,
    privateApiRequiresAuthentication: true,
    privateItemCount: count,
    passkeyLoginImplemented: false
  });
}