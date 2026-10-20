/**
 * Task 08, card 1: deny by default.
 *
 * Future cards will add a server-side, verified WebAuthn session check BEFORE
 * reading process.env.T08_PRIVATE_NOTES_JSON. Do not authorize by cookie presence,
 * query string flags, or client-side state.
 */
export default function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  // No authenticated session verifier is installed in card 1.
  // The safe state is to reject EVERY unauthenticated / forged-cookie request.
  return res.status(401).json({ error: 'authentication_required' });
}