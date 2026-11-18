import http from 'node:http';
import https from 'node:https';

// Render Free's isolated backend and edge TLS/redirect guarantees are the trust
// boundary, not forwarding headers. Never use this mode on a public HTTP listener.
export function createIngressPolicy({ server, publicOrigin, managedIngress }) {
  const endpoint = new URL(publicOrigin);
  const managed = managedIngress === 'render-free';
  if (managedIngress !== undefined && !managed) throw new Error('Unsupported managed ingress.');
  if (managed) {
    const hostname = process.env.RENDER_EXTERNAL_HOSTNAME;
    if (!(server instanceof http.Server) || server instanceof https.Server ||
      process.env.RENDER !== 'true' || typeof hostname !== 'string' ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.onrender\.com$/.test(hostname) ||
      endpoint.origin !== `https://${hostname}`)
      throw new Error('Render Free ingress requires HTTP behind Render and its exact HTTPS service origin.');
  } else if (!(server instanceof https.Server)) {
    throw new Error('A dedicated HTTPS server is required unless Render Free ingress is explicitly configured.');
  }

  function accepts(req) {
    if (req.headers.host !== endpoint.host ||
      req.rawHeaders.filter((_, index) => index % 2 === 0 && req.rawHeaders[index].toLowerCase() === 'host').length !== 1)
      return false;
    if (!managed) return req.socket.encrypted === true;
    // Reject contradictory/ambiguous claims; absent headers never enable HTTP.
    return req.headers.forwarded === undefined &&
      (req.headers['x-forwarded-proto'] === undefined || req.headers['x-forwarded-proto'] === 'https') &&
      (req.headers['x-forwarded-host'] === undefined || req.headers['x-forwarded-host'] === endpoint.host) &&
      (req.headers['x-forwarded-port'] === undefined || req.headers['x-forwarded-port'] === '443');
  }

  return Object.freeze({
    accepts,
    health(req, res, { available = true } = {}) {
      if (!managed || req.url !== '/healthz') return false;
      const allowed = accepts(req) && (req.headers.origin === undefined || req.headers.origin === endpoint.origin);
      const status = !allowed ? 403 : req.method === 'GET' ? (available ? 200 : 503) : 405;
      res.writeHead(status, { 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8',
        'X-Content-Type-Options': 'nosniff' });
      res.end(JSON.stringify(status === 200 ? { status: 'ok' } : { error: 'Health request rejected.' }));
      return true;
    }
  });
}
