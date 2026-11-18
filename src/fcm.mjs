import https from 'node:https';
import { JWT } from 'google-auth-library';

const unavailable = () => new Error('Notification delivery unavailable.');
function request(url, options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, options, res => {
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 8192) res.destroy(unavailable());
      });
      res.on('error', () => reject(unavailable()));
      res.on('end', () => res.statusCode === 200 ? resolve() : reject(unavailable()));
    });
    req.on('error', () => reject(unavailable()));
    req.end(body);
  });
}

export function createFcmSender({ projectId, credentials, authorize, request: sendRequest = request }) {
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) throw unavailable();
  const auth = authorize ? null : new JWT({ email: credentials.client_email, key: credentials.private_key,
    scopes: ['https://www.googleapis.com/auth/firebase.messaging'], universeDomain: 'googleapis.com',
    transporterOptions: { timeout: 5000, retry: false, maxRedirects: 0 } });
  const endpoint = `https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`;
  return { async prepare() {
    let token;
    try { token = authorize ? await authorize() : (await auth.getAccessToken()).token; }
    catch { throw unavailable(); }
    if (typeof token !== 'string' || !token || /[\r\n]/.test(token)) throw unavailable();
    // Resolve Google auth first; the authority rechecks its fence and device immediately
    // before invoking this sender. Never retry a delivery after that authorization point.
    return async (routingToken, data) => {
      if (typeof routingToken !== 'string' || !/^[A-Za-z0-9_:.-]{16,2048}$/.test(routingToken) ||
        !data || Object.keys(data).sort().join(',') !== 'eventID,issuedAt,type,version' ||
        data.type !== 'attention' || data.version !== '1' ||
        !/^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/.test(data.eventID) ||
        !/^\d{13}$/.test(data.issuedAt)) throw unavailable();
      const body = JSON.stringify({ message: { token: routingToken, data,
        android: { priority: 'high', ttl: '120s', collapse_key: 'notify-attention-v1' } } });
      try {
        await sendRequest(endpoint, { method: 'POST', rejectUnauthorized: true,
          signal: AbortSignal.timeout(5000), headers: { 'Content-Type': 'application/json',
            Authorization: `Bearer ${token}` } }, body);
      } catch { throw unavailable(); }
    };
  } };
}
