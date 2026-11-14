import https from 'node:https';
import { lookup } from 'node:dns';
import { isIP } from 'node:net';
import * as webPush from 'web-push';
import { privateIPv4 } from './network.mjs';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';

export const genericPayload = JSON.stringify({
  title: 'Notify',
  body: 'Notify needs you. Open the app to review on your local network.',
  tag: 'notify-attention', url: '/'
});

export function validPushEndpoint(endpoint) {
  if (typeof endpoint !== 'string' || endpoint.length > 4096) return false;
  try {
    const url = new URL(endpoint);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port && !url.search && !url.hash &&
      url.pathname.length > 1 && (
        url.hostname === 'web.push.apple.com' || /^[a-z0-9-]+\.push\.apple\.com$/.test(url.hostname) ||
        url.hostname === 'fcm.googleapis.com' ||
        url.hostname === 'updates.push.services.mozilla.com' ||
        /^[a-z0-9-]+\.push\.services\.mozilla\.com$/.test(url.hostname)
      );
  } catch { return false; }
}

export function validSubscription(value) {
  return value && validPushEndpoint(value.endpoint) && value.keys &&
    typeof value.keys.p256dh === 'string' && /^[A-Za-z0-9_-]{87}=?$/.test(value.keys.p256dh) &&
    typeof value.keys.auth === 'string' && /^[A-Za-z0-9_-]{22}=?=?$/.test(value.keys.auth);
}

export function publicPushAddress(address) {
  if (isIP(address) === 4) {
    const [first, second, third] = address.split('.').map(Number);
    return !privateIPv4(address) && first !== 0 && first !== 127 && first < 224 &&
      !(first === 169 && second === 254) &&
      !(first === 100 && second >= 64 && second <= 127) &&
      !(first === 192 && ((second === 0 && [0, 2].includes(third)) || (second === 88 && third === 99))) &&
      !(first === 198 && (second === 18 || second === 19 || (second === 51 && third === 100))) &&
      !(first === 203 && second === 0 && third === 113);
  }
  // IPv4-only push DNS resolution avoids private/mapped IPv6 destinations.
  return false;
}

export function pushSender(vapid) {
  const agent = new https.Agent({
    rejectUnauthorized: true, keepAlive: false,
    lookup: (hostname, options, done) => {
      lookup(hostname, { family: 4, all: true }, (error, addresses) => {
        if (error) return done(error);
        if (!addresses.length || addresses.some(item => !publicPushAddress(item.address))) {
          return done(new Error('Push provider resolved to a non-public address.'));
        }
        if (options?.all) return done(null, addresses);
        done(null, addresses[0].address, 4);
      });
    }
  });
  return async (subscription, payload) => {
    if (!validSubscription(subscription)) throw new Error('Unrecognized push provider or invalid subscription.');
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
    // web-push uses https.request, which does not follow redirects.
    await webPush.sendNotification(subscription, payload, {
      vapidDetails: { subject: 'https://notify.local', publicKey: vapid.publicKey, privateKey: vapid.privateKey },
      TTL: 300, urgency: 'high', timeout: 10_000, agent
    });
  };
}

export const generateVAPIDKeys = () => webPush.generateVAPIDKeys();
