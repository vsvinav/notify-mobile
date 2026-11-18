import test from 'node:test';
import assert from 'node:assert/strict';
import { createFcmSender } from '../src/fcm.mjs';

test('FCM sends only bounded generic data to the pinned project endpoint without automatic retries', async () => {
  const calls = [];
  const sender = createFcmSender({ projectId: 'notify-fixture',
    credentials: { client_email: 'notify@notify-fixture.iam.gserviceaccount.com', private_key: 'fixture' },
    authorize: async () => 'synthetic-access-token',
    request: async (url, options, body) => { calls.push({ url, options, body: JSON.parse(body) }); }
  });
  const send = await sender.prepare();
  await send('synthetic-routing-token', { type: 'attention', version: '1',
    eventID: '12345678-1234-1234-1234-123456789012', issuedAt: '1800000000000' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://fcm.googleapis.com/v1/projects/notify-fixture/messages:send');
  assert.equal(calls[0].options.rejectUnauthorized, true);
  assert.deepEqual(calls[0].body, { message: {
    token: 'synthetic-routing-token', data: { type: 'attention', version: '1',
      eventID: '12345678-1234-1234-1234-123456789012', issuedAt: '1800000000000' },
    android: { priority: 'high', ttl: '120s', collapse_key: 'notify-attention-v1' }
  } });
  await assert.rejects(send('synthetic-routing-token', { type: 'attention', request: 'private content' }));
  assert.equal(calls.length, 1);
});

test('provider failures expose no tokens, credentials, or response content and are not replayed', async () => {
  let calls = 0;
  const sender = createFcmSender({ projectId: 'notify-fixture', credentials: {},
    authorize: async () => 'secret',
    request: async () => { calls++; throw new Error('private-token and provider content'); } });
  const send = await sender.prepare();
  await assert.rejects(send('synthetic-routing-token', { type: 'attention', version: '1',
    eventID: '12345678-1234-1234-1234-123456789012', issuedAt: '1800000000000' }),
  error => error.message === 'Notification delivery unavailable.');
  assert.equal(calls, 1);
});
