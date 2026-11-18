import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { createIngressPolicy } from '../src/managed-ingress.mjs';

const hostname = 'notify-ingress-test.onrender.com';
const publicOrigin = `https://${hostname}`;

test('only explicit Render Free ingress with matching platform configuration permits HTTP', t => {
  const environment = process.env;
  t.after(() => { process.env = environment; });
  const server = http.createServer();
  for (const managedIngress of [undefined, null, true, 'render', 'trust-proxy'])
    assert.throws(() => createIngressPolicy({ server, publicOrigin, managedIngress }));
  for (const values of [
    {}, { RENDER: 'true' }, { RENDER: 'false', RENDER_EXTERNAL_HOSTNAME: hostname },
    { RENDER: 'true', RENDER_EXTERNAL_HOSTNAME: 'evil.onrender.com' },
    { RENDER: 'true', RENDER_EXTERNAL_HOSTNAME: 'notify.example.com' }
  ]) {
    process.env = { ...environment, RENDER: undefined, RENDER_EXTERNAL_HOSTNAME: undefined, ...values };
    assert.throws(() => createIngressPolicy({ server, publicOrigin, managedIngress: 'render-free' }), /Render Free/);
  }
  process.env = { ...environment, RENDER: 'true', RENDER_EXTERNAL_HOSTNAME: hostname };
  for (const value of [`http://${hostname}`, `https://${hostname}:8443`, 'https://other.onrender.com'])
    assert.throws(() => createIngressPolicy({ server, publicOrigin: value, managedIngress: 'render-free' }), /Render Free/);
  assert.throws(() => createIngressPolicy({
    server: https.createServer(), publicOrigin, managedIngress: 'render-free'
  }), /Render Free/);
  assert.doesNotThrow(() => createIngressPolicy({ server, publicOrigin, managedIngress: 'render-free' }));
});

test('forwarding claims do not bypass direct TLS and duplicate Host never authorizes ingress', t => {
  const environment = process.env;
  process.env = { ...environment, RENDER: 'true', RENDER_EXTERNAL_HOSTNAME: hostname };
  t.after(() => { process.env = environment; });
  const direct = createIngressPolicy({ server: https.createServer(), publicOrigin });
  const managed = createIngressPolicy({ server: http.createServer(), publicOrigin, managedIngress: 'render-free' });
  const request = { headers: { host: hostname, 'x-forwarded-proto': 'https', 'x-forwarded-host': hostname },
    rawHeaders: ['Host', hostname, 'X-Forwarded-Proto', 'https'], socket: { encrypted: false } };
  assert.equal(direct.accepts(request), false);
  assert.equal(managed.accepts(request), true);
  request.socket.encrypted = true;
  assert.equal(direct.accepts(request), true);
  request.rawHeaders.push('hOsT', hostname);
  assert.equal(direct.accepts(request), false);
  assert.equal(managed.accepts(request), false);
});
