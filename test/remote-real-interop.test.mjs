import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, randomUUID, verify } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createRemoteCompanion } from '../src/remote-companion.mjs';
import { createRemoteAuthority } from '../src/remote-authority.mjs';
import { NativeCrypto } from '../src/remote-crypto.mjs';
import { createRemoteTransport } from '../public/remote-transport.mjs';
import { permission } from './fixtures.mjs';

const executable = process.env.NOTIFY_NATIVE_INTEROP_BIN;
const origin = 'https://notify.example';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate, description) {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, `Timed out: ${description}`);
    await delay(5);
  }
}
function verifyAuthorization(publicKey, challenge, signature) {
  const bytes = Buffer.from(publicKey);
  const key = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
    x: bytes.subarray(1, 33).toString('base64url'), y: bytes.subarray(33).toString('base64url') } });
  const signed = Buffer.from(signature, 'base64url');
  assert.equal(verify('sha256', Buffer.from(`Notify remote authorization v1\0${challenge}`), key, signed), true);
  assert.equal(verify('sha256', Buffer.from(challenge), key, signed), false, 'Authorization includes its domain');
}

// Opt in with the release notify-channel path; never create/load/delete a Keychain identity.
test('hardware native pipe ↔ phone WASM: sustained renewal, delayed chat ACK and no replay',
  { skip: !executable, timeout: 90000 }, async t => {
    assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, '1');
    const directory = join(process.cwd(), '.test-data', `remote-real-interop-${randomUUID()}`);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const native = new NativeCrypto(executable, ['--synthetic']);
    let helper, transport, authority, identity, socket, relay, heartbeat, queue = Promise.resolve();
    const errors = [], events = [], statuses = [], wire = [], plaintext = [], signatures = [];
    t.after(async () => {
      clearInterval(heartbeat);
      transport?.close();
      await helper?.close();
      relay?.close();
      await queue;
      authority?.close();
      await native.close();
      identity?.fill(0);
      await rm(directory, { recursive: true, force: true });
    });

    const { default: init, Peer } = await import('../public/remote-crypto/channel.js');
    await init({ module_or_path: await readFile(new URL('../public/remote-crypto/channel_bg.wasm', import.meta.url)) });
    const seed = new Peer('phone');
    const phoneKey = seed.identity_key();
    identity = seed.export_identity();
    seed.free();
    const macKey = Buffer.from(await native.call('identity'));
    const macID = randomUUID(), deviceID = randomUUID();
    const accountController = new AbortController();
    const accountRequest = { headers: { origin } };
    // The authority is real; this in-memory account proof is not a passkey or browser cookie test.
    authority = createRemoteAuthority({ origin, accounts: {
      authorize(request) {
        assert.equal(request, accountRequest);
        return { issuer: origin, subject: 'fixture-owner', signal: accountController.signal };
      }
    } });
    const bootstrap = authority.beginMac({ macID, publicKey: macKey.toString('base64url') });
    const bootstrapSignature = Buffer.from(await native.call('sign', {
      bytes: [...Buffer.from(bootstrap.challenge)]
    })).toString('base64url');
    verifyAuthorization(macKey, bootstrap.challenge, bootstrapSignature);
    const host = authority.registerMac({ id: bootstrap.id, signature: bootstrapSignature });
    const pending = await authority.requestPair(accountRequest, {
      setupID: host.setupID, deviceID, publicKey: Buffer.from(phoneKey).toString('base64url'), name: 'Fixture phone'
    });
    assert.ok(Number.isSafeInteger(pending.expiresAt),
      `Real authority returned fractional pending expiresAt (${pending.expiresAt}); companion requires integer Unix milliseconds`);
    // Disk contains public metadata and an inert fixture ID, never an actual service credential or private key.
    const fixtureCredential = 'f'.repeat(43);
    await writeFile(join(directory, 'identity.json'), JSON.stringify({
      version: 1, origin, macID, publicKey: macKey.toString('base64url'), owner: null,
      devices: [], credential: fixtureCredential, setupID: 'fixture-setup'
    }), { mode: 0o600 });

    const challenges = new Map(), leases = new Map(), renewals = { mac: 0, phone: 0 };
    let phoneGrant, factoryCalls = 0, leaseCloses = 0, socketCount = 0;
    async function beginGrant(input, credential) {
      const flow = await authority.beginGrant(accountRequest, {
        ...input, ...(input.role === 'mac' ? { credential } : {})
      });
      challenges.set(flow.id, { ...flow, role: input.role });
      return flow;
    }
    function finishGrant(input) {
      const flow = challenges.get(input.id);
      assert.ok(flow, 'Only issued challenges are signed');
      challenges.delete(input.id);
      verifyAuthorization(flow.role === 'mac' ? macKey : phoneKey, flow.challenge, input.signature);
      signatures.push(flow.role);
      const result = authority.finishGrant(input, accountRequest);
      leases.set(flow.role, result);
      return result;
    }
    async function renewGrant(role, input, credential) {
      const previous = leases.get(role);
      assert.equal(input.id, previous.renewal.id);
      verifyAuthorization(role === 'mac' ? macKey : phoneKey, previous.renewal.challenge, input.signature);
      const result = await authority.renewGrant(role === 'phone' ? accountRequest : { headers: {} }, input, credential);
      leases.set(role, result);
      renewals[role]++;
      return result;
    }
    const fetchRequest = async (url, options) => {
      const path = new URL(url).pathname, input = JSON.parse(options.body);
      let credential;
      if (options.headers.Authorization) {
        assert.equal(options.headers.Authorization, `Bearer ${fixtureCredential}`);
        credential = host.credential;
      }
      let result;
      if (path.endsWith('/mac/status')) result = authority.macStatus(credential);
      else if (path.endsWith('/grant/begin')) result = await beginGrant(input, credential);
      else if (path.endsWith('/grant/finish')) result = finishGrant(input);
      else if (path.endsWith('/grant/renew')) result = await renewGrant('mac', input, credential);
      else if (path.endsWith('/mac/decision')) result = authority.decidePair(credential, input);
      else assert.fail(`Unexpected companion endpoint: ${path}`);
      return Response.json(result);
    };
    const enqueue = action => {
      queue = queue.then(action).catch(error => { errors.push(error); socket?.close(); });
    };
    class Socket {
      readyState = 1;
      bufferedAmount = 0;
      constructor(url, protocol) {
        assert.equal(url, 'wss://notify.example/v1/relay');
        assert.equal(protocol, 'notify-relay-v1');
        this.controller = new AbortController();
        const proof = authority.authorizeRelay({ headers: {
          origin, cookie: `__Host-notify-relay=${phoneGrant.credential}`
        } }, { signal: this.controller.signal });
        assert.equal(proof.role, 'phone');
        assert.equal(proof.deviceID, deviceID);
        socket = this;
        socketCount++;
        proof.signal.addEventListener('abort', () => this.close(), { once: true });
        queueMicrotask(() => this.onopen?.());
      }
      send(bytes) {
        assert.equal(this.readyState, 1);
        const frame = Buffer.from(bytes);
        wire.push({ direction: 'phone', bytes: frame });
        enqueue(() => relay.receive(frame));
      }
      close() {
        if (this.readyState === 3) return;
        this.readyState = 3;
        this.controller.abort();
        relay?.close();
        this.onclose?.();
      }
      message(data) { this.onmessage?.({ data }); }
    }
    const connectRelay = async ({ receive, credential, signal, onOpen }) => {
      const proof = authority.authorizeRelay({ headers: { authorization: `Bearer ${credential}` } }, { signal });
      assert.equal(proof.role, 'mac');
      assert.equal(proof.macID, macID);
      let finish;
      const closed = new Promise(resolve => { finish = resolve; });
      relay = {
        receive, closed, signal, close: () => { finish(); socket?.close(); },
        renew(expiresAt, deadline) {
          assert.ok(expiresAt <= proof.expiresAt && expiresAt > Date.now(),
            'Local expiry conservatively subtracts request latency');
          assert.ok(deadline > performance.now() && deadline <= performance.now() + 30000);
        },
        async send(bytes) {
          const frame = Buffer.from(bytes);
          wire.push({ direction: 'native', bytes: frame });
          assert.equal(socket.readyState, 1);
          socket.message(Uint8Array.from(frame).buffer);
        }
      };
      signal.addEventListener('abort', () => relay.close(), { once: true });
      proof.signal.addEventListener('abort', () => relay.close(), { once: true });
      onOpen?.(relay);
      return relay;
    };
    helper = await createRemoteCompanion({
      directory, origin, emit: event => events.push(event), fetchRequest, connectRelay,
      cryptoProcess(_path, args) {
        assert.equal(args[0], 'load-identity');
        assert.equal(args[1], macID);
        assert.deepEqual(JSON.parse(args[2]), [...macKey]);
        factoryCalls++;
        // Share one ephemeral signer/group pipe; lease close must not destroy the shared identity.
        return {
          async call(op, args = {}) {
            const result = await native.call(op, args);
            if (op === 'send') plaintext.push(JSON.parse(Buffer.from(args.bytes).toString()));
            if (op === 'receive') assert.equal(Buffer.from(result.sender).toString(), 'phone');
            return result;
          },
          async close() { leaseCloses++; }
        };
      }
    });
    await until(() => relay, 'native relay grant').catch(error => {
      throw new Error(`${error.message}; companion: ${events.findLast(event => event.type === 'status')?.status.message}`);
    });
    const ticket = `private-fixture-ticket-${randomUUID()}`;
    const snapshot = permission(ticket);
    await helper.command({ type: 'snapshot', total: 1, requests: [snapshot] });
    transport = createRemoteTransport({
      origin, macID, deviceID, pinnedMacKey: Uint8Array.from(macKey), autoReconnect: false,
      restorePeer: async () => Peer.restore_identity('phone', identity, phoneKey),
      WebSocketImpl: Socket, onStatus: status => statuses.push(status),
      post: async (path, input) => {
        if (path.endsWith('/grant/begin')) return beginGrant(input);
        if (path.endsWith('/grant/renew')) return renewGrant('phone', input);
        assert.equal(path, '/v1/remote/grant/finish');
        phoneGrant = finishGrant(input);
        return phoneGrant;
      }
    });
    await transport.connect();
    assert.equal(statuses.at(-1).state, 'connecting', 'Socket creation is not handshake completion');
    socket.message('{"type":"ready","version":1}');
    await until(() => events.some(event => event.type === 'pairing'), 'real encrypted hello');
    await queue;
    assert.deepEqual(errors, []);
    assert.equal(phoneGrant.approved, false);
    assert.deepEqual(plaintext.map(value => value.type), ['pending']);
    assert.equal(wire.length, 4, 'Key package, welcome, encrypted hello, encrypted pending only');
    assert.equal(JSON.parse(wire[0].bytes).type, 'key_package');
    assert.equal(JSON.parse(wire[1].bytes).type, 'welcome');
    const pairing = events.find(event => event.type === 'pairing');
    assert.equal(pairing.verificationData, Buffer.from(phoneKey).toString('base64'));
    await assert.rejects(transport.api('state'), /approved|connected/i);
    await assert.rejects(helper.command({
      type: 'pair', id: pending.id, allow: true, verificationData: pairing.verificationData.slice(0, -4)
    }), /complete phone public key/i);
    assert.equal(authority.macStatus(host.credential).devices.length, 0);
    assert.equal(wire.length, 4, 'No private state before full-key local approval');
    await helper.command({ type: 'pair', id: pending.id, allow: true, verificationData: pairing.verificationData });
    await until(() => statuses.at(-1).state === 'connected', 'encrypted native ready');
    const connectedAt = Date.now();
    assert.equal(authority.macStatus(host.credential).devices[0].deviceID, deviceID);
    const state = await transport.api('state');
    assert.equal(state.connected, true);
    assert.deepEqual(state.requests, [snapshot]);
    const reply = { sessionID: snapshot.sessionID, requestID: snapshot.request.id, ticket, decision: 'deny', answers: {} };
    let settled = false;
    const response = transport.api('reply', reply).finally(() => { settled = true; });
    await until(() => events.some(event => event.type === 'reply'), 'synthetic runtime receives reply');
    const dispatched = events.find(event => event.type === 'reply');
    assert.deepEqual(dispatched, { type: 'reply', id: dispatched.id, ...reply });
    const repliesBeforeACK = plaintext.length;
    await helper.command({ type: 'result', id: randomUUID(), ok: true });
    await delay(30);
    assert.equal(settled, false, 'An unrelated runtime ACK cannot resolve this action');
    assert.equal(plaintext.length, repliesBeforeACK, 'No encrypted success before exact runtime ACK');
    await helper.command({ type: 'result', id: dispatched.id, ok: true });
    assert.deepEqual(await response, { ok: true });

    const workspace = { type: 'workspace', sessions: [{
      id: 'fixture-session', ticket: 'fixture-chat-ticket', name: 'Fixture', project: 'notify', agent: 'copilot',
      color: '#123456', state: 'working', connected: true,
      capabilities: { steering: true, subagentChat: false, subagentStop: false },
      runningCount: 0, idleCount: 0
    }], total: 1, truncated: false };
    await helper.command(workspace);
    heartbeat = setInterval(() => {
      void helper.command({ type: 'snapshot', total: 1, requests: [snapshot] })
        .then(() => helper.command(workspace)).catch(error => errors.push(error));
    }, 3000);
    while (Date.now() - connectedAt < 55000) {
      await delay(Math.min(3000, 55000 - (Date.now() - connectedAt)));
      assert.equal(statuses.at(-1).state, 'connected', 'Authorization renewal must preserve the channel');
      assert.equal((await transport.api('state')).connected, true);
    }
    const chat = { id: randomUUID(), sessionID: 'fixture-session', ticket: 'fixture-chat-ticket',
      action: 'queue', text: 'Synthetic delayed-ack chat; never sent to a real runtime.' };
    let chatSettled = false;
    const chatResponse = transport.api('control', chat).then(
      value => { chatSettled = true; return { value }; },
      error => { chatSettled = true; return { error }; }
    );
    await until(() => events.some(event => event.type === 'control'), 'synthetic chat dispatch');
    const sentChat = events.findLast(event => event.type === 'control');
    await helper.command({ type: 'control_result', id: randomUUID(), ok: true,
      commandID: 'wrong-ack', status: 'queued', detail: 'Wrong acknowledgment' });
    await delay(14000);
    assert.equal(chatSettled, false, 'The phone must wait beyond12s for the exact native acknowledgment');
    await helper.command({ type: 'control_result', id: sentChat.id, ok: true,
      commandID: 'fixture-chat-ack', status: 'queued', detail: 'Synthetic runtime acknowledgment' });
    const chatResult = await chatResponse;
    assert.equal(chatResult.error, undefined);
    assert.equal(chatResult.value.commandID, 'fixture-chat-ack');
    assert.equal(events.filter(event => event.type === 'control').length, 1);
    assert.equal(socketCount, 1, 'Renewal must retain the original WebSocket');
    assert.equal(plaintext.filter(value => value.type === 'ready').length, 1, 'Renewal must retain the original MLS epoch');
    assert.ok(renewals.mac >= 5 && renewals.phone >= 5, 'Both endpoints must renew repeatedly');
    clearInterval(heartbeat);

    workspace.sessions[0].capabilities = { steering: false, subagentChat: false, subagentStop: false, dangerousAutoYes: true };
    const offEpoch = '00000000-0000-8000-8000-000000000001';
    workspace.sessions[0].dangerousAutoYes = { ticket: 'policy-1', offTicket: offEpoch, revision: 1, enabled: false, normalEnabled: false };
    await helper.command(workspace);
    const policyView = await transport.api('workspace', { sessionID: 'fixture-session' });
    assert.equal(policyView.dangerousAutoYesControl, true);
    for (const [enabled, revision] of [[true, 2], [false, 3]]) {
      const command = { id: enabled ? randomUUID() : offEpoch, sessionID: 'fixture-session', ticket: 'fixture-chat-ticket',
        action: 'dangerous_auto_yes', text: '', enabled, policyTicket: `policy-${revision - 1}`, offTicket: offEpoch };
      const response = transport.api('control', command);
      await until(() => events.some(event => event.action === 'dangerous_auto_yes' && event.enabled === enabled), 'encrypted policy dispatch');
      const nativeCommand = events.findLast(event => event.action === 'dangerous_auto_yes');
      assert.equal(nativeCommand.agentID, undefined);
      const policy = { ticket: `policy-${revision}`, offTicket: enabled ? offEpoch : '00000000-0000-8000-8000-000000000002', revision, enabled, normalEnabled: false };
      await helper.command({ type: 'control_result', id: nativeCommand.id, ok: true, commandID: nativeCommand.id,
        status: 'applied', detail: 'Synthetic policy authority only; no real approvals', dangerousAutoYes: policy });
      assert.deepEqual((await response).dangerousAutoYes, policy);
    }

    const next = permission(`private-fixture-ticket-${randomUUID()}`);
    await helper.command({ type: 'snapshot', total: 1, requests: [next] });
    const disconnected = assert.rejects(transport.api('reply', { ...reply, ticket: next.ticket }),
      error => error.uncertain === true && /Nothing was retried/.test(error.message));
    await until(() => events.filter(event => event.type === 'reply').length === 2, 'second runtime dispatch');
    const unacknowledged = events.findLast(event => event.type === 'reply');
    socket.close();
    await disconnected;
    await until(() => relay.signal.aborted && leaseCloses === 1, 'channel teardown');
    await helper.command({ type: 'offline' });
    const framesAfterDisconnect = wire.length;
    await helper.command({ type: 'result', id: unacknowledged.id, ok: true });
    await assert.rejects(transport.api('reply', reply), /approved|connected/i);
    await delay(1100);
    assert.equal(socketCount, 1);
    assert.equal(events.filter(event => event.type === 'reply').length, 2, 'Disconnect never replays a native action');
    assert.equal(wire.length, framesAfterDisconnect, 'Late ACK cannot send on the disconnected channel');
    for (const frame of wire) {
      assert.equal(frame.bytes.includes(Buffer.from(ticket)), false);
      assert.equal(frame.bytes.includes(Buffer.from(next.ticket)), false);
      assert.equal(frame.bytes.includes(Buffer.from(snapshot.request.title)), false);
    }
    assert.deepEqual(signatures, ['mac', 'phone']);
    assert.equal(factoryCalls, 2, 'Signer and MLS channel share the actual native identity');
    assert.deepEqual(errors, []);
    const saved = JSON.parse(await readFile(join(directory, 'identity.json'), 'utf8'));
    assert.deepEqual(saved, {
      version: 1, origin, macID, publicKey: macKey.toString('base64url'),
      owner: { issuer: origin, subject: 'fixture-owner' },
      devices: [{ id: deviceID, name: 'Fixture phone', publicKey: Buffer.from(phoneKey).toString('base64url') }],
      credential: fixtureCredential, setupID: 'fixture-setup'
    });
    // The synthetic CLI cannot reset an MLS group or export its hardware identity; reconnect needs persistent mode.
    await assert.rejects(native.call('create', { id: randomUUID() }), /Invalid fixture group/);
    t.diagnostic('Real Secure Enclave ↔ WASM MLS stayed connected beyond60s, acknowledged chat after14s and carried exact Dangerous Auto-yes On/Off ACKs. Account/HTTP/relay/runtime are fixtures; reconnect is not covered.');
  });
