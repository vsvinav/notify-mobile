import { test, expect } from '@playwright/test';
import { createServer } from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const runtime = resolve('.test-data/remote-ui-runtime');
await mkdir(runtime, { recursive: true });
test.use({ launchOptions: { env: { ...process.env, HOME: runtime, TMPDIR: runtime,
  XDG_CACHE_HOME: runtime, XDG_CONFIG_HOME: runtime } } });
const key = Buffer.from([4, ...Array(64).fill(1)]).toString('base64url');
const phoneKey = Buffer.from([4, ...Array(64).fill(2)]).toString('base64');
let server, origin;
test.beforeAll(async () => {
  server = createServer(async (req, res) => {
    const name = req.url === '/' ? 'remote.html' : req.url === '/actual-transport.mjs' ? 'remote-transport.mjs' : req.url.slice(1);
    if (!/^[a-zA-Z0-9_.-]+$/.test(name)) { res.writeHead(404).end(); return; }
    try {
      const body = await readFile(resolve('public', name));
      res.writeHead(200, { 'Content-Type': name.endsWith('.mjs') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : name.endsWith('.png') ? 'image/png' : 'text/html' }).end(body);
    } catch { res.writeHead(404).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });
const permission = {
  sessionID: 'session-original', sessionName: 'Synthetic session', project: 'test', agent: 'Test agent', ticket: 'ticket-original', fields: [
    { label: 'Command', value: 'test-only command\nsecond line', presentation: 'code' }
  ],
  request: { id: 'request-original', title: 'Synthetic permission', detail: 'The complete original request.',
    kind: 'permission', questions: [], permissionOptions: [{ id: 'offered-only', label: 'Allow offered scope', detail: 'Original scope text' }], supportsFeedback: true }
};
async function setup(page, { mismatch = false, loggedOut = false } = {}) {
  await page.addInitScript(({ permission, mismatch, loggedOut }) => {
    window.__calls = []; window.__requests = [permission]; window.__mismatch = mismatch;
    window.__connected = true; window.__account = { issuer: 'test-issuer', subject: 'test-account' }; window.__loggedOut = loggedOut;
  }, { permission, mismatch, loggedOut });
  await page.route('**/remote-transport.mjs', route => route.fulfill({ contentType: 'text/javascript', body: `
    export * from '/actual-transport.mjs';
    export async function authenticate() { window.__loggedOut = false; return { account: window.__account }; }
    export async function postJSON(path, data) {
      window.__calls.push({path,data});
      if (path.endsWith('/session')) {
        if (window.__loggedOut) throw Object.assign(new Error('Sign in'),{status:401});
        return { account:window.__account,scope:'account',fresh:true };
      }
      if (path.endsWith('/pair')) {
        if (window.__pairError) throw Object.assign(new Error(window.__pairError), { status:401 });
        return { id:'pending', macID:'mac', macPublicKey: window.__mismatch ? '${Buffer.from([4, ...Array(64).fill(9)]).toString('base64url')}' : '${key}', account:window.__account,expiresAt:Date.now()+60000 };
      }
      return {};
    }
    class Peer {
      identity_key() { return new Uint8Array([4,...Array(64).fill(2)]); }
      export_identity() { return new Uint8Array([1,2,3]); }
      static restore_identity() { return new Peer(); }
      free() {}
    }
    export async function loadCrypto() { return { Peer }; }
    export function createRemoteTransport({onStatus}) {
      const api = async (path,data) => {
        window.__calls.push({path,data});
        if (path === 'state') { if (window.__holdState) await new Promise(()=>{}); return { connected:window.__connected,requests:window.__requests,total:window.__requests.length }; }
        if (path === 'workspace') {
          await new Promise(r=>setTimeout(r,100));
          return window.__workspace ? {...window.__workspace,detail:data.sessionID ? window.__workspace.detail : null} : { connected:true,sessions:[],total:0 };
        }
        if (path === 'reply' && window.__holdReply) await new Promise((resolve,reject)=>{window.__rejectReply=()=>reject(new Error('Delivery uncertain; no reply was retried.'));});
        return { ok:true };
      };
      window.__approve = () => onStatus({state:'connected',message:'Connected'});
      window.__disconnect = () => onStatus({state:'disconnected',message:'Delivery uncertain; no reply was retried.'});
      return { api, connect:async()=>onStatus({state:'pending',message:'Waiting for approval'}), close() {} };
    }` }));
  await page.goto(`${origin}/#setup=setup&mac=mac&key=${key}`);
}
async function pair(page) {
  await page.getByLabel('Phone name').fill('Synthetic phone');
  await page.getByRole('button', { name: 'Pair with this Mac', exact: true }).click();
  await expect(page.getByText(phoneKey, { exact: true })).toBeVisible();
}

test('account-only sign-in never creates a channel identity without explicit Pair', async ({ page }) => {
  await setup(page, {loggedOut:true});
  await page.getByRole('button',{name:'Create account with a passkey',exact:true}).click();
  await expect(page.getByRole('alert')).toContainText('Enter an account name');
  await page.getByRole('button',{name:'Sign in with a passkey',exact:true}).click();
  await expect(page.getByLabel('Phone name')).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('notify-remote-relationships-v1'))).toBe(null);
  expect(await page.evaluate(() => __calls.some(call=>call.path.endsWith('/pair')))).toBe(false);
  expect(await page.evaluate(() => typeof __approve)).toBe('undefined');
});

test('failed enrollment survives reload and recovers only through explicit forget and fresh pairing', async ({ page }) => {
  await setup(page);
  await page.evaluate(() => { window.__pairError = 'Mac enrollment unavailable.'; });
  await page.getByLabel('Phone name').fill('Synthetic phone');
  await page.getByRole('button', { name: 'Pair with this Mac', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('Mac enrollment unavailable.');
  expect(await page.evaluate(() => typeof __approve)).toBe('undefined');
  const original = await page.evaluate(() => JSON.parse(localStorage.getItem('notify-remote-relationships-v1')));
  await page.goto(`${origin}/#setup=fresh-setup&mac=mac&key=${key}`);
  await page.reload();
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('notify-remote-relationships-v1')))).toEqual(original);
  expect(await page.evaluate(() => __calls.some(call => call.path.endsWith('/pair')))).toBe(false);
  await page.getByRole('button', { name: 'Forget this phone’s pairing', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Forget pairing', exact: true }).click();
  await pair(page);
  expect(await page.evaluate(() => __calls.filter(call => call.path.endsWith('/pair')).map(call => call.data.setupID))).toEqual(['fresh-setup']);
  expect(await page.evaluate(() => __calls.some(call => call.path === 'state'))).toBe(false);
  await page.evaluate(() => __approve());
  await expect(page.getByRole('heading', { name: 'Synthetic permission' })).toBeVisible();
});

test('pairing pins full QR key, strips fragment and waits for Mac approval', async ({ page }) => {
  await setup(page);
  expect(new URL(page.url()).hash).toBe('');
  await pair(page);
  await expect(page.getByRole('heading', { name: 'Compare on your Mac' })).toBeVisible();
  await mkdir('.test-data/remote-ui-render', { recursive: true });
  await page.screenshot({ path: '.test-data/remote-ui-render/pairing-light-390.png' });
  expect(await page.evaluate(() => __calls.some(call => call.path === 'state'))).toBe(false);
  await page.evaluate(() => __approve());
  await expect(page.getByRole('heading', { name: 'Synthetic permission' })).toBeVisible();
  await mkdir('.test-data/remote-ui-render', { recursive: true });
  await page.screenshot({ path: '.test-data/remote-ui-render/inbox-light-390.png' });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.setViewportSize({ width: 320, height: 740 });
  await page.screenshot({ path: '.test-data/remote-ui-render/inbox-dark-320.png' });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('offered permission preserves original identifiers and requires confirmation', async ({ page }) => {
  await setup(page); await pair(page); await page.evaluate(() => __approve());
  await page.getByRole('button', { name: 'Allow offered scope', exact: false }).click();
  expect(await page.evaluate(() => __calls.filter(call => call.path === 'reply'))).toHaveLength(0);
  await expect(page.getByRole('dialog')).toContainText('ticket-original');
  await page.getByRole('button', { name: 'Confirm reply', exact: true }).click();
  await expect.poll(() => page.evaluate(() => __calls.filter(call => call.path === 'reply'))).toEqual([{
    path: 'reply', data: { sessionID:'session-original',requestID:'request-original',ticket:'ticket-original',
      decision:'allow',answers:{},permissionOptionID:'offered-only' }
  }]);
  await page.evaluate(() => __disconnect());
  expect(await page.evaluate(() => __calls.filter(call => call.path === 'reply'))).toHaveLength(1);
});

test('QR mismatch never starts a channel', async ({ page }) => {
  await setup(page, { mismatch:true });
  await page.getByLabel('Phone name').fill('Synthetic phone');
  await page.getByRole('button', { name: 'Pair with this Mac', exact:true }).click();
  await expect(page.getByRole('alert')).toContainText('does not match');
  expect(await page.evaluate(() => typeof __approve)).toBe('undefined');
});

test('missing identity does not silently create a replacement device on returning login', async ({ page }) => {
  await setup(page); await pair(page);
  await page.evaluate(async () => {
    const { deleteIdentity } = await import('/remote-identity.mjs');
    await deleteIdentity({origin:location.origin,accountID:'test-account',macID:'mac'});
  });
  await page.reload();
  await page.getByRole('button', { name: 'Connect', exact:true }).click();
  await expect(page.getByRole('alert')).toContainText('pair again');
  expect(await page.evaluate(() => __calls.filter(call => call.path.endsWith('/pair')))).toHaveLength(0);
});

test('original question choices and custom answers survive review and enforce minimum selections', async ({ page }) => {
  await setup(page); await pair(page);
  await page.evaluate(() => {
    __requests = [{ ...__requests[0], request: { id:'question-original',title:'Synthetic question',kind:'question',questions:[
      {id:'platform',text:'Choose platforms',multiple:true,minimumSelections:2,allowFreeform:false,options:[{label:'A'},{label:'B'}]},
      {id:'instructions',text:'Instructions',multiple:false,allowFreeform:true,options:[{label:'Original choice'}]}
    ] } }];
    __approve();
  });
  await page.getByRole('button', { name:'Send answer',exact:true }).click();
  await expect(page.getByRole('status').filter({hasText:'choose at least 2'})).toBeVisible();
  await page.getByRole('checkbox', { name:'A',exact:true }).check();
  await page.getByRole('checkbox', { name:'B',exact:true }).check();
  await page.getByLabel('Custom answer for Instructions').fill('Exact custom text\nsecond line');
  await page.getByRole('button', { name:'Send answer',exact:true }).click();
  await expect(page.getByRole('dialog')).toContainText('Exact custom text');
  await page.getByRole('button', { name:'Confirm reply' }).click();
  await expect.poll(() => page.evaluate(() => __calls.find(call=>call.path==='reply')?.data)).toEqual({
    sessionID:'session-original',requestID:'question-original',ticket:'ticket-original',decision:'answer',
    answers:{platform:['A','B'],instructions:['Exact custom text\nsecond line']}
  });
});

test('freshness lease disables actions and expired confirmation cannot send', async ({ page }) => {
  await page.clock.install();
  await setup(page); await pair(page); await page.evaluate(() => __approve());
  await page.getByRole('button', { name:'Allow once',exact:true }).click();
  await page.evaluate(() => { __holdState = true; });
  await page.clock.fastForward(11000);
  await page.getByRole('button', { name:'Confirm reply' }).click();
  expect(await page.evaluate(() => __calls.filter(call=>call.path==='reply'))).toHaveLength(0);
  await expect(page.getByRole('button', { name:'Allow once',exact:true })).toBeDisabled();
  await expect(page.locator('#connection')).toHaveText('Mac unavailable');
});

test('uncertain reply is not offered again after reconnect', async ({ page }) => {
  await setup(page); await pair(page); await page.evaluate(() => { __holdReply = true; __approve(); });
  await page.getByRole('button', { name:'Allow once',exact:true }).click();
  await page.getByRole('button', { name:'Confirm reply' }).click();
  await expect.poll(() => page.evaluate(() => typeof __rejectReply)).toBe('function');
  await page.evaluate(() => { __rejectReply(); __disconnect(); __approve(); });
  await expect(page.getByRole('button', { name:'Allow once',exact:true })).toBeDisabled();
  expect(await page.evaluate(() => __calls.filter(call=>call.path==='reply'))).toHaveLength(1);
});

test('session chat reuses original workspace and exact target ticket; disconnected controls are disabled', async ({ page }) => {
  await setup(page); await pair(page);
  await page.evaluate(() => {
    __workspace = { connected:true,total:1,sessions:[{id:'session-original',name:'Synthetic session',agent:'Test agent',project:'test',
      color:'#765c3c',state:'working',connected:true,ticket:'workspace-ticket',runningCount:0,idleCount:0,capabilities:{steering:true}}],
      detail:{sessionID:'session-original',ticket:'workspace-ticket',controls:[],activity:[{id:'line',kind:'assistant',detail:'Synthetic chat message',timestamp:'2026-11-16T00:00:00Z'}],team:{agents:[]}} };
    __approve();
  });
  await page.getByRole('button', {name:'Sessions',exact:true}).click();
  await page.getByRole('button', {name:'Open Synthetic session',exact:true}).click();
  await expect(page.getByRole('region',{name:'Conversation'})).toContainText('Synthetic chat message');
  await page.setViewportSize({width:320,height:480});
  await expect.poll(async () => {
    const button = await page.getByRole('button',{name:'Send',exact:true}).boundingBox();
    const navigation = await page.getByRole('navigation',{name:'Notify views'}).boundingBox();
    return button.y + button.height <= navigation.y && navigation.y + navigation.height <= 480;
  }).toBe(true);
  await page.getByLabel('Message',{exact:true}).fill('Synthetic instruction');
  await page.getByRole('button',{name:'Send',exact:true}).click();
  await expect.poll(() => page.evaluate(() => __calls.find(call=>call.path==='control')?.data)).toMatchObject({
    sessionID:'session-original',ticket:'workspace-ticket',action:'queue',text:'Synthetic instruction'
  });
  await page.evaluate(() => __disconnect());
  await expect(page.getByRole('button',{name:'Stop main',exact:true})).toBeDisabled();
  await expect(page.getByLabel('Message',{exact:true})).toBeDisabled();
});

test('real browser passkey registration and discoverable login serialize binary fields without fake userHandle', async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options:{
    protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true
  } });
  const posted = [];
  await page.route('**/v1/account/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/options')) {
      const common = { challenge:Buffer.alloc(32,1).toString('base64url'),timeout:60000 };
      await route.fulfill({json:path.includes('/register/') ? {...common,rp:{name:'Notify synthetic test',id:'localhost'},
        user:{id:Buffer.from('test-account').toString('base64url'),name:'Synthetic',displayName:'Synthetic'},
        pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'required',userVerification:'required'}}
        : {...common,rpId:'localhost',userVerification:'required'}});
    } else {
      posted.push({path,data:route.request().postDataJSON()});
      await route.fulfill({json:{account:{issuer:'test',subject:'test-account'}}});
    }
  });
  await page.goto(`${origin.replace('127.0.0.1','localhost')}/actual-transport.mjs`);
  // This is the real browser WebAuthn ceremony with a synthetic in-memory authenticator, not a user passkey.
  await page.evaluate(async () => {
    const { authenticate } = await import('/actual-transport.mjs');
    await authenticate('register','Synthetic'); await authenticate('login');
    Object.defineProperty(PublicKeyCredential,'parseRequestOptionsFromJSON',{value:undefined});
    Object.defineProperty(PublicKeyCredential,'parseCreationOptionsFromJSON',{value:undefined});
    await authenticate('register','Synthetic fallback'); await authenticate('login');
  });
  expect(posted).toHaveLength(4);
  const register = posted[0].data.response, login = posted[1].data.response;
  expect(register.response.attestationObject).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(login.response.userHandle).toBe(Buffer.from('test-account').toString('base64url'));
  expect(login.rawId).toBe(register.rawId);
  expect(login.response.signature).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(posted[2].data.response.response.attestationObject).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(posted[3].data.response.response.userHandle).toBe(Buffer.from('test-account').toString('base64url'));
});
