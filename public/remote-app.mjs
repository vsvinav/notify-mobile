import { authenticate, base64, base64url, createRemoteTransport, loadCrypto, parseSetup, postJSON, publicKey } from './remote-transport.mjs';
import { createIdentity, deleteIdentity, loadIdentity } from './remote-identity.mjs';
import { createWorkspace } from './workspace.mjs';

const app = document.querySelector('#app'), connection = document.querySelector('#connection');
const metadataKey = 'notify-remote-relationships-v1';
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const text = (value, max = 65535) => typeof value === 'string' && value.length <= max;
let account, setup, setupError, relationship, transport, workspace, view = 'inbox', channelState = 'disconnected';
let banner, reconnect, inbox, settings, navigation, picker, list, lastRead = 0, snapshot, pollTimer, leaseTimer, polling = false;
let generation = 0, selectedTicket, selectedSessionID, confirmation, signingIn = false;
const cards = new Map();
function el(tag, value, className) {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = value;
  if (className) node.className = className;
  return node;
}
function button(label, className, handler) {
  const node = el('button', label, `button ${className || ''}`); node.type = 'button';
  node.addEventListener('click', handler); return node;
}
function input(labelText, maxLength = 80) {
  const label = el('label', labelText, 'input-label'), field = el('input');
  field.type = 'text'; field.maxLength = maxLength; label.append(field);
  return { label, field };
}
function errorNode() { const node = el('p', '', 'message error'); node.setAttribute('role', 'alert'); return node; }
const sameAccount = value => value?.issuer === account?.issuer && value?.subject === account?.subject;
const scope = record => ({ origin: location.origin, accountID: account.subject, macID: record.macID });
function acceptAccount(result) {
  if (!result?.account || !text(result.account.issuer, 2048) || !result.account.issuer || !id(result.account.subject)) throw new Error('Invalid account session. Sign in again.');
  account = { issuer: result.account.issuer, subject: result.account.subject };
}
function records() {
  const raw = localStorage.getItem(metadataKey);
  if (!raw) return [];
  if (raw.length > 32768) throw new Error('Saved pairing metadata is invalid. Do not reconnect from this browser.');
  const values = JSON.parse(raw);
  if (!Array.isArray(values) || values.length > 8 || !values.every(record =>
    Object.keys(record).sort().join(',') === 'account,deviceID,macID,macPublicKey,name,origin,publicKey'
    && record.origin === location.origin && id(record.macID) && id(record.deviceID)
    && record.account && Object.keys(record.account).sort().join(',') === 'issuer,subject'
    && text(record.account.issuer, 2048) && record.account.issuer.length && id(record.account.subject)
    && text(record.name, 80) && record.name.trim()
    && publicKey(record.macPublicKey) && publicKey(record.publicKey))) throw new Error('Saved pairing metadata is invalid. Do not reconnect from this browser.');
  const keys = values.map(value => JSON.stringify([value.account, value.macID]));
  if (new Set(keys).size !== values.length) throw new Error('Saved pairing metadata contains conflicting Macs.');
  return values;
}
function saveRecord(record) {
  const all = records();
  if (all.some(value => sameAccount(value.account) && value.macID === record.macID)) throw new Error('This Mac already has a saved identity. Connect or explicitly forget it before pairing again.');
  if (all.length >= 8) throw new Error('This browser has eight saved Macs. Forget an unused pairing before adding another.');
  localStorage.setItem(metadataKey, JSON.stringify([...all, record]));
}
function resetPrivateView() {
  generation++; clearTimeout(pollTimer); clearInterval(leaseTimer); polling = false;
  transport?.close(); transport = undefined;
  workspace?.clear(); workspace = undefined;
  confirmation?.close(); confirmation?.remove(); confirmation = undefined;
  cards.clear(); snapshot = undefined; lastRead = 0; selectedTicket = selectedSessionID = undefined; channelState = 'disconnected';
  banner = reconnect = inbox = settings = navigation = undefined;
  document.body.classList.remove('paired'); delete document.body.dataset.detail;
  app.replaceChildren();
}
function showLogin(message = '') {
  resetPrivateView(); account = undefined; relationship = undefined;
  connection.textContent = 'Sign in'; connection.dataset.connected = 'false';
  const intro = el('section', undefined, 'intro');
  intro.append(el('h1', 'Your Mac, from here'), el('p', 'Sign in with a passkey, then pair in person. Account sign-in alone does not grant access to your Mac.', 'support'));
  const panel = el('section', undefined, 'pair-panel'), name = input('Account name');
  const error = errorNode(); error.textContent = message || setupError || '';
  const register = button('Create account with a passkey', '', () => signIn('register'));
  const login = button('Sign in with a passkey', 'primary', () => signIn('login'));
  panel.append(name.label, login, register, error); app.append(intro, panel);
  async function signIn(mode) {
    if (signingIn) return;
    if (mode === 'register' && !name.field.value.trim()) { error.textContent = 'Enter an account name before creating a passkey.'; name.field.focus(); return; }
    signingIn = true; login.disabled = register.disabled = true; error.textContent = '';
    try { acceptAccount(await authenticate(mode, name.field.value.trim())); showRelationships(); }
    catch (cause) { error.textContent = cause.name === 'NotAllowedError' ? 'Passkey sign-in was cancelled or unavailable. Try again when ready.' : cause.message; }
    finally { signingIn = false; login.disabled = register.disabled = false; }
  }
}
async function logout() {
  resetPrivateView();
  const notice = el('p', 'Signing out…', 'banner'); app.append(notice);
  try { await postJSON('/v1/account/logout', {}); showLogin(); }
  catch { notice.textContent = 'Sign-out could not be confirmed. Your Mac channel is closed; retry to end the account session.'; app.append(button('Retry sign out', '', logout)); }
}
function showRelationships() {
  resetPrivateView(); connection.textContent = 'Choose your Mac';
  const intro = el('section', undefined, 'intro');
  intro.append(el('h1', setup ? 'Pair with your Mac' : 'Your Macs'),
    el('p', setup ? 'This QR code pins the complete public key from your Mac. Pair only while you can compare both screens in person.'
      : 'Choose a saved Mac, or scan a fresh setup QR code shown by Notify on your Mac.', 'support'));
  app.append(intro); const error = errorNode(); error.textContent = setupError || '';
  try {
    const saved = records().filter(value => sameAccount(value.account));
    for (const record of saved) {
      const section = el('section', undefined, 'settings');
      section.append(el('h2', record.name), el('p', `Mac: ${record.macID}`, 'field-value'),
        button('Connect', 'primary', () => void connectSaved(record, error)),
        button('Forget this phone’s pairing', 'deny', () => forget(record, error)));
      app.append(section);
    }
    if (setup && !saved.some(value => value.macID === setup.macID)) {
      const panel = el('section', undefined, 'pair-panel'), name = input('Phone name');
      const pair = button('Pair with this Mac', 'primary', async () => {
        if (!name.field.value.trim()) { error.textContent = 'Enter a phone name.'; name.field.focus(); return; }
        pair.disabled = true;
        try { await pairPhone(name.field.value.trim()); }
        catch (cause) {
          error.textContent = cause.message;
          const recovery = button('Forget this scanned Mac’s stored identity', 'deny', () => forget({ macID: setup.macID }, error));
          pair.after(recovery); pair.disabled = true;
        }
      });
      panel.append(name.label, el('p', `Mac: ${setup.macID}`, 'support'), pair); app.append(panel);
    }
  } catch (cause) { error.textContent = cause.message; }
  app.append(error, button('Sign out', '', logout));
}
function forget(record, error) {
  const dialog = el('dialog', undefined, 'control-confirmation');
  dialog.setAttribute('aria-label', 'Forget this pairing');
  dialog.append(el('h2', 'Forget this pairing?'), el('p', 'This deletes this browser’s channel identity, not the account. Revoke the phone on your Mac too. A new in-person pairing is required to connect again.', 'support'));
  const actions = el('div', undefined, 'actions'), close = () => { dialog.close(); dialog.remove(); };
  actions.append(button('Cancel', '', close), button('Forget pairing', 'deny', async () => {
    close();
    try {
      await deleteIdentity(scope(record));
      localStorage.setItem(metadataKey, JSON.stringify(records().filter(value => !(sameAccount(value.account) && value.macID === record.macID))));
      showRelationships();
    } catch (cause) { error.textContent = cause.message; }
  }));
  dialog.append(actions); app.append(dialog); dialog.showModal();
}
async function pairPhone(name) {
  const result = await postJSON('/v1/account/session', {});
  if (result.scope !== 'account' || !sameAccount(result.account)) throw new Error('Your account changed. Sign out and sign in again before pairing.');
  if (!result.fresh) throw new Error('Pairing needs a fresh passkey sign-in. Sign out, sign in again, and scan the Mac QR code.');
  const { Peer } = await loadCrypto(), peer = new Peer('phone');
  let secret;
  const record = { origin: location.origin, account: { ...account }, macID: setup.macID, macPublicKey: setup.macPublicKey,
    deviceID: crypto.randomUUID(), name, publicKey: base64url(peer.identity_key()) };
  try {
    const saved = records();
    if (saved.length >= 8) throw new Error('This browser has eight saved Macs. Forget an unused pairing first.');
    if (saved.some(value => sameAccount(value.account) && value.macID === record.macID)) throw new Error('A saved pairing already exists. Connect or explicitly forget it first.');
    secret = peer.export_identity();
    await createIdentity(scope(record), { publicKey: publicKey(record.publicKey), secret });
    saveRecord(record);
  } finally { secret?.fill(0); peer.free(); }
  const pending = await postJSON('/v1/remote/pair', { setupID: setup.setupID, deviceID: record.deviceID, publicKey: record.publicKey, name });
  if (pending.macID !== record.macID || pending.macPublicKey !== record.macPublicKey || !sameAccount(pending.account)) {
    throw new Error('The pairing response does not match the complete QR-pinned Mac key and account. Do not approve it. Forget this pairing and check your Mac.');
  }
  await connectSaved(record);
}
async function connectSaved(record, error) {
  try {
    const identity = await loadIdentity(scope(record), publicKey(record.publicKey));
    identity.secret.fill(0);
    resetPrivateView(); relationship = record;
    showWaiting();
    transport = createRemoteTransport({ macID: record.macID, deviceID: record.deviceID, autoReconnect: true,
      pinnedMacKey: publicKey(record.macPublicKey), onStatus: statusChanged,
      restorePeer: async () => {
        const { Peer } = await loadCrypto();
        const identity = await loadIdentity(scope(record), publicKey(record.publicKey));
        try { return Peer.restore_identity('phone', identity.secret, identity.publicKey); }
        finally { identity.secret.fill(0); }
      } });
    await transport.connect();
  } catch (cause) {
    const message = cause.code ? 'This browser’s saved identity is missing or unreadable. Explicitly forget this pairing and pair again in person; no replacement was created.' : cause.message;
    if (error?.isConnected) error.textContent = message;
    else if (banner) { banner.textContent = message; banner.setAttribute('role', 'alert'); }
  }
}
function showWaiting() {
  app.replaceChildren();
  const intro = el('section', undefined, 'intro');
  intro.append(el('h1', 'Compare on your Mac'), el('p', 'Compare every character of this phone’s complete public key with the value displayed by Notify on your Mac. Approve on the Mac only if the entire value matches.', 'support'));
  const key = el('pre', base64(publicKey(relationship.publicKey)), 'field-value');
  key.setAttribute('aria-label', 'Complete phone public key');
  const panel = el('section', undefined, 'pair-panel');
  panel.append(el('p', relationship.name, 'session-name'), key,
    el('p', '88 characters, including the final “=”. Do not compare only the beginning or end. A name or short code is not proof.', 'support'));
  banner = el('p', 'Waiting for the encrypted channel and Mac approval. No private data is available yet.', 'banner'); banner.setAttribute('role', 'status');
  reconnect = button('Reconnect', '', () => void transport?.connect().catch(() => {})); reconnect.hidden = true;
  app.append(intro, panel, banner, reconnect, button('Your Macs', '', showRelationships), button('Sign out', '', logout));
}
function live() { return channelState === 'connected' && snapshot?.connected === true && performance.now() - lastRead < 10000 && !document.hidden; }
function statusChanged(status) {
  channelState = status.state; connection.dataset.connected = String(status.state === 'connected');
  connection.textContent = status.state === 'connected' ? 'Connected' : status.state === 'pending' ? 'Awaiting approval' : status.state === 'connecting' ? 'Connecting…' : 'Not connected';
  if (status.state === 'connected') {
    if (!inbox) buildWorkspace();
    banner.textContent = 'Refreshing from your Mac…'; banner.hidden = false;
    void refresh();
  } else {
    lastRead = 0;
    if (banner) { banner.hidden = false; banner.textContent = status.message; }
    if (reconnect) reconnect.hidden = status.state !== 'disconnected';
    confirmation?.close(); confirmation?.remove(); confirmation = undefined;
    updateControls();
  }
}
async function api(path, data, timeout, signal) {
  if (['reply', 'control'].includes(path) && !live()) throw new Error('Reconnect and refresh the Mac before sending. Nothing was sent.');
  return transport.api(path, data, timeout, signal);
}
function buildWorkspace() {
  app.replaceChildren(); document.body.classList.add('paired');
  banner = el('p', '', 'banner'); banner.setAttribute('role', 'status');
  reconnect = button('Reconnect', '', () => void transport.connect().catch(() => {})); reconnect.hidden = true;
  inbox = el('section', undefined, 'review-screen');
  const toolbar = el('div', undefined, 'review-toolbar');
  toolbar.append(el('h1', 'Inbox'));
  picker = el('select', undefined, 'request-picker'); picker.setAttribute('aria-label', 'Review request');
  picker.addEventListener('change', () => { selectedTicket = picker.value; renderSelection(); });
  toolbar.append(picker); list = el('div', undefined, 'review-list'); inbox.append(toolbar, list);
  workspace = createWorkspace({ api, el, button, onUnauthorized: message => showLogin(message),
    onNetworkError: () => { lastRead = 0; updateControls(); },
    onNavigate: sessionID => { selectedSessionID = sessionID; document.body.dataset.detail = String(view === 'sessions' && !!sessionID); } });
  settings = el('section', undefined, 'phone-settings');
  settings.append(el('h1', 'Connection'), el('p', `Phone: ${relationship.name}`, 'detail'),
    el('p', `Mac: ${relationship.macID}`, 'detail'),
    el('p', 'Only this approved Mac can answer through the encrypted channel. Keep it awake with internet access enabled. No background alerts or offline action queue.', 'detail'),
    button('Your Macs', '', showRelationships), button('Sign out', '', logout));
  navigation = el('nav', undefined, 'primary-navigation'); navigation.setAttribute('aria-label', 'Notify views');
  for (const [value, label] of [['inbox', 'Inbox'], ['sessions', 'Sessions'], ['settings', 'Settings']]) {
    const item = button(label, '', () => selectView(value)); item.dataset.view = value; navigation.append(item);
  }
  app.append(banner, reconnect, inbox, workspace.node, settings, navigation); selectView(view);
  clearInterval(leaseTimer); leaseTimer = setInterval(updateControls, 500);
}
function selectView(value) {
  view = value; inbox.hidden = value !== 'inbox'; settings.hidden = value !== 'settings';
  document.body.dataset.detail = String(value === 'sessions' && !!selectedSessionID);
  workspace.setVisible(value === 'sessions');
  for (const item of navigation.children) item.setAttribute('aria-pressed', String(item.dataset.view === value));
}
function validRequest(item) {
  const request = item?.request;
  return item && text(item.ticket, 256) && item.ticket && text(item.sessionID, 256) && item.sessionID
    && text(item.sessionName, 256) && request && text(request.id, 256) && request.id && text(request.title)
    && (request.detail === undefined || text(request.detail)) && ['permission', 'question'].includes(request.kind)
    && Array.isArray(item.fields) && item.fields.every(field => text(field.label) && text(field.value))
    && (request.permissionOptions === undefined || (Array.isArray(request.permissionOptions)
      && request.permissionOptions.every(option => text(option.id, 256) && option.id && text(option.label) && (!option.detail || text(option.detail)))))
    && (request.kind !== 'question' || (Array.isArray(request.questions) && request.questions.length > 0
      && new Set(request.questions.map(q => q.id)).size === request.questions.length
      && request.questions.every(q => text(q.id, 256) && q.id && !['__proto__', 'constructor', 'prototype'].includes(q.id)
        && text(q.text) && typeof q.multiple === 'boolean' && typeof q.allowFreeform === 'boolean'
        && (q.minimumSelections === undefined || Number.isInteger(q.minimumSelections) && q.minimumSelections >= 0)
        && Array.isArray(q.options) && q.options.every(option => text(option.label) && (!option.description || text(option.description))))));
}
async function refresh() {
  if (polling || channelState !== 'connected' || document.hidden || !inbox) return;
  polling = true; const current = generation;
  try {
    const state = await api('state', {}, 10000);
    if (current !== generation) return;
    if (typeof state.connected !== 'boolean' || !Array.isArray(state.requests) || state.requests.length > 100 || !state.requests.every(validRequest)
      || new Set(state.requests.map(item => item.ticket)).size !== state.requests.length) throw new Error('The Mac returned an unsupported request snapshot. Review it on your Mac; no phone replies are enabled.');
    snapshot = state; lastRead = performance.now();
    const present = new Set(state.requests.map(item => item.ticket));
    for (const [ticket, card] of cards) if (!present.has(ticket)) { card.node.remove(); cards.delete(ticket); }
    for (const item of state.requests) {
      let card = cards.get(item.ticket); const signature = JSON.stringify(item);
      if (card && card.signature !== signature && !card.submitted) { card.node.remove(); cards.delete(item.ticket); card = undefined; }
      if (!card) { card = makeCard(item); card.signature = signature; cards.set(item.ticket, card); list.append(card.node); }
    }
    renderSelection(); updateControls();
  } catch (cause) {
    if (current !== generation) return;
    lastRead = 0; banner.hidden = false; banner.textContent = cause.message; updateControls();
  } finally {
    if (current === generation) { polling = false; clearTimeout(pollTimer); pollTimer = setTimeout(refresh, 3000); }
  }
}
function updateControls() {
  const connected = live();
  if (channelState === 'connected') {
    connection.textContent = connected ? 'Connected' : 'Mac unavailable';
    connection.dataset.connected = String(connected);
  }
  workspace?.setConnected(connected);
  for (const card of cards.values()) {
    const disabled = !connected || card.submitted || card.item.sending;
    for (const control of card.node.querySelectorAll('button,input,textarea')) control.disabled = !!disabled;
  }
  if (inbox && banner) {
    if (connected) { banner.hidden = true; reconnect.hidden = true; }
    else if (channelState === 'connected') {
      banner.hidden = false;
      if (lastRead) banner.textContent = 'Mac snapshots are stale or disconnected. Replies and controls are disabled until a fresh update arrives.';
    }
  }
}
function renderSelection() {
  const waiting = [...cards.values()].filter(card => !card.succeeded);
  if (!waiting.some(card => card.item.ticket === selectedTicket)) selectedTicket = waiting[0]?.item.ticket;
  picker.replaceChildren();
  for (const card of waiting) {
    const option = el('option', `${card.item.sessionName} · ${card.item.request.title}`); option.value = card.item.ticket; picker.append(option);
  }
  picker.hidden = waiting.length < 2; picker.value = selectedTicket || '';
  list.querySelector('.empty')?.remove();
  for (const card of cards.values()) card.node.hidden = card.item.ticket !== selectedTicket;
  if (!waiting.length) list.append(el('p', 'No waiting requests reported by your Mac.', 'empty'));
}
function makeCard(item) {
  const node = el('article', undefined, 'request'), body = el('div', undefined, 'request-body');
  const card = { node, item, forms: new Map(), submitted: false, succeeded: false };
  body.append(el('p', item.sessionName, 'session-name'), el('p', `${item.agent || ''} · ${item.project || ''}`, 'session-meta'),
    el('h2', item.request.title), el('p', item.request.detail || '', 'detail'));
  for (const field of item.fields) {
    const section = el('section', undefined, `field ${['code', 'diff', 'warning'].includes(field.presentation) ? field.presentation : ''}`);
    section.append(el('p', `${field.target ? `${field.target} · ` : ''}${field.label}`, 'field-label'),
      el(['code', 'diff'].includes(field.presentation) || field.target ? 'pre' : 'p', field.value, 'field-value')); body.append(section);
  }
  for (const [index, question] of (item.request.kind === 'question' ? item.request.questions : []).entries()) {
    const fieldset = el('fieldset');
    fieldset.append(el('legend', question.text), el('p', `${question.multiple ? `Choose at least ${question.minimumSelections ?? 1}` : 'Choose one'} · ${question.required === false ? 'Optional' : 'Required'}`, 'question-help'));
    const options = [];
    for (const option of question.options) {
      const label = el('label', undefined, 'choice'), field = el('input'), labelText = el('span', option.label, 'choice-text');
      field.type = question.multiple ? 'checkbox' : 'radio'; field.name = `${item.ticket}-${index}`; field.value = option.label;
      if (option.description) labelText.append(el('small', option.description));
      label.append(field, labelText); fieldset.append(label); options.push(field);
    }
    let custom;
    if (question.allowFreeform) {
      const label = el('label', 'Or write your own', 'input-label'); custom = el('textarea'); custom.maxLength = 65535;
      custom.setAttribute('aria-label', `Custom answer for ${question.text}`); label.append(custom); fieldset.append(label);
      custom.addEventListener('input', () => { if (!question.multiple && custom.value) for (const field of options) field.checked = false; });
      for (const field of options) field.addEventListener('change', () => { if (!question.multiple && field.checked) custom.value = ''; });
    }
    card.forms.set(question.id, { options, custom }); body.append(fieldset);
  }
  const actions = el('div', undefined, 'actions'), area = el('div', undefined, 'request-actions');
  if (item.request.kind === 'permission') {
    const row = el('div', undefined, 'button-row');
    row.append(button('Deny', 'deny', () => prepareReply(card, 'deny', 'Deny')),
      button('Allow once', 'primary', () => prepareReply(card, 'allow', 'Allow once'))); actions.append(row);
    for (const option of item.request.permissionOptions || []) {
      const choice = button(option.label, 'scope', () => prepareReply(card, 'allow', option.label, option.id));
      if (option.detail) choice.append(el('small', option.detail)); actions.append(choice);
    }
    if (item.request.supportsFeedback) {
      const details = el('details', undefined, 'denial-feedback'), label = el('label', 'Optional feedback when denying', 'input-label');
      card.feedback = el('textarea'); card.feedback.maxLength = 4000; label.append(card.feedback);
      details.append(el('summary', 'Add denial instructions'), label); body.append(details);
    }
  } else actions.append(button('Send answer', 'primary', () => prepareReply(card, 'answer', 'Send answer')),
    button('Decline request', 'deny', () => prepareReply(card, 'deny', 'Decline request')));
  card.message = el('p', '', 'message'); card.message.setAttribute('role', 'status');
  area.append(actions, card.message); node.append(body, area); return card;
}
function prepareReply(card, decision, label, permissionOptionID) {
  if (!live() || card.submitted || card.item.sending || cards.get(card.item.ticket) !== card) return;
  const answers = {};
  if (decision === 'answer') for (const q of card.item.request.questions) {
    const form = card.forms.get(q.id), values = form.options.filter(option => option.checked).map(option => option.value);
    if (form.custom?.value.trim()) values.push(form.custom.value);
    const unique = [...new Set(values)], minimum = q.multiple ? q.minimumSelections ?? 1 : 1;
    if ((q.required !== false || unique.length) && (unique.length < minimum || (!q.multiple && unique.length !== 1))) {
      card.message.textContent = `Review “${q.text}”: ${q.multiple ? `choose at least ${minimum}` : 'choose one answer'}.`; return;
    }
    answers[q.id] = unique;
  }
  const item = card.item, payload = { sessionID: item.sessionID, requestID: item.request.id, ticket: item.ticket, decision, answers,
    ...(permissionOptionID ? { permissionOptionID } : {}),
    ...(decision === 'deny' && card.feedback?.value.trim() ? { feedback: card.feedback.value } : {}) };
  confirmation?.remove(); confirmation = el('dialog', undefined, 'control-confirmation');
  confirmation.setAttribute('aria-label', 'Confirm this exact reply');
  confirmation.append(el('h2', `${label}?`), el('p', item.request.title, 'detail'),
    el('p', `Session: ${item.sessionID}\nRequest: ${item.request.id}\nTicket: ${item.ticket}`, 'field-value'));
  if (decision === 'answer') for (const q of item.request.questions) confirmation.append(el('p', `${q.text}\n${answers[q.id].join('\n') || 'No answer (optional)'}`, 'detail'));
  if (payload.feedback) confirmation.append(el('p', payload.feedback, 'detail'));
  const controls = el('div', undefined, 'actions');
  const close = () => { confirmation?.close(); confirmation?.remove(); confirmation = undefined; };
  controls.append(button('Cancel', '', close), button('Confirm reply', decision === 'deny' ? 'deny' : 'primary', async () => {
    close();
    if (!live() || cards.get(item.ticket) !== card || card.submitted) { card.message.textContent = 'The request or connection changed. Review the latest request before replying.'; return; }
    card.submitted = true; card.message.textContent = 'Waiting for agent acknowledgment…'; updateControls();
    try { await api('reply', payload); card.succeeded = true; card.message.textContent = 'Agent acknowledged your reply.'; }
    catch (cause) {
      card.message.textContent = cause.message;
      if (cause.status === 400) card.submitted = false;
    }
    renderSelection(); updateControls(); void refresh();
  }));
  confirmation.append(controls); app.append(confirmation); confirmation.showModal(); controls.firstChild.focus();
}
function resizeViewport() {
  document.documentElement.style.setProperty('--app-height', `${window.visualViewport?.height ?? innerHeight}px`);
}
window.addEventListener('resize', resizeViewport);
window.visualViewport?.addEventListener('resize', resizeViewport);
resizeViewport();
document.addEventListener('visibilitychange', () => { updateControls(); if (!document.hidden) void refresh(); });
window.addEventListener('pagehide', () => resetPrivateView());
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
try { setup = parseSetup(location.hash); } catch (cause) { setupError = cause.message; }
if (location.hash) history.replaceState(null, '', `${location.pathname}${location.search}`);
try {
  const session = await postJSON('/v1/account/session', {});
  if (session.scope !== 'account') throw new Error('Sign in to continue.');
  acceptAccount(session); showRelationships();
} catch (cause) { showLogin(cause.status === 401 ? '' : cause.message); }
