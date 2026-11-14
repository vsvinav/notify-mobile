const root = document.querySelector('#app');
const connection = document.querySelector('#connection');
const cards = new Map();
let paired = false, connected = false, polling = false, lastRefresh = 0, pairingTimer;
let list, banner, deviceBar, pushButton, pushNote, state, registration;
let workerError, pendingInstall;
const installed = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const isApple = /iPhone|iPad|iPod/.test(navigator.userAgent) ||
  (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function button(text, className, action) {
  const node = el('button', text, `button ${className ?? ''}`);
  node.type = 'button';
  if (action) node.addEventListener('click', action);
  return node;
}
function status(text, live = false) {
  connection.textContent = text;
  connection.dataset.connected = String(live);
}
async function api(path, data = {}, timeout = 25000) {
  let response;
  try {
    response = await fetch(`/api/${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', cache: 'no-store', body: JSON.stringify(data),
      signal: AbortSignal.timeout(timeout)
    });
  } catch {
    const error = new Error('Cannot reach your Mac. Connect to the same Wi-Fi and keep the Mac awake. No reply was retried.');
    error.network = true; throw error;
  }
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error ?? 'The Mac could not complete this request.');
    error.status = response.status; throw error;
  }
  return result;
}

function setupHelp() {
  const help = el('details', undefined, 'settings');
  help.append(el('summary', 'Install & connection help'));
  const steps = el('ol');
  for (const text of [
    'Use the same Wi-Fi as your Mac. In Notify on the Mac, enable Mobile and open its setup address.',
    'Before installing the local CA, compare its SHA-256 fingerprint with the Mac using a trusted certificate viewer. Do not trust it if you cannot verify a match. Never enter a pairing code on the HTTP setup page.',
    'Manually install and trust the CA, then open the exact HTTPS address shown on the Mac.',
    isApple ? 'In Safari, use Share → Add to Home Screen. Open Notify from its new Home Screen icon.'
      : 'Use your browser menu → Install app or Add to Home screen. Open the installed Notify app.',
    'Pair inside the installed app using a fresh Mac code. Safari and Home Screen storage can be separate; pairing in the browser may not carry over.',
    'To get alerts, tap Enable alerts in the installed app. Permission is optional; Focus and battery settings may delay delivery.'
  ]) steps.append(el('li', text));
  help.append(steps, el('p', 'Keep the Mac awake and connected. A changed Mac IP address means opening the new HTTPS address and pairing that origin again. Push alerts need internet access; requests and replies stay on your LAN.'),
    el('p', 'To remove trust, delete the Notify local CA/profile from iPhone Settings → General → VPN & Device Management, or Android Settings → Security → Trusted credentials → User. Also revoke this phone in Notify on the Mac.'));
  if (pendingInstall) {
    const install = button('Install Notify', '', async () => {
      try { await pendingInstall.prompt(); pendingInstall = undefined; install.remove(); }
      catch { install.textContent = 'Use the browser menu to install'; install.disabled = true; }
    });
    help.append(install);
  }
  return help;
}

function showPairing(message) {
  paired = false; connected = false;
  cards.clear(); root.replaceChildren();
  const intro = el('section', undefined, 'intro');
  intro.append(el('h1', 'Your Mac, within reach.'), el('p', 'Review requests and reply from your phone. Request details and replies stay on your local network.', 'muted'));
  const panel = el('form', undefined, 'pair-panel');
  panel.append(el('h2', 'Pair with your Mac'), el('p', 'Install Notify first, then pair from the Home Screen app with a fresh code from Mac Settings.', 'support'));
  const nameLabel = el('label', 'Phone name', 'input-label');
  const name = el('input'); name.type = 'text'; name.id = 'phone-name'; name.maxLength = 80; name.autocomplete = 'off';
  name.value = isApple ? 'My iPhone' : 'My phone'; name.required = true; nameLabel.htmlFor = name.id;
  const codeLabel = el('label', 'Pairing code', 'input-label');
  const code = el('input'); code.type = 'text'; code.inputMode = 'numeric'; code.pattern = '[0-9]{8}';
  code.autocomplete = 'off'; code.id = 'pairing-code'; code.maxLength = 8; code.required = true; code.placeholder = '8-digit code from your Mac';
  codeLabel.htmlFor = code.id;
  const submit = button('Pair with Mac', 'primary'); submit.type = 'submit';
  const note = el('p', message ?? '', 'message error'); note.setAttribute('role', 'alert');
  panel.append(nameLabel, name, codeLabel, code, submit, note);
  panel.addEventListener('submit', async event => {
    event.preventDefault(); submit.disabled = true; note.textContent = '';
    try {
      const result = await api('pair', { name: name.value, code: code.value });
      showComparison(result.code);
    } catch (error) { note.textContent = error.message; submit.disabled = false; }
  });
  root.append(intro, panel, setupHelp());
  status(navigator.onLine ? 'Not paired' : 'Offline');
}

function showComparison(code) {
  clearTimeout(pairingTimer);
  root.replaceChildren();
  const section = el('section', undefined, 'pair-panel');
  section.append(el('h1', 'Compare on your Mac'),
    el('p', 'Only confirm this phone in Notify Settings if both comparison codes match.', 'support'),
    el('p', code, 'pair-code'), el('p', 'Waiting for your Mac’s confirmation…', 'support'));
  root.append(section, setupHelp());
  status('Awaiting confirmation');
  const check = async () => {
    try {
      const result = await api('pair-status');
      if (result.state === 'accepted') { await refresh(); return; }
      if (result.state === 'denied') { showPairing('Pairing was declined on the Mac. Generate a new code to try again.'); return; }
      pairingTimer = setTimeout(check, 2000);
    } catch (error) { showPairing(error.message); }
  };
  pairingTimer = setTimeout(check, 1000);
}

function buildWorkspace() {
  root.replaceChildren();
  deviceBar = el('div', undefined, 'device-bar');
  banner = el('p', '', 'banner'); banner.hidden = true; banner.setAttribute('role', 'status');
  const heading = el('div', undefined, 'section-heading');
  heading.append(el('h1', 'Needs your attention'), el('span', '', 'count'));
  list = el('div');
  root.append(deviceBar, banner, heading, list);
  const settings = el('details', undefined, 'settings');
  settings.append(el('summary', 'Alerts & this phone'));
  pushNote = el('p');
  pushButton = button('Enable alerts', 'primary', enablePush);
  settings.append(pushNote, pushButton, el('p', 'Alerts contain only “Notify needs you.” Open Notify on the same network to see the current request. Permission and OS Focus may delay alerts. Test from Notify Settings on the Mac.'));
  root.append(settings, setupHelp());
}

function updatePush() {
  if (!pushButton) return;
  const supported = 'Notification' in window && 'PushManager' in window && 'serviceWorker' in navigator;
  pushButton.disabled = !supported || !connected || (isApple && !installed()) || !registration || !!state?.pushEnabled;
  pushButton.textContent = state?.pushEnabled ? 'Alerts enabled' : 'Enable alerts';
  pushNote.textContent = workerError ?? (!supported ? 'This browser does not support Web Push. Use a current Safari Home Screen app or Chrome on Android.'
    : isApple && !installed() ? 'On iPhone, install to the Home Screen and open that app before enabling alerts. Pair there with a fresh code.'
    : state?.pushEnabled ? 'Push subscription enabled. Delivery still depends on browser permission, internet access, and Focus settings.'
    : 'Enable alerts with this button. Your browser will ask permission; nothing is enabled automatically.');
  if (state?.pushMessage) pushNote.textContent += ` ${state.pushMessage}`;
  if (supported) pushNote.textContent += ` Browser notification permission: ${Notification.permission}.`;
}

async function enablePush() {
  pushButton.disabled = true;
  try {
    // Call directly in the button gesture; iOS rejects deferred permission requests.
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') throw new Error('Alerts were not allowed. Change notification permission in your phone settings, then try again.');
    if (!registration) throw new Error('The installed app is not ready for notifications. Close and reopen it.');
    const key = Uint8Array.from(atob(state.vapidPublicKey.replace(/-/g, '+').replace(/_/g, '/')), character => character.charCodeAt(0));
    let subscription = await registration.pushManager.getSubscription();
    if (!subscription) subscription = await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
    await api('push', { subscription: subscription.toJSON() });
    await refresh();
  } catch (error) {
    pushNote.textContent = error.message;
    pushButton.disabled = false;
  }
}

function requestHeader(item) {
  const node = el('div');
  const session = el('div', undefined, 'session');
  const dot = el('span', '', 'session-dot');
  if (/^#[a-fA-F0-9]{6}$/.test(item.color)) dot.style.backgroundColor = item.color;
  const identity = el('div');
  identity.append(el('p', item.sessionName, 'session-name'), el('p', `${item.agent} · ${item.project}`, 'session-meta'));
  session.append(dot, identity);
  node.append(session, el('h2', item.request.title));
  if (item.request.detail) node.append(el('p', item.request.detail, 'detail'));
  for (const field of item.fields) {
    const section = el('section', undefined, `field ${field.presentation}`);
    section.append(el('p', `${field.target ? `${field.target} · ` : ''}${field.label}`, 'field-label'));
    section.append(el(['code', 'diff'].includes(field.presentation) || field.target ? 'pre' : 'p', field.value, 'field-value'));
    node.append(section);
  }
  return node;
}

function makeCard(item) {
  const node = el('article', undefined, 'request');
  const header = requestHeader(item);
  node.append(header);
  const card = { node, header, item, forms: new Map(), submitted: false, busy: false, error: '', succeeded: false };
  const controls = el('div');
  if (item.request.kind === 'question') {
    for (const [index, q] of item.request.questions.entries()) {
      const fieldset = el('fieldset');
      fieldset.append(el('legend', q.text), el('p',
        `${q.multiple ? `Choose ${q.minimumSelections ?? 1} or more` : 'Choose one'}${q.required === false ? ' · Optional' : ' · Required'}${q.allowFreeform ? ' · Custom answers allowed' : ''}`,
        'question-help'));
      const options = [];
      for (const option of q.options) {
        const label = el('label', undefined, 'choice');
        const input = el('input'); input.type = q.multiple ? 'checkbox' : 'radio';
        input.name = `${item.ticket}-${index}`; input.value = option.label;
        const text = el('span', option.label, 'choice-text');
        if (option.description) text.append(el('small', option.description));
        label.append(input, text); fieldset.append(label); options.push(input);
      }
      let custom;
      if (q.allowFreeform) {
        const label = el('label', 'Or write your own', 'input-label');
        custom = el('textarea'); custom.maxLength = 65535;
        custom.setAttribute('aria-label', `Custom answer for ${q.text}`);
        label.append(custom); fieldset.append(label);
        custom.addEventListener('input', () => {
          if (!q.multiple && custom.value.length) for (const option of options) option.checked = false;
        });
        for (const option of options) option.addEventListener('change', () => {
          if (!q.multiple && option.checked) custom.value = '';
        });
      }
      card.forms.set(q.id, { options, custom });
      controls.append(fieldset);
    }
  }
  const actions = el('div', undefined, 'actions');
  if (item.request.kind === 'permission') {
    const row = el('div', undefined, 'button-row');
    row.append(button('Deny', 'deny', () => send(card, 'deny')), button('Allow once', 'primary', () => send(card, 'allow')));
    actions.append(row);
    for (const option of item.request.permissionOptions ?? []) {
      const scope = button(option.label, 'scope', () => send(card, 'allow', option.id));
      if (option.detail) scope.append(el('small', option.detail));
      actions.append(scope);
    }
    if (item.request.supportsFeedback) {
      const label = el('label', 'Optional feedback when denying', 'input-label');
      card.feedback = el('textarea'); card.feedback.maxLength = 4000; card.feedback.setAttribute('aria-label', 'Optional feedback when denying');
      label.append(card.feedback); controls.append(label);
    }
  } else {
    actions.append(button('Send answer', 'primary', () => send(card, 'answer')),
      button('Decline request', 'deny', () => send(card, 'deny')));
  }
  card.controls = controls; controls.append(actions);
  card.message = el('p', '', 'message'); card.message.setAttribute('role', 'status');
  node.append(controls, card.message);
  return card;
}

function updateCard(card) {
  const disabled = !connected || card.busy || card.submitted || card.item.sending;
  for (const control of card.controls.querySelectorAll('button, input, textarea')) control.disabled = disabled;
  card.message.classList.toggle('error', !!card.error || !!card.item.error);
  card.message.textContent = card.error || (card.busy ? 'Waiting for agent acknowledgment…' :
    card.succeeded ? 'Agent acknowledged your reply.' : card.item.error ||
    (card.item.sending ? 'Already sent. Waiting for the Mac to update this request.' :
      !connected ? 'Replies disabled until the Mac reconnects with a fresh request.' : ''));
}

async function send(card, decision, permissionOptionID) {
  if (!connected || card.busy || card.submitted || card.item.sending) return;
  const answers = {};
  if (decision === 'answer') {
    for (const q of card.item.request.questions) {
      const form = card.forms.get(q.id);
      const values = form.options.filter(o => o.checked).map(o => o.value);
      if (form.custom?.value.trim()) values.push(form.custom.value);
      const minimum = q.multiple ? q.minimumSelections ?? 1 : 1;
      if ((q.required !== false || values.length > 0) && (values.length < minimum || (!q.multiple && values.length !== 1))) {
        card.error = `Review “${q.text}”: ${q.multiple ? `choose at least ${minimum}` : 'choose one answer'}.`;
        updateCard(card); return;
      }
      answers[q.id] = [...new Set(values)];
    }
  }
  card.busy = true; card.submitted = true; card.error = ''; updateCard(card);
  const item = card.item;
  try {
    await api('reply', {
      sessionID: item.sessionID, requestID: item.request.id, ticket: item.ticket, decision, answers,
      ...(permissionOptionID ? { permissionOptionID } : {}),
      ...(decision === 'deny' && card.feedback?.value.trim() ? { feedback: card.feedback.value } : {})
    });
    card.succeeded = true;
  } catch (error) {
    card.error = error.message;
    if (error.status === 400) card.submitted = false;
    if (error.network) connected = false;
    if (error.status === 401) { showPairing(error.message); return; }
  } finally {
    card.busy = false; updateCard(card);
  }
  void refresh();
}

async function refresh() {
  if (polling || document.hidden) return;
  polling = true;
  try {
    state = await api('state', {}, 6000);
    lastRefresh = Date.now(); connected = state.connected && navigator.onLine;
    if (!paired) { paired = true; buildWorkspace(); }
    status(connected ? 'Connected' : 'Mac unavailable', connected);
    deviceBar.replaceChildren(el('span', `Paired · ${state.device.name}`), el('span', state.pushEnabled ? 'Push enabled' : 'Push not enabled'));
    banner.hidden = connected;
    banner.textContent = connected ? '' : 'The Mac is unavailable or its requests are stale. Keep it awake and reconnect before replying.';
    root.querySelector('.count').textContent = connected ? `${state.total} pending` : '';
    if (connected) {
      const keys = new Set(state.requests.map(item => item.ticket));
      for (const [key, card] of cards) {
        if (!keys.has(key)) { card.node.remove(); cards.delete(key); }
      }
      list.querySelector('.empty')?.remove();
      for (const item of state.requests) {
        let card = cards.get(item.ticket);
        const signature = JSON.stringify({
          kind: item.request.kind, questions: item.request.questions,
          permissionOptions: item.request.permissionOptions, supportsFeedback: item.request.supportsFeedback
        });
        const headerSignature = JSON.stringify({
          sessionName: item.sessionName, project: item.project, agent: item.agent, color: item.color,
          title: item.request.title, detail: item.request.detail, fields: item.fields
        });
        if (card && card.signature !== signature) {
          card.node.remove(); cards.delete(item.ticket); card = undefined;
        }
        if (!card) { card = makeCard(item); card.signature = signature; cards.set(item.ticket, card); list.append(card.node); }
        if (card.headerSignature !== headerSignature) {
          const header = requestHeader(item); card.header.replaceWith(header); card.header = header;
          card.headerSignature = headerSignature;
        }
        card.item = item; updateCard(card);
      }
      if (!cards.size) {
        const empty = el('section', undefined, 'empty');
        empty.append(el('div', '✓', 'empty-mark'), el('h2', 'All caught up'),
          el('p', 'New requests will appear here. You can leave this app open or enable alerts below.'));
        list.append(empty);
      }
    } else {
      for (const card of cards.values()) updateCard(card);
    }
    updatePush();
  } catch (error) {
    connected = false;
    if (error.status === 401) {
      if (paired) showPairing(error.message);
      else if (!root.children.length) showPairing();
    } else {
      status('Offline');
      if (!root.children.length) showPairing(error.message);
      if (banner) { banner.hidden = false; banner.textContent = error.message; }
      for (const card of cards.values()) updateCard(card);
    }
  } finally { polling = false; }
}

window.addEventListener('offline', () => {
  connected = false; status('Offline');
  if (banner) { banner.hidden = false; banner.textContent = 'Offline. Connect to the Mac’s Wi-Fi to review the latest requests. Replies are disabled.'; }
  for (const card of cards.values()) updateCard(card);
  updatePush();
});
window.addEventListener('online', () => { void refresh(); });
window.addEventListener('pageshow', () => { void refresh(); });
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    connected = false;
    for (const card of cards.values()) updateCard(card);
    void refresh();
  }
});
window.addEventListener('beforeinstallprompt', event => { event.preventDefault(); pendingInstall = event; });
window.addEventListener('appinstalled', () => { pendingInstall = undefined; updatePush(); });
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').then(async worker => {
    registration = worker;
    await navigator.serviceWorker.ready;
    updatePush();
  }).catch(() => {
    workerError = 'The offline shell or notification worker could not start. Verify the local CA is trusted, then reopen the installed app.';
    updatePush();
  });
  navigator.serviceWorker.addEventListener('message', event => { if (event.data?.type === 'refresh') void refresh(); });
}
setInterval(() => {
  if (paired && connected && Date.now() - lastRefresh > 10000) {
    connected = false; status('Mac unavailable');
    for (const card of cards.values()) updateCard(card);
  }
  if (!pairingTimer || paired) void refresh();
}, 3000);
void refresh();
