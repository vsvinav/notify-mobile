function portrait(main, state) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 120 90');
  svg.setAttribute('aria-hidden', 'true');
  svg.classList.add('agent-portrait');
  if (['working', 'running'].includes(state)) svg.classList.add('is-working');
  const draw = (tag, attributes) => {
    const node = document.createElementNS(svg.namespaceURI, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
    svg.append(node); return node;
  };
  draw('path', { d: 'M12 70H111M22 70V85M100 70V85', class: 'portrait-line' });
  draw('circle', { cx: 36, cy: 29, r: 12, class: 'portrait-face' });
  draw('path', { d: 'M25 45Q17 55 20 69H49Q48 54 42 45M39 71L44 83H54', class: 'portrait-line' });
  draw('path', { d: 'M29 45L38 50V43L29 49Z', class: 'portrait-accent' });
  draw('path', { d: 'M66 63L73 43H106L98 63ZM59 67H101', class: 'portrait-accent' });
  draw('path', { d: 'M24 53L31 62L67 64M44 54L47 61L72 64', class: 'portrait-line portrait-hands' });
  if (state === 'cancelled' || state === 'stopped') {
    draw('path', { d: 'M30 26L33 29M33 26L30 29M39 26L42 29M42 26L39 29', class: 'portrait-line' });
  } else {
    draw('circle', { cx: 32, cy: 27, r: 1, fill: 'currentColor' });
    draw('circle', { cx: 40, cy: 27, r: 1, fill: 'currentColor' });
  }
  draw('path', { d: 'M33 34Q36 37 40 33', class: 'portrait-line' });
  if (main) {
    draw('path', { d: 'M23 19H49M28 18L30 4H42L44 18Z', class: 'portrait-hat' });
    draw('path', { d: 'M29 14H44', class: 'portrait-accent' });
  }
  return svg;
}

export function createWorkspace({ api, el, button, onUnauthorized, onNetworkError, onNavigate }) {
  const node = el('section', undefined, 'sessions-panel');
  const notice = el('p', 'Loading sessions…', 'banner');
  notice.setAttribute('role', 'status');
  const content = el('div', undefined, 'workspace-content');
  node.append(notice, content);
  let visible = false, connected = false, disposed = false, request, retry, revision;
  let generation = 0, data, sessionID = null, agentID = '', tab = 'chat', lastRead = 0;
  let showIdle = false, showInactive = false, fit = true, dialog, resize, chartFrame;
  let heading, metadata, target, composer, feed, tools, toolFeed, chat, chart, controlNote, sendButton, interruptButton, stopButton, jumpLatest;
  let messageSignature = '';
  let signature = '', targetSignature = '', chartSignature = '', listSignature = '';
  const drafts = new Map(), deliveries = new Map(), collapsed = new Set();
  const key = () => JSON.stringify([sessionID, agentID]);
  const session = () => data?.sessions.find(item => item.id === sessionID);
  const detail = () => data?.detail?.sessionID === sessionID && data.detail.ticket === session()?.ticket ? data.detail : null;
  const agent = () => detail()?.team?.agents.find(item => item.id === agentID);
  const name = () => agentID ? agent()?.name ?? 'Unavailable subagent' : 'Main agent';
  const live = () => connected && data?.connected && visible && Date.now() - lastRead < 10000 && !!detail() && session()?.connected;
  function cancelRead() {
    generation++; request?.abort(); request = undefined;
    clearTimeout(retry); revision = undefined;
  }
  async function watch() {
    if (!visible || !connected || disposed || request || document.hidden) return;
    const current = generation, selected = sessionID, controller = new AbortController();
    request = controller;
    const timeout = setTimeout(() => controller.abort(), 12000);
    let delay = 0;
    try {
      const result = await api('workspace', { sessionID: selected, ...(revision ? { revision } : {}) }, 12000, controller.signal);
      if (current !== generation || disposed) return;
      data = result; revision = result.revision; lastRead = Date.now();
      if (!result.connected || result.error) delay = 3000;
      notice.hidden = result.connected && !result.error;
      notice.textContent = result.error || (result.connected ? '' : 'The Mac workspace is unavailable. Keep Notify and the session connected.');
      render();
    } catch (error) {
      if (current !== generation || disposed) return;
      if (error.status === 401) { onUnauthorized(error.message); return; }
      data = data ? { ...data, connected: false } : undefined;
      notice.hidden = false;
      notice.textContent = error.aborted ? 'The live update timed out. Reconnecting; no message was retried.' : error.message;
      if (error.network) onNetworkError();
      updateControls(); delay = 3000;
    } finally {
      clearTimeout(timeout);
      if (request === controller) request = undefined;
      if (current === generation && !disposed) retry = setTimeout(watch, delay);
    }
  }
  function open(id, remember = true) {
    cancelRead(); sessionID = id; agentID = ''; tab = 'chat';
    showIdle = false; showInactive = false; fit = true; collapsed.clear();
    signature = targetSignature = chartSignature = listSignature = '';
    messageSignature = '';
    resize?.disconnect(); content.replaceChildren();
    if (id) { buildDetail(); composer.value = drafts.get(key()) ?? ''; }
    render(); void watch();
    node.classList.toggle('has-detail', !!id);
    if (remember) onNavigate(id);
  }
  function selectAgent(id) {
    agentID = id; tab = 'chat'; signature = ''; messageSignature = '';
    composer.value = drafts.get(key()) ?? '';
    renderDetail(); setTab('chat'); composer.focus();
  }
  function setTab(value) {
    tab = value; chat.hidden = value !== 'chat'; chart.hidden = value !== 'hierarchy';
    for (const tabButton of content.querySelectorAll('[data-workspace-tab]')) {
      tabButton.setAttribute('aria-pressed', String(tabButton.dataset.workspaceTab === value));
    }
    if (value === 'hierarchy') renderChart();
  }
  function render() {
    if (!sessionID) {
      const next = JSON.stringify([data?.sessions, data?.total, data?.truncated]);
      if (next === listSignature) return;
      listSignature = next; content.replaceChildren();
      const title = el('div', undefined, 'section-heading');
      title.append(el('h1', 'Sessions'), el('span', `${data?.total ?? 0} on your Mac`));
      content.append(title);
      if (!data?.sessions.length) content.append(el('p', 'No sessions reported. Connect an agent in Notify on your Mac.', 'empty'));
      for (const item of data?.sessions ?? []) {
        const row = button('', 'session-row', () => open(item.id));
        row.setAttribute('aria-label', `Open ${item.name}`);
        row.style.setProperty('--session-color', item.color);
        const text = el('span');
        text.append(el('strong', item.name), el('span', `${item.agent} · ${item.project}`, 'support'),
          el('span', item.connected ? `${item.state} · ${item.runningCount} running · ${item.idleCount} idle` : 'Not connected · Set up on Mac', 'support'));
        row.append(portrait(true, item.connected ? item.state : 'disconnected'), text);
        content.append(row);
      }
      if (data?.truncated) content.append(el('p', `Showing ${data.sessions.length} of ${data.total} sessions. See the full list on your Mac.`, 'support'));
    } else renderDetail();
  }
  function buildDetail() {
    const back = button('All sessions', 'back-button', () => open(null));
    heading = el('h1'); metadata = el('p', '', 'support');
    const header = el('header', undefined, 'workspace-heading'); header.append(back, heading, metadata);
    const tabs = el('nav', undefined, 'workspace-tabs'); tabs.setAttribute('aria-label', 'Session view');
    for (const [value, label] of [['chat', 'Chat'], ['hierarchy', 'Hierarchy']]) {
      const item = button(label, '', () => setTab(value));
      item.dataset.workspaceTab = value; item.setAttribute('aria-pressed', String(value === tab)); tabs.append(item);
    }
    chat = el('section', undefined, 'session-chat');
    const label = el('label', 'Chat with', 'target-label');
    target = el('select'); target.setAttribute('aria-label', 'Chat with');
    target.addEventListener('change', () => selectAgent(target.value)); label.append(target);
    feed = el('div', undefined, 'chat-feed'); feed.setAttribute('role', 'region'); feed.setAttribute('aria-label', 'Conversation');
    jumpLatest = button('Jump to latest', 'jump-latest', () => {
      jumpLatest.hidden = true; feed.scrollTop = feed.scrollHeight;
    });
    jumpLatest.hidden = true;
    feed.addEventListener('scroll', () => {
      if (feed.scrollHeight - feed.scrollTop - feed.clientHeight < 48) jumpLatest.hidden = true;
    });
    tools = el('details', undefined, 'reported-tools');
    toolFeed = el('div', undefined, 'tool-feed'); tools.append(el('summary', 'Tools & thinking'), toolFeed);
    const form = el('form', undefined, 'chat-composer');
    const inputLabel = el('label', 'Message', 'input-label');
    composer = el('textarea'); composer.maxLength = 16000; composer.setAttribute('aria-label', 'Message');
    composer.rows = 2;
    composer.placeholder = 'Give this agent an instruction…'; inputLabel.append(composer);
    composer.addEventListener('input', () => {
      const draftKey = key(), text = composer.value;
      const bytes = [...drafts.entries()].reduce((sum, [id, value]) => sum + (id === draftKey ? 0 : new TextEncoder().encode(value).length), 0);
      if ((!drafts.has(draftKey) && drafts.size >= 100) || bytes + new TextEncoder().encode(text).length > 524288) {
        composer.value = drafts.get(draftKey) ?? '';
        controlNote.textContent = 'Phone draft storage is full. Clear another draft before writing here.';
        return;
      }
      if (text) drafts.set(draftKey, text); else drafts.delete(draftKey);
      updateControls();
    });
    const actions = el('div', undefined, 'chat-actions');
    sendButton = button('Send', 'primary', () => prepare('queue'));
    interruptButton = button('Interrupt', '', () => prepare('interrupt'));
    stopButton = button('Stop main', 'deny', () => prepare('stop'));
    actions.append(sendButton, interruptButton, stopButton);
    controlNote = el('p', '', 'message'); controlNote.setAttribute('role', 'status');
    form.append(inputLabel, actions, controlNote);
    form.addEventListener('submit', event => { event.preventDefault(); prepare('queue'); });
    chat.append(label, feed, jumpLatest, tools, form);
    chart = el('section', undefined, 'session-hierarchy'); chart.hidden = true;
    content.append(header, tabs, chat, chart);
  }
  function unsupported(action) {
    if (!live()) return 'Reconnect with a fresh session before sending.';
    if (agentID) {
      if (detail().team?.error) return detail().team.error;
      if (!agent() || !['running', 'idle'].includes(agent().status)) return 'This subagent is unavailable or has ended. Its chat is read-only.';
      if (action === 'interrupt') return 'Interrupt applies only to the main agent.';
      if (!session().capabilities[action === 'stop' ? 'subagentStop' : 'subagentChat']) return 'This connection does not support this subagent control.';
    } else if (!session().capabilities.steering) return 'Messaging this connection is unavailable. Check its setup and supported controls on your Mac.';
    return null;
  }
  function updateControls() {
    if (!composer || !sessionID) return;
    const delivery = deliveries.get(key()), busy = !!delivery?.busy;
    composer.disabled = !live() || !!unsupported('queue') || busy;
    sendButton.disabled = busy || !!unsupported('queue') || !composer.value.trim();
    interruptButton.hidden = !!agentID;
    interruptButton.disabled = busy || !!unsupported('interrupt') || !composer.value.trim();
    stopButton.textContent = agentID ? 'Stop subagent' : 'Stop main';
    stopButton.disabled = busy || !!unsupported('stop');
    controlNote.classList.toggle('error', !!delivery?.error);
    controlNote.textContent = busy ? 'Waiting for agent acknowledgment…' :
      delivery?.error || delivery?.detail || unsupported('queue') || '';
  }
  function renderDetail() {
    const item = session(), selected = detail();
    heading.textContent = item?.name ?? 'Session unavailable';
    metadata.textContent = item ? `${item.agent} · ${item.project} · ${item.connected ? item.state : 'Not connected'}` : 'This session is no longer reported by your Mac.';
    content.style.setProperty('--session-color', item?.color ?? 'var(--accent)');
    const nextTargets = JSON.stringify(selected?.team?.agents ?? []);
    if (nextTargets !== targetSignature || !target.children.length) {
      targetSignature = nextTargets; target.replaceChildren();
      const main = el('option', 'Main agent'); main.value = ''; target.append(main);
      for (const child of selected?.team?.agents ?? []) {
        const option = el('option', `${child.name} · ${child.status}`); option.value = child.id;
        option.disabled = child.status === 'cancelled'; target.append(option);
      }
      if (agentID && !agent()) {
        const missing = el('option', 'Selected subagent unavailable'); missing.value = agentID; missing.disabled = true; target.append(missing);
      }
    }
    target.value = agentID;
    const receipt = deliveries.get(key());
    const ack = selected?.controls.find(control => control.id === receipt?.commandID);
    if (ack && !receipt.busy) { receipt.detail = ack.detail || ack.status; receipt.error = ['failed', 'unknown', 'cancelled'].includes(ack.status) ? receipt.detail : ''; }
    const next = JSON.stringify([selected?.activity, selected?.controls, selected?.truncated, agentID]);
    if (next !== signature) {
      signature = next; renderMessages(selected);
    }
    updateControls();
    if (tab === 'hierarchy') renderChart();
  }
  function copyButton(text) {
    const copy = button('Copy', 'copy-button', async () => {
      try { await navigator.clipboard.writeText(text); copy.textContent = 'Copied'; }
      catch { copy.textContent = 'Copy unavailable; select the text'; }
    });
    return copy;
  }
  function prose(text) {
    const body = el('div', undefined, 'message-body');
    const lines = text.split('\n'); let code = null;
    const flushCode = () => {
      const raw = code.join('\n'), block = el('div', undefined, 'chat-code');
      block.append(copyButton(raw), el('pre', raw)); body.append(block); code = null;
    };
    for (const line of lines) {
      if (/^```/.test(line)) { if (code) flushCode(); else code = []; }
      else if (code) code.push(line);
      else if (/^#{1,4} /.test(line)) body.append(el('h3', line.replace(/^#{1,4} /, '')));
      else body.append(el('p', line || '\u00a0'));
    }
    if (code) flushCode();
    return body;
  }
  function renderMessages(selected) {
    const atBottom = !messageSignature || feed.scrollHeight - feed.scrollTop - feed.clientHeight < 48, scroll = feed.scrollTop;
    feed.replaceChildren(); toolFeed.replaceChildren();
    if (!selected) { feed.append(el('p', 'Waiting for this session’s details…', 'empty')); return; }
    const activity = selected.activity.filter(item => (item.agentID ?? '') === agentID);
    const messages = activity.filter(item => ['user', 'assistant'].includes(item.kind));
    for (const control of selected.controls.filter(item => (item.agentID ?? '') === agentID && ['queue', 'interrupt'].includes(item.action))) {
      if (!messages.some(item => item.clientTurnID === control.id)) messages.push({
        ...control, kind: 'user', title: 'Your message', timestamp: control.createdAt, detail: control.message,
        delivery: control.detail || control.status
      });
    }
    messages.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    const latest = messages.at(-1);
    const nextSignature = JSON.stringify([latest?.id, latest?.detail, latest?.delivery]);
    if (atBottom) jumpLatest.hidden = true;
    else if (messageSignature !== nextSignature) jumpLatest.hidden = false;
    messageSignature = nextSignature;
    if (selected.truncated) feed.append(el('p', 'Showing recent reported messages. Earlier history is on your Mac.', 'support'));
    if (!messages.length) feed.append(el('p', 'No messages reported for this agent yet.', 'empty'));
    for (const message of messages) {
      const article = el('article', undefined, `chat-message ${message.kind}`);
      const header = el('div', undefined, 'message-heading');
      header.append(el('strong', message.kind === 'user' ? 'You' : name()), copyButton(message.detail));
      article.append(header, prose(message.detail));
      if (message.delivery) article.append(el('p', message.delivery, 'support'));
      feed.append(article);
    }
    feed.scrollTop = atBottom ? feed.scrollHeight : scroll;
    const other = activity.filter(item => !['user', 'assistant'].includes(item.kind));
    tools.querySelector('summary').textContent = `Tools & thinking · ${other.length}`;
    if (!other.length) toolFeed.append(el('p', 'No tool or thinking updates reported for this agent.', 'support'));
    for (const item of other.slice(-12)) {
      const section = el('section', undefined, 'tool-entry');
      const header = el('div', undefined, 'message-heading');
      header.append(el('strong', `${item.kind === 'reasoning' ? 'Thinking' : item.kind === 'tool' ? 'Tool' : 'Status'} · ${item.title}`), copyButton(item.detail));
      section.append(header, el('pre', item.detail, 'activity-preview')); toolFeed.append(section);
    }
    if (other.length > 12) toolFeed.append(el('p', 'Showing the latest 12 activity entries.', 'support'));
  }
  function prepare(action) {
    if (unsupported(action) || deliveries.get(key())?.busy || (action !== 'stop' && !composer.value.trim())) return;
    const payload = { id: crypto.randomUUID(), sessionID, ticket: session().ticket, action,
      text: action === 'stop' ? '' : composer.value, ...(agentID ? { agentID } : {}) };
    const destination = key();
    if (action === 'queue') { void dispatch(payload, destination); return; }
    dialog = el('dialog', undefined, 'control-confirmation');
    const title = el('h2', action === 'stop' ? `Stop ${name()}?` : 'Interrupt the main agent?');
    title.id = 'phone-control-title'; dialog.setAttribute('aria-labelledby', title.id);
    dialog.append(title, el('p', action === 'stop'
      ? agentID ? 'This stops the selected subagent. Its descendants may also stop. Other agents are not selected.'
        : 'This stops the current main-agent turn. It does not delete the session.'
      : 'Stop the current main-agent turn and send your instruction instead.', 'support'));
    const controls = el('div', undefined, 'button-row');
    const close = () => { dialog?.close(); dialog?.remove(); dialog = undefined; };
    const cancel = button('Cancel', '', close);
    controls.append(cancel, button(action === 'stop' ? 'Stop' : 'Interrupt', 'deny', () => {
      close(); void dispatch(payload, destination);
    }));
    dialog.addEventListener('cancel', close);
    dialog.append(controls); node.append(dialog); dialog.showModal(); cancel.focus();
  }
  async function dispatch(payload, destination) {
    if (payload.sessionID !== sessionID || payload.ticket !== session()?.ticket ||
      (payload.agentID ?? '') !== agentID || unsupported(payload.action)) {
      deliveries.set(destination, { error: 'This session changed. Review it again before sending.' }); updateControls(); return;
    }
    const delivery = { busy: true }; deliveries.set(destination, delivery); updateControls();
    try {
      const result = await api('control', payload);
      if (disposed) return;
      delivery.commandID = result.commandID; delivery.detail = result.detail || `Agent acknowledged: ${result.status}.`;
      if (payload.action !== 'stop' && drafts.get(destination) === payload.text) {
        drafts.delete(destination); if (key() === destination) composer.value = '';
      }
    } catch (error) {
      if (disposed) return;
      delivery.error = error.message;
      if (error.status === 401) { onUnauthorized(error.message); return; }
      if (error.network) onNetworkError();
    } finally { delivery.busy = false; if (!disposed && key() === destination) updateControls(); }
  }
  function renderChart() {
    const selected = detail();
    const next = JSON.stringify([selected?.team, session()?.state, agentID, showIdle, showInactive, [...collapsed]]);
    if (next === chartSignature) { chartFrame?.(); return; }
    chartSignature = next; resize?.disconnect(); chart.replaceChildren();
    if (!selected) { chart.append(el('p', 'Waiting for the reported team…', 'empty')); return; }
    chart.append(el('p', 'Select an agent to chat. Only reported parent relationships are connected.', 'support'));
    const toolbar = el('div', undefined, 'chart-toolbar');
    toolbar.append(button('Fit', '', () => { fit = true; chartFrame(); }),
      button('100%', '', () => { fit = false; chartFrame(); }));
    if (showIdle) toolbar.append(button('Hide idle', '', () => { showIdle = false; fit = true; renderChart(); }));
    chart.append(toolbar);
    const viewport = el('div', undefined, 'chart-viewport'); viewport.tabIndex = 0; viewport.setAttribute('aria-label', 'Scrollable agent hierarchy');
    const scaled = el('div', undefined, 'chart-scaled'), natural = el('div', undefined, 'org-chart');
    scaled.append(natural); viewport.append(scaled); chart.append(viewport);
    const agents = selected.team?.agents ?? [], records = new Map(agents.map(item => [item.id, item]));
    const idle = agents.filter(item => item.status === 'idle');
    const ended = agents.filter(item => !['running', 'idle'].includes(item.status));
    const hidden = new Set([...(!showIdle ? idle : []), ...(!showInactive ? ended : [])].map(item => item.id));
    const children = new Map(), roots = [], unlinked = [];
    function cyclic(item) {
      const seen = new Set([item.id]); let current = item;
      while (current.parentAgentID && records.has(current.parentAgentID)) {
        if (seen.has(current.parentAgentID)) return true;
        seen.add(current.parentAgentID); current = records.get(current.parentAgentID);
      }
      return false;
    }
    for (const item of agents.filter(item => !hidden.has(item.id))) {
      if (!item.parentKnown || cyclic(item)) unlinked.push(item);
      else if (!item.parentAgentID) roots.push(item);
      else if (!records.has(item.parentAgentID) || hidden.has(item.parentAgentID)) unlinked.push(item);
      else {
        if (!children.has(item.parentAgentID)) children.set(item.parentAgentID, []);
        children.get(item.parentAgentID).push(item);
      }
    }
    function tile(item) {
      const main = !item, id = item?.id ?? '', label = main ? 'Main agent' : item.name;
      const state = item?.status ?? session()?.state ?? 'disconnected';
      const tileButton = button('', `agent-tile ${main ? 'main-agent' : ''}`, () => selectAgent(id));
      tileButton.dataset.agentId = id; tileButton.setAttribute('aria-label', `Chat with ${label}`);
      tileButton.disabled = state === 'cancelled';
      tileButton.setAttribute('aria-pressed', String(id === agentID));
      tileButton.append(portrait(main, state), el('strong', label), el('span', state, 'support'));
      if (item?.task) tileButton.append(el('span', item.task, 'agent-task'));
      return tileButton;
    }
    function branch(item) {
      const row = el('li', undefined, 'tree-branch');
      row.append(tile(item));
      const descendants = children.get(item.id) ?? [];
      if (descendants.length) {
        const toggle = button(collapsed.has(item.id) ? `Show ${descendants.length} branches` : 'Hide branches', 'branch-toggle', () => {
          if (collapsed.has(item.id)) collapsed.delete(item.id); else collapsed.add(item.id);
          renderChart();
        });
        toggle.setAttribute('aria-expanded', String(!collapsed.has(item.id))); row.append(toggle);
        if (!collapsed.has(item.id)) {
          const list = el('ul', undefined, 'tree-children'); for (const child of descendants) list.append(branch(child)); row.append(list);
        }
      }
      return row;
    }
    const tree = el('ul', undefined, 'tree-root'), main = el('li', undefined, 'tree-branch main-branch');
    main.append(tile(null)); tree.append(main); natural.append(tree);
    const childList = el('ul', undefined, 'tree-children');
    for (const root of roots) childList.append(branch(root));
    const groupedAtMain = idle.every(item => item.parentKnown && !item.parentAgentID);
    if (idle.length && !showIdle) {
      const group = button('', 'agent-tile idle-group', () => { showIdle = true; fit = true; renderChart(); });
      group.setAttribute('aria-label', `+${idle.length} idle subagents`);
      group.setAttribute('aria-expanded', 'false');
      group.append(portrait(false, 'idle'), el('strong', `+${idle.length} idle subagents`), el('span', 'Expand', 'support'));
      if (groupedAtMain) { const row = el('li', undefined, 'tree-branch'); row.append(group); childList.append(row); }
      else {
        const separate = el('section', undefined, 'unlinked-group');
        separate.append(el('p', 'Idle agents · mixed or unreported parents', 'support'), group); natural.append(separate);
      }
    }
    if (childList.children.length) main.append(childList);
    for (const root of unlinked) {
      const section = el('section', undefined, 'unlinked-group');
      const reason = cyclic(root) ? 'Parent relationship is cyclic' : root.parentAgentID
        ? `Parent: ${records.get(root.parentAgentID)?.name ?? root.parentAgentID}` : 'Parent not reported';
      const list = el('ul', undefined, 'tree-root'); list.append(branch(root));
      section.append(el('p', reason, 'support'), list); natural.append(section);
    }
    if (ended.length) chart.append(button(showInactive ? 'Hide inactive subagents' : `+${ended.length} inactive subagent${ended.length === 1 ? '' : 's'}`, 'inactive-group', () => {
      showInactive = !showInactive; fit = true; renderChart();
    }));
    if (!selected.team) chart.append(el('p', 'This connection does not report its subagent team.', 'support'));
    if (selected.team?.error) chart.append(el('p', selected.team.error, 'message error'));
    if (selected.team?.truncated) chart.append(el('p', 'Only part of this team is reported. Counts can include helpers not shown.', 'support'));
    chartFrame = () => {
      if (chart.hidden || disposed) return;
      const width = natural.offsetWidth, height = natural.offsetHeight;
      if (!width || !height) return;
      const scale = fit ? Math.min(1, Math.max(1, viewport.clientWidth - 16) / width, 380 / height) : 1;
      natural.style.transform = `scale(${scale})`;
      scaled.style.width = `${width * scale}px`; scaled.style.height = `${height * scale}px`;
      if (fit) { viewport.scrollLeft = 0; viewport.scrollTop = 0; }
    };
    resize = new ResizeObserver(chartFrame); resize.observe(viewport); chartFrame();
  }
  return {
    node,
    selectSession(id) { open(id, false); },
    setVisible(value) {
      visible = value; node.hidden = !value; node.classList.toggle('workspace-paused', !value);
      if (!value) cancelRead(); else { updateControls(); void watch(); }
    },
    setConnected(value) {
      if (connected === value) return;
      connected = value;
      if (!value) cancelRead(); else void watch();
      updateControls();
    },
    clear() {
      disposed = true; cancelRead(); resize?.disconnect(); dialog?.close(); dialog?.remove();
      drafts.clear(); deliveries.clear(); data = undefined; node.replaceChildren();
    }
  };
}
