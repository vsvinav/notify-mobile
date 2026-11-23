const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value, max = 65535) => typeof value === 'string' && value.length <= max;
const nonempty = (value, max) => text(value, max) && value.length > 0;
export { object };

export function attentionProjection(value) {
  const id = v => nonempty(v, 128) && !v.includes('\0');
  if (!object(value) || value.version !== 1 ||
    typeof value.epoch !== 'string' || !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value.epoch) ||
    !Number.isSafeInteger(value.revision) || value.revision < 1 ||
    !Number.isInteger(value.additionalCount) || value.additionalCount < 0 || value.additionalCount > 256) return;
  const c = value.current;
  if (c === null ? value.additionalCount !== 0 :
    !object(c) || !id(c.sessionID) || !id(c.requestID) || !text(c.sessionName, 256) ||
    !nonempty(c.requestTitle, 300) || c.sessionName.includes('\0') || c.requestTitle.includes('\0')) return;
  return { version: 1, epoch: value.epoch, revision: value.revision,
    current: c === null ? null : { sessionID: c.sessionID, requestID: c.requestID,
      sessionName: c.sessionName, requestTitle: c.requestTitle }, additionalCount: value.additionalCount };
}

export function validSnapshot(message) {
  if (!Array.isArray(message.requests) || message.requests.length > 256 ||
    !Number.isSafeInteger(message.total) || message.total !== message.requests.length) return false;
  const identities = new Set();
  return message.requests.every(item => {
    if (!object(item) || !nonempty(item.sessionID, 128) || !nonempty(item.ticket, 256) ||
      !nonempty(item.notificationID, 512) || !text(item.sessionName) || !text(item.project) || !text(item.agent, 128) ||
      !/^#[a-fA-F0-9]{6}$/.test(item.color) || typeof item.sending !== 'boolean' ||
      (item.error !== undefined && !text(item.error)) || !Array.isArray(item.fields) || item.fields.length > 256) return false;
    const r = item.request;
    if (!object(r) || !nonempty(r.id, 128) || !nonempty(r.title) || !text(r.detail) ||
      !['permission', 'question'].includes(r.kind) || !Array.isArray(r.questions) || r.questions.length > 64) return false;
    const identity = `${item.sessionID}\0${r.id}`;
    if (identities.has(identity)) return false;
    identities.add(identity);
    if (r.kind === 'question' && r.questions.length === 0) return false;
    const ids = new Set();
    if (!r.questions.every(q => {
      if (!object(q) || !nonempty(q.id, 128) || ids.has(q.id) || !text(q.text) ||
        typeof q.multiple !== 'boolean' || typeof q.allowFreeform !== 'boolean' ||
        (q.required !== undefined && q.required !== null && typeof q.required !== 'boolean') ||
        (q.minimumSelections != null && (!Number.isInteger(q.minimumSelections) || q.minimumSelections < 0)) ||
        !Array.isArray(q.options) || q.options.length > 128 ||
        !q.options.every(o => object(o) && nonempty(o.label) && text(o.description))) return false;
      ids.add(q.id); return true;
    })) return false;
    const scopes = r.permissionOptions ?? [];
    if (!Array.isArray(scopes) || scopes.length > 12 || (scopes.length && r.kind !== 'permission') ||
      new Set(scopes.map(o => o.id)).size !== scopes.length ||
      !scopes.every(o => object(o) && nonempty(o.id, 128) && nonempty(o.label, 300) && text(o.detail, 4000))) return false;
    return item.fields.every(f => object(f) && Number.isSafeInteger(f.id) && text(f.label) && text(f.value, 1_048_576) &&
      ['text', 'code', 'diff', 'warning'].includes(f.presentation) &&
      (f.target === undefined || f.target === null || ['Command', 'URL', 'URI', 'File', 'Path'].includes(f.target)));
  });
}

export function validReply(request, body) {
  if (!object(body) || !object(body.answers) || !['allow', 'deny', 'answer'].includes(body.decision)) return false;
  if (body.feedback !== undefined && !(request.kind === 'permission' && request.supportsFeedback === true &&
    body.decision === 'deny' && nonempty(body.feedback, 4000) && body.feedback.trim())) return false;
  if (body.permissionOptionID !== undefined && !(request.kind === 'permission' && body.decision === 'allow' &&
    request.permissionOptions?.some(option => option.id === body.permissionOptionID))) return false;
  if (Object.keys(body.answers).some(key => !request.questions.some(q => q.id === key))) return false;
  if (body.decision === 'deny') return Object.keys(body.answers).length === 0;
  if (request.kind === 'permission') return body.decision === 'allow' && Object.keys(body.answers).length === 0;
  if (body.decision !== 'answer') return false;
  return request.questions.every(q => {
    const values = body.answers[q.id];
    if (q.required === false && (values === undefined || (Array.isArray(values) && values.length === 0))) return true;
    return Array.isArray(values) && values.length >= (q.multiple ? q.minimumSelections ?? 1 : 1) &&
      (q.multiple || values.length === 1) && values.length <= 128 &&
      new Set(values).size === values.length && values.every(value => nonempty(value, 65535) && value.trim() &&
        (q.allowFreeform || q.options.some(option => option.label === value)));
  });
}
