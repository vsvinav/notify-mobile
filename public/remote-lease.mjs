export const leaseStart = () => ({ wall: Date.now(), mono: performance.now() });

// Anchor before HTTP: subtracting the entire round trip is conservative even
// when the server issued its lease partway through that request.
export function localLease(value, start, now = leaseStart()) {
  const fail = () => { throw new Error('Invalid or expired channel authorization lifetime.'); };
  if (!Number.isSafeInteger(value?.expiresAt) || value.expiresAt <= 0 ||
    !Number.isSafeInteger(start?.wall) || start.wall < 0 ||
    !Number.isSafeInteger(now.wall) || now.wall < start.wall ||
    !Number.isFinite(start.mono) || start.mono < 0 ||
    !Number.isFinite(now.mono) || now.mono < start.mono) fail();
  let expiresAt;
  if (Object.hasOwn(value, 'validForMs')) {
    if (!Number.isSafeInteger(value.validForMs) || value.validForMs <= 0 || value.validForMs > 30000) fail();
    expiresAt = start.wall + value.validForMs;
  } else {
    if (value.expiresAt <= now.wall || value.expiresAt > now.wall + 30000) fail();
    expiresAt = Math.min(value.expiresAt, start.wall + 30000);
  }
  const deadline = start.mono + (expiresAt - start.wall);
  const remaining = Math.floor(Math.min(expiresAt - now.wall, deadline - now.mono));
  if (!Number.isSafeInteger(expiresAt) || !Number.isFinite(deadline) || remaining <= 0 || remaining > 30000) fail();
  return { expiresAt, deadline, remaining };
}
