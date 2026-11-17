import test from 'node:test';
import assert from 'node:assert/strict';
import { localLease } from '../public/remote-lease.mjs';

const start = { wall: 1800000000000, mono: 1000 };
const grant = { expiresAt: start.wall + 30019, validForMs: 30000 };
test('bounded remaining validity is anchored before HTTP and consumes wall and monotonic latency', () => {
  const result = localLease(grant, start, { wall: start.wall + 900, mono: 2100 });
  assert.equal(result.expiresAt, start.wall + 30000);
  assert.equal(result.deadline, 31000);
  assert.equal(result.remaining, 28900);
  assert.equal(localLease({ expiresAt: start.wall - 1000, validForMs: 30000 }, start, start).deadline, 31000,
    'Server wall time is not a local clock');
  assert.throws(() => localLease(grant, start, { wall: start.wall + 30000, mono: 31000 }));
  assert.throws(() => localLease(grant, start, { wall: start.wall + 10, mono: 31000 }));
  assert.throws(() => localLease(grant, start, { wall: start.wall + 30000, mono: 1010 }));
});
test('explicit invalid duration never falls back to the legacy timestamp', () => {
  for (const validForMs of [null, 0, -1, 30001, 1.5, '30000', true, NaN, Infinity])
    assert.throws(() => localLease({ expiresAt: start.wall + 30000, validForMs }, start, start));
  for (const expiresAt of [null, 0, -1, '1800000030000', 1.5, Number.MAX_SAFE_INTEGER + 1])
    assert.throws(() => localLease({ ...grant, expiresAt }, start, start));
  assert.throws(() => localLease(grant, start, { wall: start.wall - 1, mono: 1001 }));
  assert.throws(() => localLease(grant, start, { wall: start.wall + 1, mono: 999 }));
});
test('pending short validity and legacy responses cannot gain transport time', () => {
  const current = { wall: start.wall + 900, mono: 1900 };
  assert.equal(localLease({ ...grant, validForMs: 1000 }, start, current).remaining, 100);
  assert.throws(() => localLease({ ...grant, validForMs: 900 }, start, current));
  assert.equal(localLease({ expiresAt: start.wall + 30900 }, start, current).remaining, 29100);
  assert.throws(() => localLease({ expiresAt: start.wall + 30901 }, start, current));
});
