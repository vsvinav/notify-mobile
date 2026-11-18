import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { NativeCrypto } from '../src/remote-crypto.mjs';

test('crypto pipe correlates responses and rejects pending calls on exit without retry', async () => {
  const root = join(process.cwd(), '.test-data');
  await mkdir(root, { recursive: true });
  const dir = await mkdtemp(join(root, 'crypto-pipe-'));
  const fixture = join(dir, 'fixture.mjs');
  await writeFile(fixture, `
    import { createInterface } from 'node:readline';
    for await (const line of createInterface({input:process.stdin})) {
      const request = JSON.parse(line);
      if(request.op==='exit') process.exit(1);
      process.stdout.write(JSON.stringify({result:request.bytes})+'\\n');
    }
  `);
  const crypto = new NativeCrypto(process.execPath, [fixture]);
  try {
    assert.deepEqual(await crypto.call('send', { bytes: [1, 2] }), [1, 2]);
    assert.deepEqual(await crypto.call('send', { bytes: [3] }), [3]);
    await assert.rejects(crypto.call('exit'), /closed|exited/i);
    assert.equal(crypto.failed, true, 'A retired pipe must be detectable before starting a new authorization attempt');
    await assert.rejects(crypto.call('send', { bytes: [4] }), /closed|exited/i);
  } finally {
    await crypto.close();
    await rm(dir, { recursive: true });
  }
});
