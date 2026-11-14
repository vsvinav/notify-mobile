import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { X509Certificate, randomBytes } from 'node:crypto';
import { chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { readPrivate, writePrivate } from './storage.mjs';

const execute = promisify(execFile);
async function openssl(args) {
  try {
    await execute('/usr/bin/openssl', args, {
      env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '1' },
      timeout: 60_000, maxBuffer: 64 * 1024
    });
  } catch {
    throw new Error('Local certificate generation failed. /usr/bin/openssl must support critical nameConstraints; no unconstrained fallback is used.');
  }
}

export async function certificates(directory, address, testOnlyLoopback = false) {
  const file = name => join(directory, name);
  const root = file('ca.pem'), rootKey = file('ca-key.pem');
  // OpenSSL writes paths itself; reject linked destinations before invoking it.
  for (const name of ['ca-key.pem', 'server-key.pem', 'server.csr']) await readPrivate(file(name));
  let ca = await readPrivate(root);
  if (!ca) {
    if (await readPrivate(rootKey)) throw new Error('Incomplete certificate authority. Inspect mobile data before generating a new authority.');
    const config = [
      '[req]', 'distinguished_name=dn', 'x509_extensions=ca', 'prompt=no',
      '[dn]', 'CN=Notify Local Certificate Authority',
      '[ca]', 'basicConstraints=critical,CA:true,pathlen:0', 'keyUsage=critical,keyCertSign,cRLSign',
      'extendedKeyUsage=serverAuth', 'subjectKeyIdentifier=hash', 'authorityKeyIdentifier=keyid:always',
      `nameConstraints=critical,permitted;DNS:.local,permitted;IP:10.0.0.0/255.0.0.0,permitted;IP:172.16.0.0/255.240.0.0,permitted;IP:192.168.0.0/255.255.0.0${testOnlyLoopback ? ',permitted;IP:127.0.0.0/255.0.0.0' : ''}`
    ].join('\n');
    await writePrivate(file('ca.cnf'), config);
    await openssl(['req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '365',
      '-keyout', rootKey, '-out', root, '-config', file('ca.cnf')]);
    await chmod(rootKey, 0o600); await chmod(root, 0o600);
    ca = await readPrivate(root);
  }
  const authority = new X509Certificate(ca);
  if (Date.parse(authority.validTo) < Date.now() + 86_400_000) {
    throw new Error('Local certificate authority expires soon. Remove its trust from phones and reset mobile certificates manually.');
  }
  const certPath = file('server.pem'), keyPath = file('server-key.pem');
  let cert = await readPrivate(certPath);
  if (!cert || !new X509Certificate(cert).checkIP(address) ||
    Date.parse(new X509Certificate(cert).validTo) < Date.now() + 7 * 86_400_000) {
    // A new address or expiring leaf does not change the phone's trusted authority.
    const config = [
      '[req]', 'distinguished_name=dn', 'prompt=no', '[dn]', 'CN=Notify LAN',
      '[server]', 'basicConstraints=critical,CA:false', 'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth', `subjectAltName=IP:${address}`
    ].join('\n');
    await writePrivate(file('server.cnf'), config);
    await openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
      '-keyout', keyPath, '-out', file('server.csr'), '-config', file('server.cnf')]);
    await openssl(['x509', '-req', '-in', file('server.csr'), '-CA', root, '-CAkey', rootKey,
      '-set_serial', `0x${randomBytes(16).toString('hex')}`, '-days', '90', '-sha256',
      '-extfile', file('server.cnf'), '-extensions', 'server', '-out', certPath]);
    await chmod(keyPath, 0o600); await chmod(certPath, 0o600); await chmod(file('server.csr'), 0o600);
    cert = await readPrivate(certPath);
  }
  const key = await readPrivate(keyPath);
  if (!key) throw new Error('Local HTTPS private key is missing. Disable mobile and inspect the data directory.');
  return { ca, key, cert, fingerprint: authority.fingerprint256 };
}
