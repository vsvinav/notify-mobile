import { networkInterfaces } from 'node:os';

export function privateIPv4(address) {
  const bytes = address.split('.').map(Number);
  if (bytes.length !== 4 || bytes.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return bytes[0] === 10 || (bytes[0] === 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
    (bytes[0] === 192 && bytes[1] === 168);
}

export function selectNetwork() {
  for (const [name, addresses] of Object.entries(networkInterfaces())) {
    if (/^(utun|tun|tap|lo|docker|bridge|vbox|vmnet)/.test(name)) continue;
    const network = addresses.find(item => item.family === 'IPv4' && !item.internal && privateIPv4(item.address));
    if (network) return { address: network.address, netmask: network.netmask, name };
  }
  throw new Error('No private IPv4 LAN connection. Connect the Mac and phone to the same Wi-Fi, then enable mobile again.');
}

const number = ip => ip.split('.').reduce((n, byte) => (n * 256 + Number(byte)) >>> 0, 0);
export function sameSubnet(peer, network) {
  if (!peer || !/^\d+\.\d+\.\d+\.\d+$/.test(peer)) return false;
  return (number(peer) & number(network.netmask)) === (number(network.address) & number(network.netmask));
}

export function networkPresent(network) {
  return Object.values(networkInterfaces()).flat().some(item => item.address === network.address && item.netmask === network.netmask);
}
