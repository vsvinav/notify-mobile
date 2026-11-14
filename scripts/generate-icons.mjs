import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';

function crc(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ (value & 1 ? 0xedb88320 : 0);
  }
  return (value ^ 0xffffffff) >>> 0;
}
function chunk(type, bytes) {
  const name = Buffer.from(type), length = Buffer.alloc(4), checksum = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length); checksum.writeUInt32BE(crc(Buffer.concat([name, bytes])));
  return Buffer.concat([length, name, bytes, checksum]);
}
for (const size of [192, 512]) {
  const image = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const u = x / size, v = y / size;
      const bell = ((u - .5) ** 2 / .19 ** 2 + (v - .42) ** 2 / .21 ** 2 < 1 && v < .5) ||
        (u > .31 && u < .69 && v >= .4 && v < .61) ||
        (u > .26 && u < .74 && v >= .61 && v < .66) ||
        ((u - .5) ** 2 + (v - .72) ** 2 < .045 ** 2) ||
        ((u - .5) ** 2 + (v - .22) ** 2 < .045 ** 2);
      const color = bell ? [52, 48, 42] : [240, 232, 220];
      const offset = y * (size * 4 + 1) + x * 4 + 1;
      image.set([...color, 255], offset);
    }
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0); header.writeUInt32BE(size, 4); header[8] = 8; header[9] = 6;
  writeFileSync(new URL(`../public/icon-${size}.png`, import.meta.url),
    Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('IDAT', deflateSync(image)), chunk('IEND', Buffer.alloc(0))]));
}
