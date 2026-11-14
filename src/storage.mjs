import { constants } from 'node:fs';
import { mkdir, lstat, chmod, open, rename, unlink } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { randomUUID } from 'node:crypto';

export async function privateDirectory(directory) {
  if (!isAbsolute(directory)) throw new Error('Mobile data directory must be absolute.');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.()) {
    throw new Error('Mobile data directory must be owned by this user and cannot be a symlink.');
  }
  await chmod(directory, 0o700);
}

export async function readPrivate(file) {
  let handle;
  try {
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || info.nlink !== 1 || info.uid !== process.getuid?.() || info.size > 2_097_152) {
      throw new Error('Invalid mobile data file. Disable mobile and inspect its data directory.');
    }
    await handle.chmod(0o600);
    return await handle.readFile();
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  } finally {
    await handle?.close();
  }
}

export async function writePrivate(file, content) {
  const temporary = `${file}.${randomUUID()}.new`;
  const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    await handle.writeFile(content);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, file);
  } catch (error) {
    await unlink(temporary);
    throw error;
  }
}

export function stateStore(directory) {
  const path = join(directory, 'state.json');
  let writes = Promise.resolve();
  return {
    read: async () => {
      const data = await readPrivate(path);
      return data === null ? null : JSON.parse(data.toString());
    },
    write: state => {
      const data = JSON.stringify(state);
      const next = writes.then(() => writePrivate(path, data));
      // A failed save is reported to its caller; later saves must still be attempted.
      writes = next.then(() => undefined, () => undefined);
      return next;
    }
  };
}
