// Synthetic transaction seam, not a Firestore emulator or live-service acceptance test.
export function firestoreFixture() {
  const documents = new Map();
  const metrics = { reads: 0, writes: 0, transactions: 0 };
  let serial = Promise.resolve(), unavailable = false, failureCode, beforeCommit, afterCommit;
  const snapshot = ref => {
    if (unavailable) throw Object.assign(new Error('Synthetic storage failure'), { code: failureCode });
    metrics.reads++;
    const value = documents.get(ref.path);
    return { exists: value !== undefined, data: () => structuredClone(value) };
  };
  const firestore = {
    doc: path => ({ path, get: async () => snapshot({ path }) }),
    runTransaction(operation) {
      metrics.transactions++;
      const next = serial.then(async () => {
        const writes = [];
        const result = await operation({
          get: async ref => snapshot(ref),
          set: (ref, value) => writes.push([ref.path, structuredClone(value)])
        });
        if (beforeCommit) await beforeCommit();
        if (unavailable) throw Object.assign(new Error('Synthetic storage failure'), { code: failureCode });
        for (const [path, value] of writes) { documents.set(path, value); metrics.writes++; }
        await afterCommit?.(writes);
        return result;
      });
      serial = next.then(() => {}, () => {});
      return next;
    }
  };
  return { firestore, documents, metrics,
    fail: (value, code) => { unavailable = value; failureCode = code; },
    beforeCommit: callback => { beforeCommit = callback; },
    afterCommit: callback => { afterCommit = callback; } };
}
