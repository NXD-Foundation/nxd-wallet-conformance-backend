const DEFAULT_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const DEFAULT_REFRESH_LEAD_MS = 5 * 60 * 1000;
const DEFAULT_MAX_ENTRIES = 64;

function validityDeadline(snapshot) {
  const updates = [snapshot?.lotl, ...Object.values(snapshot?.lists || {}).flatMap((value) => Array.isArray(value) ? value : [value])]
    .map((list) => Date.parse(list?.scheme?.nextUpdate || ""))
    .filter(Number.isFinite);
  return updates.length ? Math.min(...updates) : 0;
}

export function createAuthenticatedSnapshotCache({ clock = Date.now, maxAgeMs = DEFAULT_MAX_AGE_MS, refreshLeadMs = DEFAULT_REFRESH_LEAD_MS, maxEntries = DEFAULT_MAX_ENTRIES } = {}) {
  const entries = new Map();

  function schedule(key, entry, load) {
    if (entry.timer) clearTimeout(entry.timer);
    const delay = Math.max(0, entry.refreshAt - clock());
    entry.timer = setTimeout(() => {
      entry.timer = null;
      refresh(key, entry, load).catch(() => {});
    }, delay);
    entry.timer.unref?.();
  }

  async function refresh(key, entry, load) {
    if (entry.promise) return entry.promise;
    entry.promise = Promise.resolve().then(load).then((snapshot) => {
      const now = clock();
      const validUntil = validityDeadline(snapshot);
      if (!validUntil || validUntil <= now) throw new Error("Authenticated trust snapshot has no future validity deadline");
      entry.snapshot = snapshot;
      entry.expiresAt = Math.min(validUntil, now + maxAgeMs);
      entry.refreshAt = Math.max(now, entry.expiresAt - refreshLeadMs);
      entry.promise = null;
      schedule(key, entry, load);
      return snapshot;
    }).catch((error) => {
      entry.promise = null;
      throw error;
    });
    return entry.promise;
  }

  return {
    async get(key, load) {
      if (typeof load !== "function") throw new TypeError("Trust snapshot loader is required");
      let entry = entries.get(key);
      if (!entry) {
        entry = { snapshot: null, expiresAt: 0, refreshAt: 0, promise: null, timer: null };
        entries.set(key, entry);
        while (entries.size > maxEntries) {
          const [oldestKey, oldest] = entries.entries().next().value;
          if (oldest.timer) clearTimeout(oldest.timer);
          entries.delete(oldestKey);
        }
      } else {
        entries.delete(key);
        entries.set(key, entry);
      }
      const now = clock();
      if (entry.snapshot && now < entry.refreshAt) return entry.snapshot;
      try {
        return await refresh(key, entry, load);
      } catch (error) {
        if (entry.snapshot && now < entry.expiresAt) return entry.snapshot;
        throw error;
      }
    },
    clear() {
      for (const entry of entries.values()) if (entry.timer) clearTimeout(entry.timer);
      entries.clear();
    },
    size() { return entries.size; },
  };
}
