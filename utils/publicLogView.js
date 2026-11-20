/** Keep complete protocol evidence while giving log readers a short event summary. */
export function toPublicLogEntry(entry) {
  if (!entry || typeof entry.message !== "string") return entry;
  const firstLine = entry.message.split(/\r?\n/, 1)[0].trim();
  const summary = firstLine.length > 240 ? `${firstLine.slice(0, 239)}…` : firstLine;
  if (summary === entry.message) return entry;
  return { ...entry, message: summary, detail: entry.message };
}

export function toPublicLogs(logs) {
  return logs?.map(toPublicLogEntry) ?? logs;
}
