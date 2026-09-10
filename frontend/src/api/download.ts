/** Trigger a browser download for an in-memory Blob (CSV exports). */
export function downloadBlob(data: Blob, filename: string): void {
  const url = URL.createObjectURL(data)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/** YYYY-MM-DD stamp for export filenames. */
export function todayStamp(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10)
}
