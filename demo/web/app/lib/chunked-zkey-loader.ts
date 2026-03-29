import localforage from 'localforage'

/**
 * Section suffixes for a standard Groth16 zkey (10 sections).
 * Section IDs 1-10 map to suffixes b-k via sectionName(id) = String.fromCharCode('a' + id).
 */
export const SECTION_SUFFIXES = ['b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k'] as const

type ProgressCallback = (detail: string) => void

/**
 * Check whether all section chunk files for a circuit are cached in localforage.
 */
export async function areChunksReady(circuitName: string): Promise<boolean> {
  for (const suffix of SECTION_SUFFIXES) {
    const key = `${circuitName}.zkey${suffix}`
    const item = await localforage.getItem(key)
    if (item === null) return false
  }
  return true
}

/**
 * Download missing chunk files from a remote URL and store them in localforage.
 *
 * @param circuitName - e.g. "ecdsa_verify"
 * @param urlSource - either a base URL string (chunks fetched as `${base}/${key}`)
 *                    or a Record mapping chunk keys to their full URLs (for CDN-hosted files)
 * @param suffixes - which section suffixes to download (defaults to all 10)
 * @param onProgress - optional callback for UI progress
 */
export async function downloadChunks(
  circuitName: string,
  urlSource: string | Record<string, string>,
  suffixes: readonly string[] = SECTION_SUFFIXES,
  onProgress?: ProgressCallback,
): Promise<void> {
  const total = suffixes.length
  let downloaded = 0

  for (const suffix of suffixes) {
    const key = `${circuitName}.zkey${suffix}`

    const cached = await localforage.getItem(key)
    if (cached !== null) {
      downloaded++
      continue
    }

    const url = typeof urlSource === 'string' ? `${urlSource}/${key}` : urlSource[key]
    if (!url) {
      onProgress?.(`Skipping ${key} — no URL configured`)
      continue
    }
    onProgress?.(`Downloading chunk ${downloaded + 1}/${total} (${key})...`)

    const buffer = await fetchWithRetry(url, 3)
    await localforage.setItem(key, buffer)
    downloaded++
    onProgress?.(`Cached ${key} (${downloaded}/${total})`)
  }
}

async function fetchWithRetry(url: string, maxRetries: number): Promise<ArrayBuffer> {
  let lastError: Error | null = null
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const resp = await fetch(url)
      if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${url}`)
      return await resp.arrayBuffer()
    } catch (err) {
      lastError = err as Error
      if (attempt < maxRetries) {
        const delay = Math.min(1000 * 2 ** attempt, 10000)
        await new Promise((r) => setTimeout(r, delay))
      }
    }
  }
  throw lastError!
}

/**
 * Get statistics about cached chunks in localforage.
 */
export async function getChunkStats(): Promise<{ totalBytes: number; entries: number }> {
  const keys = await localforage.keys()
  let totalBytes = 0
  for (const key of keys) {
    const item = await localforage.getItem<ArrayBuffer>(key)
    if (item && item.byteLength !== undefined) {
      totalBytes += item.byteLength
    }
  }
  return { totalBytes, entries: keys.length }
}

/**
 * Clear all cached chunks from localforage.
 */
export async function clearChunkCache(): Promise<void> {
  await localforage.clear()
}
