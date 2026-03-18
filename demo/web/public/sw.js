// zk-eidas offline verifier service worker
// The /verify page must work fully offline after first visit

const CACHE_NAME = 'zk-eidas-v4'

const PRECACHE_URLS = [
  '/trusted-vks.json',
  '/favicon.svg',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
]

// Fetch a URL, cache it, and return the response text
async function fetchAndCache(cache, url) {
  try {
    const res = await fetch(url)
    if (!res.ok) return null
    const clone = res.clone()
    await cache.put(new Request(url), clone)
    return res.text()
  } catch (_) { return null }
}

// Precache /verify and ALL its dependencies (including dynamic imports)
async function precacheVerifyPage(cache) {
  try {
    // 1. Fetch and cache the HTML
    const htmlRes = await fetch('/verify')
    if (!htmlRes.ok) return
    await cache.put(new Request('/verify'), htmlRes.clone())
    const html = await htmlRes.text()

    // 2. Extract asset URLs from HTML
    const assetUrls = new Set()
    for (const match of html.matchAll(/(?:src|href)=["'](\/(assets\/[^"']+))["']/g)) {
      assetUrls.add(match[1])
    }
    for (const match of html.matchAll(/rel="modulepreload"[^>]*href="([^"]+)"/g)) {
      assetUrls.add(match[1])
    }

    // 3. Fetch HTML-referenced assets and scan JS files for dynamic imports
    const jsContents = []
    for (const url of assetUrls) {
      const text = await fetchAndCache(cache, url)
      if (text && url.endsWith('.js')) jsContents.push(text)
    }

    // 4. Scan JS bundles for dynamic import chunks
    const chunkUrls = new Set()
    for (const js of jsContents) {
      // Match patterns like: import("./chunk-xxx.js") or import("/assets/xxx.js")
      for (const match of js.matchAll(/import\(["'](\.[^"']+\.js)["']\)/g)) {
        chunkUrls.add('/assets/' + match[1].replace('./', ''))
      }
      for (const match of js.matchAll(/import\(["'](\/assets\/[^"']+)["']\)/g)) {
        chunkUrls.add(match[1])
      }
    }

    // 5. Fetch and cache dynamic import chunks (and scan one more level)
    for (const url of chunkUrls) {
      if (!assetUrls.has(url)) {
        const text = await fetchAndCache(cache, url)
        if (text && url.endsWith('.js')) {
          // One more level: scan these chunks for their own imports
          for (const match of text.matchAll(/import\(["'](\.[^"']+\.js)["']\)/g)) {
            const deepUrl = '/assets/' + match[1].replace('./', '')
            if (!assetUrls.has(deepUrl) && !chunkUrls.has(deepUrl)) {
              await fetchAndCache(cache, deepUrl)
            }
          }
        }
      }
    }
  } catch (_) {}
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      await cache.addAll(PRECACHE_URLS)
      await precacheVerifyPage(cache)
    })
  )
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  )
  self.clients.claim()
})

self.addEventListener('fetch', (event) => {
  const { request } = event
  const url = new URL(request.url)

  // Skip API calls
  if (url.pathname.startsWith('/issuer/') ||
      url.pathname.startsWith('/holder/') ||
      url.pathname.startsWith('/verifier/')) {
    return
  }

  // Cross-origin (Google Fonts etc): cache-first, empty fallback
  if (url.origin !== self.location.origin) {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached
        return fetch(request).then((response) => {
          if (response && response.status === 200) {
            const clone = response.clone()
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone))
          }
          return response
        }).catch(() => new Response('', { status: 200, headers: { 'content-type': 'text/css' } }))
      })
    )
    return
  }

  // Navigation: network-first, cache fallback
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const clone = response.clone()
          caches.open(CACHE_NAME).then((cache) => cache.put(request, clone))
          return response
        })
        .catch(() => caches.match(request))
    )
    return
  }

  // Static assets: cache-first
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached
      return fetch(request).then((response) => {
        if (!response || response.status !== 200) return response
        const clone = response.clone()
        caches.open(CACHE_NAME).then((cache) => cache.put(request, clone))
        return response
      })
    })
  )
})
