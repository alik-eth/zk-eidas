import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock localforage
const mockStore: Record<string, unknown> = {}
vi.mock('localforage', () => ({
  default: {
    getItem: vi.fn((key: string) => Promise.resolve(mockStore[key] ?? null)),
    setItem: vi.fn((key: string, value: unknown) => {
      mockStore[key] = value
      return Promise.resolve(value)
    }),
    keys: vi.fn(() => Promise.resolve(Object.keys(mockStore))),
    removeItem: vi.fn((key: string) => {
      delete mockStore[key]
      return Promise.resolve()
    }),
  },
}))

// Mock fetch
const mockFetchResponses: Record<string, ArrayBuffer> = {}
globalThis.fetch = vi.fn((url: string) => {
  const buf = mockFetchResponses[url]
  if (!buf) return Promise.resolve({ ok: false, status: 404 } as Response)
  return Promise.resolve({
    ok: true,
    arrayBuffer: () => Promise.resolve(buf),
  } as Response)
}) as unknown as typeof fetch

import {
  downloadChunks,
  areChunksReady,
  getChunkStats,
  SECTION_SUFFIXES,
} from './chunked-zkey-loader'

describe('chunked-zkey-loader', () => {
  beforeEach(() => {
    for (const key of Object.keys(mockStore)) delete mockStore[key]
    for (const key of Object.keys(mockFetchResponses)) delete mockFetchResponses[key]
    vi.clearAllMocks()
  })

  it('SECTION_SUFFIXES covers sections 1-10 (b through k)', () => {
    expect(SECTION_SUFFIXES).toEqual(['b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k'])
    expect(SECTION_SUFFIXES.length).toBe(10)
  })

  describe('areChunksReady', () => {
    it('returns false when no chunks are cached', async () => {
      expect(await areChunksReady('ecdsa_verify')).toBe(false)
    })

    it('returns true when all section files are cached', async () => {
      for (const suffix of SECTION_SUFFIXES) {
        mockStore[`ecdsa_verify.zkey${suffix}`] = new ArrayBuffer(10)
      }
      expect(await areChunksReady('ecdsa_verify')).toBe(true)
    })

    it('returns false when some chunks are missing', async () => {
      mockStore['ecdsa_verify.zkeyb'] = new ArrayBuffer(10)
      mockStore['ecdsa_verify.zkeyc'] = new ArrayBuffer(10)
      expect(await areChunksReady('ecdsa_verify')).toBe(false)
    })
  })

  describe('downloadChunks', () => {
    it('downloads all missing chunks and stores in localforage', async () => {
      for (const suffix of SECTION_SUFFIXES) {
        mockFetchResponses[`https://cdn.example.com/ecdsa_verify.zkey${suffix}`] =
          new ArrayBuffer(100)
      }

      const progress: string[] = []
      await downloadChunks(
        'ecdsa_verify',
        'https://cdn.example.com',
        SECTION_SUFFIXES,
        (detail: string) => progress.push(detail),
      )

      for (const suffix of SECTION_SUFFIXES) {
        expect(mockStore[`ecdsa_verify.zkey${suffix}`]).toBeDefined()
      }
      expect(progress.length).toBeGreaterThan(0)
    })

    it('skips already-cached chunks', async () => {
      for (const suffix of SECTION_SUFFIXES) {
        mockStore[`ecdsa_verify.zkey${suffix}`] = new ArrayBuffer(10)
      }

      await downloadChunks(
        'ecdsa_verify',
        'https://cdn.example.com',
        SECTION_SUFFIXES,
      )

      expect(globalThis.fetch).not.toHaveBeenCalled()
    })

    it('only downloads missing chunks', async () => {
      for (const suffix of SECTION_SUFFIXES) {
        if (suffix !== 'e') {
          mockStore[`ecdsa_verify.zkey${suffix}`] = new ArrayBuffer(10)
        }
      }
      mockFetchResponses['https://cdn.example.com/ecdsa_verify.zkeye'] = new ArrayBuffer(100)

      await downloadChunks(
        'ecdsa_verify',
        'https://cdn.example.com',
        SECTION_SUFFIXES,
      )

      expect(globalThis.fetch).toHaveBeenCalledTimes(1)
      expect(globalThis.fetch).toHaveBeenCalledWith('https://cdn.example.com/ecdsa_verify.zkeye')
    })
  })

  describe('getChunkStats', () => {
    it('returns zero when empty', async () => {
      const stats = await getChunkStats()
      expect(stats.totalBytes).toBe(0)
      expect(stats.entries).toBe(0)
    })

    it('counts all localforage entries', async () => {
      mockStore['ecdsa_verify.zkeyb'] = new ArrayBuffer(100)
      mockStore['ecdsa_verify.zkeyc'] = new ArrayBuffer(200)

      const stats = await getChunkStats()
      expect(stats.entries).toBe(2)
      expect(stats.totalBytes).toBe(300)
    })
  })
})
