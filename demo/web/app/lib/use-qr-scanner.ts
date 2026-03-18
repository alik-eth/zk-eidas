import { useRef, useCallback, useState, useEffect } from 'react'
import jsQR from 'jsqr'

export function useQrScanner(onScan: (data: Uint8Array) => void) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const animFrameRef = useRef<number>(0)
  const [active, setActive] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const start = useCallback(async () => {
    setError(null)
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
      })
      streamRef.current = stream
      if (videoRef.current) {
        videoRef.current.srcObject = stream
        await videoRef.current.play()
      }
      setActive(true)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Camera access failed')
    }
  }, [])

  const stop = useCallback(() => {
    if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current)
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop())
      streamRef.current = null
    }
    setActive(false)
  }, [])

  // Scan loop
  useEffect(() => {
    if (!active) return

    const scan = () => {
      const video = videoRef.current
      const canvas = canvasRef.current
      if (!video || !canvas || video.readyState !== video.HAVE_ENOUGH_DATA) {
        animFrameRef.current = requestAnimationFrame(scan)
        return
      }

      canvas.width = video.videoWidth
      canvas.height = video.videoHeight
      const ctx = canvas.getContext('2d')!
      ctx.drawImage(video, 0, 0)
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
      const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'dontInvert',
      })

      if (code) {
        // jsQR stores binary data in code.binaryData
        const bytes = new Uint8Array(code.binaryData)
        onScan(bytes)
      }

      animFrameRef.current = requestAnimationFrame(scan)
    }

    animFrameRef.current = requestAnimationFrame(scan)
    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current)
    }
  }, [active, onScan])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (streamRef.current) {
        streamRef.current.getTracks().forEach(t => t.stop())
      }
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current)
    }
  }, [])

  return { videoRef, canvasRef, active, error, start, stop }
}
