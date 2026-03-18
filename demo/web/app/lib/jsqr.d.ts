declare module 'jsqr' {
  interface QRCode {
    binaryData: number[]
    data: string
  }
  interface Options {
    inversionAttempts?: 'dontInvert' | 'onlyInvert' | 'attemptBoth'
  }
  export default function jsQR(
    data: Uint8ClampedArray,
    width: number,
    height: number,
    options?: Options,
  ): QRCode | null
}
