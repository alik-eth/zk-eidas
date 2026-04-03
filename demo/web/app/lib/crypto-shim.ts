// Browser shim for Node's "crypto" module.
// mlkem dynamically imports "crypto" as fallback, but in the browser
// globalThis.crypto (Web Crypto API) is always available.
// This shim prevents Vite from externalizing the module and breaking the chunk.
export const webcrypto = globalThis.crypto
export default globalThis.crypto
