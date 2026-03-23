// Stub for production builds where wasm-pack hasn't been run.
// On-device proving requires the real WASM module (wasm-pack build).
export default function init() { throw new Error('WASM module not available — run wasm-pack build') }
export function prepare_inputs() { throw new Error('WASM module not available') }
