declare module "zk-eidas-wasm" {
  export default function init(): Promise<void>;
  export function prepare_inputs(credential: string, claim: string): string;
}
