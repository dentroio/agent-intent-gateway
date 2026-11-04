// Same verifier as docs/demo/chain.js (byte-compatible with aig/ledger.py); copied at build time.
export declare function verifyChain(records: unknown[]): Promise<{ ok: boolean; n: number; index: number; reason: string }>
