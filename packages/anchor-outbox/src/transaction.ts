import { keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction, type Hex, type TransactionSerializedLegacy } from "viem";
import { data, exact } from "@ramex-labs/irontrellis-mcp-gateway/data";
import { address, chunks, fields, LIMITS, need, OutboxError, unchunk, type SelectedProfile } from "./validation.ts";
export type LegacyTransaction = Readonly<{ type: "legacy"; chainId: number; nonce: number; from: Hex; to: Hex; gas: bigint; gasPrice: bigint; value: bigint; data: Hex }>;
export type StoredTransaction = Readonly<Omit<LegacyTransaction,"gas"|"gasPrice"|"value"|"data"> & { gas: string; gasPrice: string; value: string; dataChunks: readonly string[] }>;
const MAX = (1n<<256n)-1n, ORDER=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const hex = (v: unknown): v is Hex => typeof v === "string" && v.length <= LIMITS.rawTransactionBytes*2+2 && /^0x(?:[0-9a-f]{2})*$/.exec(v)?.[0] === v;
const uint = (v: unknown): v is bigint => typeof v === "bigint" && v>=0n && v<=MAX;
export function captureTransaction(input: unknown, p: SelectedProfile): LegacyTransaction {
  const t=fields(input,["type","chainId","nonce","from","to","gas","gasPrice","value","data"]);
  need(t.type==="legacy" && typeof t.chainId==="number" && Number.isSafeInteger(t.chainId) && t.chainId>0 &&
    t.chainId<=Math.floor((Number.MAX_SAFE_INTEGER-36)/2) && `eip155:${t.chainId}`===p.chainId &&
    typeof t.nonce==="number" && Number.isSafeInteger(t.nonce) && t.nonce>=0 && !Object.is(t.nonce,-0) &&
    address(t.from) && t.from===p.publisher && address(t.to) && t.to===p.destination && uint(t.gas) && t.gas>0n &&
    uint(t.gasPrice) && uint(t.value) && t.value===0n && hex(t.data) && t.data!=="0x", "TRANSACTION_INVALID");
  return t as unknown as LegacyTransaction;
}
export const unsignedDigest = (t: LegacyTransaction): Hex => keccak256(serializeTransaction(t));
export const storedTransaction = (t: LegacyTransaction): StoredTransaction => {const {data:raw,...rest}=t;return Object.freeze({...rest,gas:String(t.gas),gasPrice:String(t.gasPrice),value:String(t.value),dataChunks:chunks(Buffer.from(raw.slice(2),"hex"))});};
export function restoreTransaction(input: unknown, p: SelectedProfile): LegacyTransaction {
  const t=exact(data(input),["type","chainId","nonce","from","to","gas","gasPrice","value","dataChunks"]);
  for (const k of ["gas","gasPrice","value"]) need(typeof t[k]==="string" && /^(0|[1-9][0-9]{0,77})$/.exec(t[k] as string)?.[0]===t[k],"STORED_TRANSACTION_INVALID");
  const {dataChunks,...rest}=t;
  return captureTransaction({...rest,data:`0x${unchunk(dataChunks,LIMITS.rawTransactionBytes).toString("hex")}`,gas:BigInt(t.gas as string),gasPrice:BigInt(t.gasPrice as string),value:BigInt(t.value as string)},p);
}
/** Real selected viem; no injectable crypto result or caller success flag. */
export async function verifySigned(t: LegacyTransaction, input: unknown): Promise<Readonly<{raw:Hex;transactionHash:Hex}>> {
  need(hex(input) && input!=="0x","SIGNER_RESULT_INVALID");
  const raw=input as Hex;
  try {
    const p=parseTransaction(raw), base=BigInt(t.chainId)*2n+35n;
    need(p.type==="legacy" && p.chainId===t.chainId && p.nonce===t.nonce && p.to?.toLowerCase()===t.to &&
      (p.gas??0n)===t.gas && (p.gasPrice??0n)===t.gasPrice && (p.value??0n)===t.value && (p.data??"0x")===t.data &&
      typeof p.v==="bigint" && (p.v===base || p.v===base+1n) && hex(p.r) && p.r!=="0x" && hex(p.s) && p.s!=="0x", "SIGNER_RESULT_INVALID");
    const r=BigInt(p.r!),s=BigInt(p.s!);
    need(r>0n && r<ORDER && s>0n && s<=ORDER/2n && serializeTransaction(t,{v:p.v!,r:p.r!,s:p.s!})===raw,"SIGNER_RESULT_INVALID");
    need((await recoverTransactionAddress({serializedTransaction:raw as TransactionSerializedLegacy})).toLowerCase()===t.from,"SIGNER_RESULT_INVALID");
    return Object.freeze({raw,transactionHash:keccak256(raw)});
  } catch { throw new OutboxError("SIGNER_RESULT_INVALID"); }
}
