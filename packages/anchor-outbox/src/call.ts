import { encodeFunctionData, type Hex } from "viem";
import { bytes, canonicalInput, LIMITS, statement } from "./validation.ts";
/** New raw-byte ABI proposal for A158. It is deliberately distinct from the
 * prior tuple ABI. Deployed implementation/decoder equivalence is a pending gate. */
export const RAW_STATEMENT_ABI=[{type:"function",name:"publish",stateMutability:"nonpayable",inputs:[{name:"statement",type:"bytes"}],outputs:[]}] as const;
export function encodeRawStatementCall(input:Uint8Array):Hex {
 const raw=bytes(input,LIMITS.statementBytes);statement(canonicalInput(raw,LIMITS.statementBytes));
 return encodeFunctionData({abi:RAW_STATEMENT_ABI,functionName:"publish",args:[("0x"+raw.toString("hex")) as Hex]});
}
