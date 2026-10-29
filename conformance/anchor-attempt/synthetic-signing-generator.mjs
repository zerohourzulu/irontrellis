/** SYNTHETIC_TEST_ONLY. Public nonsecret conformance constants. Offline only.
 * No credential discovery, random key, RPC, funding, wallet or real custody.
 * Secp256k1 scalar1 is the elementary generator-point input. The Ed25519
 * seed is RFC8032 section7.1 test1, distinct from the publisher/history keys.
 */
import {privateKeyToAccount} from '../../packages/anchor-outbox/node_modules/viem/_esm/accounts/index.js';
import {keyPairFromPrivateKey,hashCanonical,signHashWith} from '../../packages/core/dist/index.js';
const PUBLIC_TEST_PUBLISHER='0x'+'0'.repeat(63)+'1';
const PUBLIC_TEST_OPERATOR='0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
export const publicPublisher=()=>privateKeyToAccount(PUBLIC_TEST_PUBLISHER);
export const publicOperator=()=>keyPairFromPrivateKey('ed25519','synthetic-operator-rfc8032-test1',PUBLIC_TEST_OPERATOR);
export async function signSyntheticClearance(unsigned){const {signature,...value}=unsigned;return {...value,signature:await signHashWith(publicOperator())(hashCanonical(value))};}

export async function publisherSignedClearance(unsigned){const {signature,...value}=unsigned;const key=keyPairFromPrivateKey("eip191-personal-sign-keccak256","synthetic-publisher",PUBLIC_TEST_PUBLISHER);return {...value,signature:await signHashWith(key)(hashCanonical(value))};}
