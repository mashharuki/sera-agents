/**
 * Minimal x402 "exact" client — sign an EIP-3009 authorization and build the
 * X-PAYMENT header exactly as the Sera x402-service parses it.
 *
 * This is the buyer side of the flow. The server (payment-binding.ts +
 * eip3009.ts) recovers the signer of this authorization and requires it to
 * equal `from`, so the signature MUST be produced over the SAME EIP-712 domain
 * the server verifies against ({ name, version, chainId, verifyingContract }).
 * If they disagree the payment silently fails closed — which is exactly the
 * LOW-1 footgun the live E2E exists to catch.
 *
 * Kept dependency-light (only viem, already a service dep) and framework-free
 * so it can back both the live harness and the CI contract test.
 */
import { randomBytes } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";

/** A fresh 32-byte hex nonce for a TransferWithAuthorization. */
export function randomNonce() {
  return `0x${randomBytes(32).toString("hex")}`;
}

const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

/**
 * Sign an EIP-3009 TransferWithAuthorization.
 *
 * @param {`0x${string}`} privateKey  payer key (funded with the payment asset + gas on the chain)
 * @param {{from:string,to:string,value:string|bigint,validAfter:string|bigint,validBefore:string|bigint,nonce:string}} auth
 * @param {{name:string,version:string,chainId:number,verifyingContract:string}} domain  token EIP-712 domain
 * @returns {Promise<{signature:string, authorization:object}>}
 */
export async function signTransferAuthorization(privateKey, auth, domain) {
  const account = privateKeyToAccount(privateKey);
  if (account.address.toLowerCase() !== auth.from.toLowerCase()) {
    throw new Error(
      `signer ${account.address} does not match auth.from ${auth.from} — the server will reject this`,
    );
  }
  const signature = await account.signTypedData({
    domain: {
      name: domain.name,
      version: domain.version,
      chainId: domain.chainId,
      verifyingContract: domain.verifyingContract,
    },
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from: auth.from,
      to: auth.to,
      value: BigInt(auth.value),
      validAfter: BigInt(auth.validAfter),
      validBefore: BigInt(auth.validBefore),
      nonce: auth.nonce,
    },
  });
  return {
    signature,
    authorization: {
      ...auth,
      value: String(auth.value),
      validAfter: String(auth.validAfter),
      validBefore: String(auth.validBefore),
    },
  };
}

/**
 * Build the x402 v1 payment payload object the service accepts. `network` is
 * the CAIP-2 / named network the server advertised in its 402 (e.g.
 * "eip155:11155111"). Shape matches payment-binding.ts `extract()`:
 *   { x402Version, scheme, network, payload: { signature, authorization } }
 */
export function buildX402Payload({ network, signature, authorization }) {
  return {
    x402Version: 1,
    scheme: "exact",
    network,
    payload: { signature, authorization },
  };
}

/**
 * Compose the full `X-PAYMENT` header value: `<payment_id>:<base64(payload)>`.
 * The service splits on the FIRST ":" — see server.ts branch 2.
 */
export function buildXPaymentHeader(paymentId, payload) {
  const b64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
  return `${paymentId}:${b64}`;
}
