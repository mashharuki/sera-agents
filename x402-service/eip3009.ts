/**
 * EIP-3009 `transferWithAuthorization` signature verification.
 *
 * This is the control that makes the payer's `from` address UN-FORGEABLE. The
 * x402 payment header is attacker-controllable (a malicious/self-hosted
 * facilitator or a hostile client writes it), so binding the on-chain
 * confirmation to header-asserted `from`/`value` alone is not enough — an
 * attacker could name someone else's real transfer. Recovering the signer of
 * the EIP-712 typed authorization and requiring it to equal `from` closes that:
 * the attacker cannot produce a valid signature for a payer they don't control.
 *
 * Uses viem's audited `recoverTypedDataAddress` — never hand-rolled secp256k1
 * or EIP-712 encoding. A wrong domain (name/version/chainId/verifyingContract)
 * recovers a different address and therefore REJECTS — the failure mode is
 * fail-closed (legit payments bounce, caught by E2E), never a forged accept.
 */
import { recoverTypedDataAddress, type Hex } from "viem";

export interface Eip3009Authorization {
  from: string;
  to: string;
  value: string; // uint256 decimal
  validAfter: string; // uint256 decimal (seconds)
  validBefore: string; // uint256 decimal (seconds)
  nonce: string; // bytes32 hex
}

export interface Eip712TokenDomain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string; // the token (USDC) address
}

export interface SignatureCheck {
  ok: boolean;
  reason?: string;
}

const HEX32 = /^0x[0-9a-fA-F]{64}$/;

/**
 * Verify that `signature` is a valid EIP-3009 TransferWithAuthorization
 * signature by `auth.from` over the given token domain, and that the
 * authorization time window covers `nowSeconds`. Fail-closed on any parse or
 * recovery error.
 */
export async function verifyTransferAuthorization(
  auth: Eip3009Authorization,
  signature: string,
  domain: Eip712TokenDomain,
  nowSeconds: number,
): Promise<SignatureCheck> {
  try {
    if (!/^0x[0-9a-fA-F]+$/.test(signature)) return { ok: false, reason: "signature must be hex" };
    // 65-byte sig = 0x + 130 hex chars = 132; longer is tolerated (some encoders
    // append), shorter is rejected. Note this also rejects EIP-2098 compact
    // 64-byte signatures (130 chars) — a known limitation, not a security gap
    // (fail-closed). Add compact-sig support here if a client ever needs it.
    if (signature.length < 132) return { ok: false, reason: "signature too short" };
    if (!HEX32.test(auth.nonce)) return { ok: false, reason: "nonce must be bytes32" };

    // Time window (defense in depth; the chain also enforces validBefore).
    const after = BigInt(auth.validAfter);
    const before = BigInt(auth.validBefore);
    const now = BigInt(Math.floor(nowSeconds));
    if (now < after) return { ok: false, reason: "authorization not yet valid" };
    if (before !== 0n && now >= before) return { ok: false, reason: "authorization expired" };

    const recovered = await recoverTypedDataAddress({
      domain: {
        name: domain.name,
        version: domain.version,
        chainId: domain.chainId,
        verifyingContract: domain.verifyingContract as Hex,
      },
      types: {
        TransferWithAuthorization: [
          { name: "from", type: "address" },
          { name: "to", type: "address" },
          { name: "value", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
        ],
      },
      primaryType: "TransferWithAuthorization",
      message: {
        from: auth.from as Hex,
        to: auth.to as Hex,
        value: BigInt(auth.value),
        validAfter: after,
        validBefore: before,
        nonce: auth.nonce as Hex,
      },
      signature: signature as Hex,
    });

    if (recovered.toLowerCase() !== auth.from.toLowerCase()) {
      return { ok: false, reason: "signature does not recover to the authorization's `from`" };
    }
    return { ok: true };
  } catch (e: any) {
    return {
      ok: false,
      reason: `signature verification failed: ${e?.shortMessage ?? e?.message ?? String(e)}`,
    };
  }
}
