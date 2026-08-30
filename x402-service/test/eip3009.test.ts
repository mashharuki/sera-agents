/**
 * EIP-3009 signature verification — the un-forgeable binding.
 *
 * These tests sign REAL EIP-3009 authorizations with viem test keys and assert
 * that the recovered signer must equal `from`. The load-bearing case is the
 * attacker scenario from the round-2 review: an attacker names a victim's
 * `from` but cannot produce the victim's signature → rejected.
 */
import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { verifyTransferAuthorization, type Eip3009Authorization, type Eip712TokenDomain } from "../eip3009.js";

const DOMAIN: Eip712TokenDomain = {
  name: "USD Coin",
  version: "2",
  chainId: 11155111, // Ethereum Sepolia
  verifyingContract: "0x2222222222222222222222222222222222222222",
};

const TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

const VAULT = "0x1111111111111111111111111111111111111111";
const NOW = 1_800_000_000;

// Deterministic test accounts.
const PAYER = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const ATTACKER = privateKeyToAccount("0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba");

async function signAuth(
  account: typeof PAYER,
  auth: Eip3009Authorization,
): Promise<string> {
  return account.signTypedData({
    domain: {
      name: DOMAIN.name,
      version: DOMAIN.version,
      chainId: DOMAIN.chainId,
      verifyingContract: DOMAIN.verifyingContract as `0x${string}`,
    },
    types: TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from: auth.from as `0x${string}`,
      to: auth.to as `0x${string}`,
      value: BigInt(auth.value),
      validAfter: BigInt(auth.validAfter),
      validBefore: BigInt(auth.validBefore),
      nonce: auth.nonce as `0x${string}`,
    },
  });
}

function authFor(from: string): Eip3009Authorization {
  return {
    from,
    to: VAULT,
    value: "1000000",
    validAfter: "0",
    validBefore: String(NOW + 3600),
    nonce: "0x" + "ab".repeat(32),
  };
}

describe("verifyTransferAuthorization", () => {
  it("accepts an authorization signed by its own `from`", async () => {
    const auth = authFor(PAYER.address);
    const sig = await signAuth(PAYER, auth);
    expect(await verifyTransferAuthorization(auth, sig, DOMAIN, NOW)).toEqual({ ok: true });
  });

  it("REJECTS a forged `from` — attacker names the payer but can't sign as them", async () => {
    // The round-2 CRITICAL: attacker claims from = PAYER (a real payer) but
    // only has their OWN key. Sign with the attacker key over an auth that
    // claims from = PAYER.
    const forged = authFor(PAYER.address);
    const attackerSig = await signAuth(ATTACKER, forged);
    const r = await verifyTransferAuthorization(forged, attackerSig, DOMAIN, NOW);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/recover/);
  });

  it("REJECTS a wrong domain (chain/contract/name mismatch → different signer)", async () => {
    const auth = authFor(PAYER.address);
    const sig = await signAuth(PAYER, auth);
    for (const bad of [
      { ...DOMAIN, chainId: 8453 },
      { ...DOMAIN, verifyingContract: "0x9999999999999999999999999999999999999999" },
      { ...DOMAIN, name: "USDC" },
      { ...DOMAIN, version: "1" },
    ]) {
      expect((await verifyTransferAuthorization(auth, sig, bad, NOW)).ok).toBe(false);
    }
  });

  it("REJECTS outside the time window", async () => {
    const auth = { ...authFor(PAYER.address), validAfter: String(NOW + 100) };
    const sig = await signAuth(PAYER, auth);
    expect((await verifyTransferAuthorization(auth, sig, DOMAIN, NOW)).ok).toBe(false); // not yet valid
    const expired = { ...authFor(PAYER.address), validBefore: String(NOW - 1) };
    const sig2 = await signAuth(PAYER, expired);
    expect((await verifyTransferAuthorization(expired, sig2, DOMAIN, NOW)).ok).toBe(false); // expired
  });

  it("REJECTS a mutated authorization (value changed after signing)", async () => {
    const auth = authFor(PAYER.address);
    const sig = await signAuth(PAYER, auth);
    const tampered = { ...auth, value: "2000000" };
    expect((await verifyTransferAuthorization(tampered, sig, DOMAIN, NOW)).ok).toBe(false);
  });

  it("REJECTS garbage / short signatures (fail-closed)", async () => {
    const auth = authFor(PAYER.address);
    for (const bad of ["0x", "0xdead", "not-hex", "0x" + "00".repeat(64)]) {
      expect((await verifyTransferAuthorization(auth, bad, DOMAIN, NOW)).ok).toBe(false);
    }
  });
});
