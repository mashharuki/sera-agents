/**
 * Client ↔ server crypto contract.
 *
 * The live Sepolia E2E can only run against real infra, but its single most
 * fragile assumption — that a payment signed by the BUYER round-trips through
 * the SERVER's own parser + EIP-3009 verifier over the SAME EIP-712 domain —
 * is verifiable here with zero infra. If the client builder (scripts/
 * x402-client.mjs, which also backs the live harness) and the server verifier
 * (payment-binding.ts + eip3009.ts) ever drift — a field name, an encoding, a
 * domain mismatch — this test fails instead of every live payment silently
 * bouncing (the LOW-1 footgun). This is the CI-side de-risking of E2E proof #1.
 */
import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
// @ts-expect-error — untyped ESM helper shared with the live harness
import {
  signTransferAuthorization,
  buildX402Payload,
  buildXPaymentHeader,
  randomNonce,
} from "../scripts/x402-client.mjs";
import { parsePaymentAuthorization } from "../payment-binding.js";
import { verifyTransferAuthorization } from "../eip3009.js";

// Mirrors how server.ts derives the domain in live mode: operator config, not
// header-controlled. Ethereum-Sepolia-shaped values for realism.
const DOMAIN = {
  name: "USDC",
  version: "2",
  chainId: 11155111,
  verifyingContract: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", // Sepolia USDC
};
const NETWORK = "eip155:11155111";
const VAULT = "0x000000000000000000000000000000000000bEEF";
const PAYER_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const NOW = 1_800_000_000;

function authFor(from: string) {
  return {
    from,
    to: VAULT,
    value: "1000000",
    validAfter: "0",
    validBefore: String(NOW + 3600),
    nonce: randomNonce(),
  };
}

/** Reproduce server.ts branch-2 header handling: split on first ":". */
function serverParse(header: string) {
  const authorization = header.split(":", 2)[1] ?? "";
  const parsed = parsePaymentAuthorization(authorization);
  if (!parsed) throw new Error("server failed to parse the client-built X-PAYMENT header");
  return parsed;
}

describe("x402 client ↔ server contract", () => {
  it("a buyer-signed payment round-trips through the server parser + verifier", async () => {
    const payer = privateKeyToAccount(PAYER_PK);
    const auth = authFor(payer.address);
    const { signature, authorization } = await signTransferAuthorization(PAYER_PK, auth, DOMAIN);

    const header = buildXPaymentHeader(
      "pay_abc123",
      buildX402Payload({ network: NETWORK, signature, authorization }),
    );

    // Server side: parse the header exactly as the service does…
    const parsed = serverParse(header);
    expect(parsed.from).toBe(payer.address.toLowerCase());
    expect(parsed.to).toBe(VAULT.toLowerCase());
    expect(parsed.value).toBe("1000000");

    // …then verify the signature against the SAME domain the server uses.
    const check = await verifyTransferAuthorization(parsed, parsed.signature, DOMAIN, NOW);
    expect(check).toEqual({ ok: true });
  });

  it("a wrong-domain signature is rejected by the server (LOW-1 fail-closed)", async () => {
    const payer = privateKeyToAccount(PAYER_PK);
    const auth = authFor(payer.address);
    // Buyer signs over a DIFFERENT domain (e.g. mainnet-USDC name) than the
    // server verifies — the recovered signer won't match → reject, no payout.
    const { signature, authorization } = await signTransferAuthorization(PAYER_PK, auth, {
      ...DOMAIN,
      name: "USD Coin",
    });
    const parsed = serverParse(
      buildXPaymentHeader(
        "pay_x",
        buildX402Payload({ network: NETWORK, signature, authorization }),
      ),
    );
    expect((await verifyTransferAuthorization(parsed, parsed.signature, DOMAIN, NOW)).ok).toBe(
      false,
    );
  });

  it("the client helper refuses to sign for a `from` it does not hold the key to", async () => {
    // Guards the harness itself: you can't accidentally build a forged-`from`
    // payment that the server would just reject anyway.
    const notMine = authFor("0x000000000000000000000000000000000000dEaD");
    await expect(signTransferAuthorization(PAYER_PK, notMine, DOMAIN)).rejects.toThrow(
      /does not match/,
    );
  });
});
