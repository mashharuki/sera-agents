# x402-service — Ethereum Sepolia E2E runbook

The unit suite (89 tests) mocks the chain and the facilitator. **Every payment
check in the service is fail-closed**, so a green unit run proves the *rejections*
work but not that a *real* payment can succeed. Only a live testnet run proves
the EIP-712 USDC domain is configured correctly and that the depth/replay
defenses behave against a live chain. **Run this before any mainnet flip.**

> This test moves real (testnet) value. It needs infrastructure and a funded
> key that only the operator has — it is intentionally not runnable in CI, and
> nothing here should ever hold a mainnet key.

## What it proves

| # | Proof | How |
|---|-------|-----|
| 1 | A genuine EIP-3009 payment **succeeds** end-to-end (402 → pay → 200 + delivery) | `sepolia-e2e.mjs`, automated — **catches the LOW-1 domain footgun**: if `X402_USDC_NAME`/`_VERSION` don't match the token's on-chain `name()`/`version()`, every signature recovers a wrong address and silently bounces |
| 2 | Delivery only happens once the settle tx is **≥ `X402_CONFIRMATION_DEPTH`** deep | `sepolia-e2e.mjs`, automated — reads the settle-tx receipt + head at first success |
| 3 | Cross-payment `txHash` replay → `payment_proof_already_used`, and the ledger **survives a restart** | Half automated (restart-idempotency), half manual (facilitator-driven replay) — see below |
| 4 | A **forged-`from`** payment is rejected against a real facilitator, not just unit mocks | `sepolia-e2e.mjs`, automated |

The client-signing ↔ server-verify crypto contract (proof 1's fragile core) is
*also* checked with zero infra in `test/e2e-client-contract.test.ts` — run it
in CI as an early warning before you ever spin up Sepolia infra.

## Prerequisites

1. **A payment token on Sepolia** (the "USDC"). Note its contract address and
   its EIP-712 domain — read `name()` and `version()` on-chain (or from the
   deployment docs). **Do not assume `"USD Coin"`/`"2"`** — Sepolia deployments
   vary; a mismatch makes proof 1 fail (fail-closed).
2. **A funded payer wallet**: an EOA holding some of that token **and** Sepolia
   ETH for gas. You will pass its private key to the harness.
3. **A self-hosted x402 facilitator** on Sepolia (e.g. the Apache-2.0 reference
   from [coinbase/x402](https://github.com/coinbase/x402)) with a funded gas
   wallet to submit `transferWithAuthorization`.
4. **A Sepolia RPC** you control (`X402_RPC_URL`).
5. **The service running in live mode** against that facilitator:

   ```bash
   export X402_MODE=live
   export X402_LIVE_ACK=true
   export X402_FACILITATOR_KIND=selfhosted
   export X402_FACILITATOR_URL=https://your-facilitator.example/x402
   export X402_NETWORK=eip155:11155111
   export X402_CHAIN_ID=11155111
   export X402_USDC_ADDRESS=0x...        # the token from step 1
   export X402_USDC_NAME="..."           # on-chain name()  — MUST match
   export X402_USDC_VERSION="..."        # on-chain version() — MUST match
   export X402_VAULT_ADDRESS=0x...
   export X402_RPC_URL=https://...
   export X402_STATE_DB=/var/lib/x402/state.db   # durable ledger (required live)
   export X402_CONFIRMATION_DEPTH=3
   # + SERA_MCP_DIST, SERA_SIGNER_MODE=local, SIGNER_PRIVATE_KEY, etc.
   npm start
   ```

   On boot, watch stderr: if you left `X402_USDC_NAME`/`_VERSION` unset on a
   non-base network the service now prints a loud `[x402] WARNING` that the
   domain defaults may reject every payment. Heed it.

## Run the automated proofs (1, 2, 4)

```bash
export X402_E2E_URL=http://127.0.0.1:8402
export X402_E2E_PAYER_KEY=0x...          # funded payer from prerequisite 2
export X402_E2E_RPC_URL=https://...      # same Sepolia RPC
export X402_E2E_USDC=0x...               # same token address
export X402_E2E_USDC_NAME="..."          # same as X402_USDC_NAME
export X402_E2E_USDC_VERSION="..."       # same as X402_USDC_VERSION
export X402_E2E_RECIPIENT=...            # a delivery recipient the corridor accepts
npm run e2e:sepolia
```

A clean run prints `✓ Proof 1`, `✓ Proof 2`, `✓ Proof 4`. Any failure exits
non-zero with the reason. Missing config exits `2` and lists every variable.

## Proof 3 — the two halves

**3a. Restart persistence (drive it manually):**

1. Note a `payment_id` that Proof 1 delivered.
2. Restart the service process — same `X402_STATE_DB`.
3. Re-POST `/x402/swap` with the **same** `X-PAYMENT` header for that payment.
4. Expect `200` with `idempotent_replay: true` and **no** second on-chain
   charge. This confirms the durable ledger reloaded and still recognizes the
   consumed tx. If instead it re-executes, the ledger isn't durable — stop.

**3b. Cross-payment `txHash` replay (needs a cooperating facilitator):**

The `payment_proof_already_used` guard fires when two *different* `payment_id`s
resolve to the **same** settle `txHash`. A well-behaved facilitator won't do
that (the EIP-3009 nonce is single-use on-chain), so to exercise the guard
directly, point a test/stub facilitator at a fixed prior `txHash` for a second
payment and confirm the service returns `402 payment_proof_already_used` rather
than delivering. This is the last line of defense behind the on-chain
`AuthorizationUsed` check; verify it once, then keep the real facilitator.

## Sign-off before mainnet

- [ ] Proof 1 green — a real payment delivered (domain is correct)
- [ ] Proof 2 green — delivery gated on ≥ 3 confirmations
- [ ] Proof 3a green — delivered payment replays idempotently across a restart
- [ ] Proof 3b green — cross-payment `txHash` replay refused
- [ ] Proof 4 green — forged-`from` refused by the live facilitator path
- [ ] Mainnet config keeps `X402_RPC_URL` set and **never** sets
      `X402_SKIP_ONCHAIN_CONFIRM=true` (that path skips signature + on-chain
      checks entirely and trusts the facilitator blindly)
- [ ] The vault/swap signer key (`SIGNER_PRIVATE_KEY`) lives off the
      facilitator host (KMS/HSM), vault funded only to operating float

Then switch `X402_NETWORK`/`X402_CHAIN_ID` to the mainnet you settle on.
