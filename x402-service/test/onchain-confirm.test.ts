/**
 * On-chain confirmation gate — fail-closed behavior.
 *
 * The gate is what makes a lying/compromised facilitator unable to trigger
 * free delivery, so every non-success path must return confirmed:false.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { checkOnce, type ConfirmConfig } from "../payment-confirm.js";

const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const VAULT = "0x1111111111111111111111111111111111111111";
const USDC = "0x2222222222222222222222222222222222222222";
const OTHER = "0x3333333333333333333333333333333333333333";

const CFG: ConfirmConfig = {
  rpcUrl: "http://rpc.test",
  asset: USDC,
  vault: VAULT,
  minAmountBaseUnits: "1000000", // 1 USDC
  confirmationDepth: 3,
};

function topicFor(addr: string): string {
  return "0x" + addr.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

/** Real receipts carry Transfer values as one full 32-byte word. */
function word(n: number): string {
  return "0x" + n.toString(16).padStart(64, "0");
}

/** Mock fetch answering eth_getTransactionReceipt / eth_blockNumber. */
function mockRpc(receipt: unknown, headBlock = "0x64" /* 100 */) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init: any) => {
      const req = JSON.parse(init.body);
      const result = req.method === "eth_getTransactionReceipt" ? receipt : headBlock;
      return {
        ok: true,
        json: async () => ({ jsonrpc: "2.0", id: 1, result }),
      } as any;
    }),
  );
}

function goodReceipt(overrides: Record<string, unknown> = {}) {
  return {
    status: "0x1",
    blockNumber: "0x60", // 96 → 100-96+1 = 5 confirmations ≥ 3
    logs: [
      {
        address: USDC,
        topics: [TRANSFER_TOPIC, topicFor(OTHER), topicFor(VAULT)],
        data: word(1_000_000), // exactly the required amount
      },
    ],
    ...overrides,
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("checkOnce — confirms only a real, deep-enough vault payment", () => {
  it("confirms a successful transfer of >= amount to the vault at depth", async () => {
    mockRpc(goodReceipt());
    const r = await checkOnce(CFG, "0xabc");
    expect(r.confirmed).toBe(true);
    expect(r.confirmations).toBe(5);
  });

  it("REFUSES when the receipt does not exist (facilitator lied about txHash)", async () => {
    mockRpc(null);
    expect((await checkOnce(CFG, "0xabc")).confirmed).toBe(false);
  });

  it("REFUSES a reverted transaction", async () => {
    mockRpc(goodReceipt({ status: "0x0" }));
    expect((await checkOnce(CFG, "0xabc")).confirmed).toBe(false);
  });

  it("REFUSES when the transfer went to a different recipient", async () => {
    mockRpc(
      goodReceipt({
        logs: [{ address: USDC, topics: [TRANSFER_TOPIC, topicFor(VAULT), topicFor(OTHER)], data: word(1_000_000) }],
      }),
    );
    expect((await checkOnce(CFG, "0xabc")).confirmed).toBe(false);
  });

  it("REFUSES when the transfer is on a different token contract", async () => {
    mockRpc(
      goodReceipt({
        logs: [{ address: OTHER, topics: [TRANSFER_TOPIC, topicFor(OTHER), topicFor(VAULT)], data: word(1_000_000) }],
      }),
    );
    expect((await checkOnce(CFG, "0xabc")).confirmed).toBe(false);
  });

  it("REFUSES when the amount is short", async () => {
    mockRpc(
      goodReceipt({
        logs: [
          {
            address: USDC,
            topics: [TRANSFER_TOPIC, topicFor(OTHER), topicFor(VAULT)],
            data: word(999_999),
          },
        ],
      }),
    );
    expect((await checkOnce(CFG, "0xabc")).confirmed).toBe(false);
  });

  it("REFUSES when confirmations are too shallow", async () => {
    mockRpc(goodReceipt({ blockNumber: "0x64" })); // same block as head → 1 confirmation
    const r = await checkOnce(CFG, "0xabc");
    expect(r.confirmed).toBe(false);
    expect(r.confirmations).toBe(1);
  });

  it("REFUSES (fail-closed) on RPC errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) }) as any));
    expect((await checkOnce(CFG, "0xabc")).confirmed).toBe(false);
  });

  it("REFUSES (fail-closed) when fetch itself throws", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("network down"); }));
    expect((await checkOnce(CFG, "0xabc")).confirmed).toBe(false);
  });
});

describe("checkOnce — payment binding (anti-replay)", () => {
  const BOUND: ConfirmConfig = { ...CFG, payerFrom: OTHER, exactValueBaseUnits: "1000000" };

  it("confirms when payer and exact value match the authorization", async () => {
    mockRpc(goodReceipt());
    expect((await checkOnce(BOUND, "0xabc")).confirmed).toBe(true);
  });

  it("REFUSES a transfer from a different payer (someone else's payment)", async () => {
    const stranger = "0x4444444444444444444444444444444444444444";
    mockRpc(
      goodReceipt({
        logs: [{ address: USDC, topics: [TRANSFER_TOPIC, topicFor(stranger), topicFor(VAULT)], data: word(1_000_000) }],
      }),
    );
    expect((await checkOnce(BOUND, "0xabc")).confirmed).toBe(false);
  });

  it("REFUSES when the value differs from the authorized exact value", async () => {
    mockRpc(
      goodReceipt({
        logs: [{ address: USDC, topics: [TRANSFER_TOPIC, topicFor(OTHER), topicFor(VAULT)], data: word(2_000_000) }],
      }),
    );
    expect((await checkOnce(BOUND, "0xabc")).confirmed).toBe(false);
  });

  it("REFUSES non-standard Transfer data (not one 32-byte word)", async () => {
    mockRpc(
      goodReceipt({
        logs: [{ address: USDC, topics: [TRANSFER_TOPIC, topicFor(OTHER), topicFor(VAULT)], data: "0xf4240" }],
      }),
    );
    expect((await checkOnce(BOUND, "0xabc")).confirmed).toBe(false);
  });
});
