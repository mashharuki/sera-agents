/**
 * Facilitator backends — the selfhosted kind must work without any CDP
 * credentials (that's what lets a dev run their own facilitator on any EVM
 * chain, e.g. Ethereum Sepolia), and both kinds must stay fail-closed on
 * ambiguous responses.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { makeFacilitator, type FacilitatorConfig, type PaymentRequirements } from "../facilitator.js";

const REQS: PaymentRequirements = {
  scheme: "exact",
  network: "eip155:11155111",
  maxAmountRequired: "1000000",
  resource: "https://svc.example/x402/swap",
  description: "test",
  mimeType: "application/json",
  payTo: "0x1111111111111111111111111111111111111111",
  maxTimeoutSeconds: 300,
  asset: "0x2222222222222222222222222222222222222222",
  extra: {},
};

const SELFHOSTED: FacilitatorConfig = {
  kind: "selfhosted",
  url: "https://facilitator.example/x402",
  network: "eip155:11155111",
  confirmationDepth: 3,
  bearerToken: "my-own-token",
};

function capture(response: unknown) {
  const calls: Array<{ url: string; headers: Record<string, string>; body: any }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: any) => {
      calls.push({ url: String(url), headers: init.headers, body: JSON.parse(init.body) });
      return { ok: true, json: async () => response } as any;
    }),
  );
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("selfhosted facilitator — no CDP coupling", () => {
  it("verifies against the operator's own URL with a plain bearer, no CDP JWT", async () => {
    const calls = capture({ isValid: true });
    const f = makeFacilitator(SELFHOSTED);
    const r = await f.verify("payment-header", REQS);
    expect(r.isValid).toBe(true);
    expect(calls[0].url).toBe("https://facilitator.example/x402/verify");
    // Static token, not a three-part JWT
    expect(calls[0].headers.authorization).toBe("Bearer my-own-token");
    expect(calls[0].body.paymentRequirements.network).toBe("eip155:11155111");
  });

  it("sends no authorization header at all when no token is configured", async () => {
    const calls = capture({ isValid: true });
    const f = makeFacilitator({ ...SELFHOSTED, bearerToken: undefined });
    await f.verify("h", REQS);
    expect(calls[0].headers.authorization).toBeUndefined();
  });

  it("settle hits /settle and passes through txHash on explicit success", async () => {
    const calls = capture({ success: true, txHash: "0xdead", networkId: "eip155:11155111" });
    const f = makeFacilitator(SELFHOSTED);
    const r = await f.settle("h", REQS);
    expect(r).toEqual({ success: true, txHash: "0xdead", networkId: "eip155:11155111" });
    expect(calls[0].url).toBe("https://facilitator.example/x402/settle");
  });
});

describe("fail-closed result handling (both kinds)", () => {
  it("verify: missing/false/truthy-but-not-true isValid → invalid", async () => {
    for (const resp of [{}, { isValid: false }, { isValid: "true" }, { isValid: 1 }]) {
      capture(resp);
      const r = await makeFacilitator(SELFHOSTED).verify("h", REQS);
      expect(r.isValid).toBe(false);
      vi.unstubAllGlobals();
    }
  });

  it("settle: missing/false/truthy-but-not-true success → failed", async () => {
    for (const resp of [{}, { success: false }, { success: "true" }, { success: 1 }]) {
      capture(resp);
      const r = await makeFacilitator(SELFHOSTED).settle("h", REQS);
      expect(r.success).toBe(false);
      vi.unstubAllGlobals();
    }
  });

  it("2xx with null/array/string bodies fails closed instead of throwing", async () => {
    for (const resp of [null, [1, 2], "ok"]) {
      capture(resp);
      expect((await makeFacilitator(SELFHOSTED).verify("h", REQS)).isValid).toBe(false);
      expect((await makeFacilitator(SELFHOSTED).settle("h", REQS)).success).toBe(false);
      vi.unstubAllGlobals();
    }
  });

  it("HTTP error and unreachable both fail closed", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 503, text: async () => "down" }) as any));
    expect((await makeFacilitator(SELFHOSTED).verify("h", REQS)).isValid).toBe(false);
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("refused"); }));
    expect((await makeFacilitator(SELFHOSTED).settle("h", REQS)).success).toBe(false);
  });
});
