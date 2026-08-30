/**
 * Payment-authorization binding — ties the on-chain confirmation to THIS
 * payment via a cryptographic proof, closing the replay/forgery hole.
 *
 * The x402 "exact" scheme payment header carries the buyer's signed EIP-3009
 * authorization: `{ signature, authorization: { from, to, value, validAfter,
 * validBefore, nonce } }`. We parse ALL signed fields plus the signature so
 * the signer can be recovered (see eip3009.ts). Header-asserted `from` is
 * worthless on its own — a malicious facilitator can name anyone — so the
 * signature is what makes `from` trustworthy.
 *
 * Parsing is fail-closed: an authorization we cannot fully read (missing any
 * signed field or the signature) is one we will not pay out against.
 */

export interface ParsedPaymentAuthorization {
  from: string;
  to: string;
  value: string; // uint256 decimal
  validAfter: string; // uint256 decimal
  validBefore: string; // uint256 decimal
  nonce: string; // bytes32 hex
  signature: string; // 0x… hex
}

const ADDR = /^0x[0-9a-fA-F]{40}$/;
const UINT = /^\d+$/;
const HEX = /^0x[0-9a-fA-F]+$/;
const HEX32 = /^0x[0-9a-fA-F]{64}$/;

function asDecimal(v: unknown): string | null {
  // Accept decimal strings and JS numbers/bigints that are non-negative integers.
  if (typeof v === "string") return UINT.test(v) ? v : null;
  if (typeof v === "number") return Number.isInteger(v) && v >= 0 ? String(v) : null;
  if (typeof v === "bigint") return v >= 0n ? v.toString() : null;
  return null;
}

function extract(obj: unknown): ParsedPaymentAuthorization | null {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  const o = obj as Record<string, any>;
  // x402 v1 shape: { payload: { signature, authorization: {...} } }.
  // Tolerate a flat object that carries both authorization fields + signature.
  const container = o.payload && typeof o.payload === "object" ? o.payload : o;
  const auth = container.authorization ?? (container.from && container.to ? container : null);
  const signature = container.signature ?? o.signature;
  if (!auth || typeof auth !== "object") return null;

  const from = String(auth.from ?? "");
  const to = String(auth.to ?? "");
  const value = asDecimal(auth.value);
  const validAfter = asDecimal(auth.validAfter);
  const validBefore = asDecimal(auth.validBefore);
  const nonce = String(auth.nonce ?? "");
  const sig = String(signature ?? "");

  if (!ADDR.test(from) || !ADDR.test(to)) return null;
  if (value === null || validAfter === null || validBefore === null) return null;
  if (!HEX32.test(nonce)) return null;
  if (!HEX.test(sig)) return null;

  return {
    from: from.toLowerCase(),
    to: to.toLowerCase(),
    value,
    validAfter,
    validBefore,
    nonce,
    signature: sig,
  };
}

/**
 * Parse the `<authorization>` part of the X-PAYMENT header (base64 x402 v1, or
 * raw JSON). Returns null when it cannot be fully read — callers in live mode
 * must treat null as a hard reject.
 */
export function parsePaymentAuthorization(headerPart: string): ParsedPaymentAuthorization | null {
  const s = (headerPart ?? "").trim();
  if (!s) return null;
  if (s.startsWith("{")) {
    try {
      return extract(JSON.parse(s));
    } catch {
      return null;
    }
  }
  try {
    const decoded = Buffer.from(s, "base64").toString("utf8");
    if (!decoded.trim().startsWith("{")) return null;
    return extract(JSON.parse(decoded));
  } catch {
    return null;
  }
}
