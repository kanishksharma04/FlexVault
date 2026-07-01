import { createHash, randomBytes } from "crypto";
import QRCode from "qrcode";

/**
 * Mock "blockchain" certificate hash. Not a real chain write — a
 * deterministic-looking hex digest that stands in for one, so the
 * authentication flow and PDP certificate UI have something real to render.
 */
export function generateCertificateHash(listingId: string): string {
  const salt = randomBytes(8).toString("hex");
  return createHash("sha256").update(`${listingId}:${salt}:${Date.now()}`).digest("hex");
}

export async function generateCertificateQrDataUrl(
  certificateHash: string,
  listingId: string
): Promise<string> {
  const payload = `https://flexvault.in/verify/${listingId}?cert=${certificateHash.slice(0, 16)}`;
  return QRCode.toDataURL(payload, {
    margin: 1,
    width: 240,
    color: { dark: "#0a0a0b", light: "#f2f2ee" },
  });
}
