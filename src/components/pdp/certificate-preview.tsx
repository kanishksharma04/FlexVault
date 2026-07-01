import Image from "next/image";
import { ShieldCheck } from "lucide-react";
import { generateCertificateQrDataUrl } from "@/lib/business/certificate";

export async function CertificatePreview({
  certificateHash,
  listingId,
}: {
  certificateHash: string;
  listingId: string;
}) {
  const qr = await generateCertificateQrDataUrl(certificateHash, listingId);

  return (
    <div className="flex flex-col gap-4 border border-border bg-card p-5 sm:flex-row sm:items-center">
      <div className="relative size-28 shrink-0 overflow-hidden rounded-sm border border-border bg-vault-2">
        <Image src={qr} alt="Certificate QR code" fill className="object-contain p-2" />
      </div>
      <div className="flex flex-1 flex-col gap-1.5">
        <div className="flex items-center gap-2 text-acid">
          <ShieldCheck className="size-4" />
          <span className="font-display text-sm tracking-wide">VAULT CERTIFICATE OF AUTHENTICITY</span>
        </div>
        <p className="font-mono text-[11px] break-all text-muted-foreground">
          {certificateHash}
        </p>
        <p className="text-xs text-muted-foreground">
          Scan the QR or verify this hash against Flex Vault&apos;s authentication ledger before pickup.
        </p>
      </div>
    </div>
  );
}
