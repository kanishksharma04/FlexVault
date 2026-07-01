import { PackageSearch, Microscope, ShieldCheck, QrCode } from "lucide-react";
import { SectionHeading } from "@/components/vault/section-heading";

const STEPS = [
  { icon: PackageSearch, title: "1. Intake", desc: "Every seller ships directly to a Flex Vault authentication hub — items never move buyer-to-seller directly." },
  { icon: Microscope, title: "2. Multi-Layer Inspection", desc: "Trained authenticators cross-check stitching, materials, serials, hardware, and packaging against a verified reference library. Sneakers get sole-pattern and box-label checks; watches get movement and engraving checks; diecast gets casting and paint checks." },
  { icon: ShieldCheck, title: "3. Certification", desc: "Approved items receive a digital Certificate of Authenticity with a unique certificate hash — our mock stand-in for an on-chain record." },
  { icon: QrCode, title: "4. Scannable Proof", desc: "Every certificate includes a QR code buyers can scan to verify the item against Flex Vault's authentication ledger." },
];

export default function AuthenticationPage() {
  return (
    <div className="mx-auto max-w-3xl px-4 py-16 sm:px-6">
      <SectionHeading eyebrow="Trust" title="THE AUTHENTICATION PROCESS" description="No listing goes live until it clears every step below." className="mb-10" />
      <div className="flex flex-col gap-4">
        {STEPS.map((s) => (
          <div key={s.title} className="flex gap-4 border border-border bg-card p-5">
            <s.icon className="size-6 shrink-0 text-acid" />
            <div>
              <p className="font-display text-lg tracking-wide">{s.title}</p>
              <p className="mt-1 text-sm text-muted-foreground">{s.desc}</p>
            </div>
          </div>
        ))}
      </div>
      <p className="mt-8 font-mono text-xs text-muted-foreground">
        Rejected items are never released for sale. Sellers are notified with the specific reason and the
        item is returned at the seller&apos;s cost.
      </p>
    </div>
  );
}
