import { SectionHeading } from "@/components/vault/section-heading";

const FAQS = [
  { q: "How does authentication work?", a: "Every item ships to a Flex Vault hub first. Authenticators inspect it against verified references before it's cleared for sale — see our full Authentication Process page for details." },
  { q: "What happens if an item fails authentication?", a: "It's rejected, the seller is notified with a specific reason, and the item is returned to them. It never reaches a buyer." },
  { q: "How fast is delivery?", a: "2–3 days PAN-India after authentication clears, with real-time tracking in your buyer dashboard." },
  { q: "What is insurance opt-in?", a: "For items above ₹10,000, we recommend shipping insurance covering loss or damage in transit. It's a small percentage of item price, added at checkout." },
  { q: "How do seller tiers work?", a: "Bronze through Platinum, based on completed sales. Higher tiers unlock lower commission and faster payouts." },
  { q: "What is Flex Vault Pro?", a: "A membership for buyers and sellers unlocking lower commission, early drop access, and shipping perks." },
];

export default function FaqPage() {
  return (
    <div className="mx-auto max-w-2xl px-4 py-16 sm:px-6">
      <SectionHeading eyebrow="Support" title="FAQ" className="mb-8" />
      <div className="flex flex-col divide-y divide-border border-y border-border">
        {FAQS.map((f) => (
          <details key={f.q} className="group py-4">
            <summary className="cursor-pointer list-none font-semibold marker:content-none">
              <span className="flex items-center justify-between">
                {f.q}
                <span className="text-acid transition group-open:rotate-45">+</span>
              </span>
            </summary>
            <p className="mt-2 text-sm text-muted-foreground">{f.a}</p>
          </details>
        ))}
      </div>
    </div>
  );
}
