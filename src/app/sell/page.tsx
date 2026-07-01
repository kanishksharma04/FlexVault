import { SellWizard } from "@/components/sell/sell-wizard";

export default function SellPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6">
      <h1 className="mb-8 text-center font-display text-3xl tracking-wide">CREATE A LISTING</h1>
      <SellWizard />
    </div>
  );
}
