import { CheckoutWizard } from "@/components/checkout/checkout-wizard";

export default function CheckoutPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6">
      <h1 className="mb-8 text-center font-display text-3xl tracking-wide">CHECKOUT</h1>
      <CheckoutWizard />
    </div>
  );
}
