"use client";

import { useMemo, useState, useActionState, useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import Link from "next/link";
import Image from "next/image";
import { toast } from "sonner";
import { CheckCircle2, CreditCard, Landmark, Smartphone, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { StepProgress } from "./step-progress";
import { useCart } from "@/components/cart/cart-context";
import { submitOrder, type CheckoutState } from "@/actions/checkout";
import { INSURANCE_THRESHOLD_INR, INSURANCE_RATE } from "@/lib/business/constants";
import { cn } from "@/lib/utils";

const STEPS = ["Shipping", "Payment", "Review"];

type AddressState = {
  fullName: string;
  line1: string;
  line2: string;
  city: string;
  state: string;
  pincode: string;
  phone: string;
};

const EMPTY_ADDRESS: AddressState = { fullName: "", line1: "", line2: "", city: "", state: "", pincode: "", phone: "" };

const PAYMENT_METHODS = [
  { id: "card", label: "Card", icon: CreditCard },
  { id: "upi", label: "UPI", icon: Smartphone },
  { id: "netbanking", label: "Net Banking", icon: Landmark },
];

export function CheckoutWizard() {
  const { items, subtotal, clear } = useCart();
  const [step, setStep] = useState(0);
  const [address, setAddress] = useState<AddressState>(EMPTY_ADDRESS);
  const [payment, setPayment] = useState("card");
  const [insurance, setInsurance] = useState<Record<string, boolean>>({});
  const initialState: CheckoutState = {};
  const [state, formAction, pending] = useActionState(submitOrder, initialState);

  useEffect(() => {
    if (state.success) {
      clear();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.success]);

  const insuranceEligible = useMemo(() => items.filter((i) => i.price >= INSURANCE_THRESHOLD_INR), [items]);
  const insuranceTotal = insuranceEligible.reduce(
    (sum, i) => sum + (insurance[i.listingId] !== false ? Math.round(i.price * INSURANCE_RATE) : 0),
    0
  );
  const total = subtotal + insuranceTotal;

  if (state.success) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="mx-auto flex max-w-md flex-col items-center gap-4 py-16 text-center"
      >
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: "spring", stiffness: 260, damping: 18, delay: 0.1 }}
        >
          <CheckCircle2 className="size-16 text-acid" />
        </motion.div>
        <h1 className="font-display text-3xl tracking-wide">ORDER LOCKED IN</h1>
        <p className="text-sm text-muted-foreground">
          {state.orderIds?.length ?? 0} item{(state.orderIds?.length ?? 0) === 1 ? "" : "s"} sent to the vault for
          authentication. You&apos;ll get tracking updates in your dashboard.
        </p>
        <div className="mt-2 flex gap-3">
          <Button asChild>
            <Link href="/dashboard/buyer/orders">Track Orders</Link>
          </Button>
          <Button asChild variant="outline">
            <Link href="/browse/sneakers">Keep Shopping</Link>
          </Button>
        </div>
      </motion.div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="py-24 text-center">
        <p className="font-display text-2xl tracking-wide">YOUR CART IS EMPTY</p>
        <Button asChild className="mt-4">
          <Link href="/browse/sneakers">Browse the vault</Link>
        </Button>
      </div>
    );
  }

  function next() {
    if (step === 0) {
      const required: (keyof AddressState)[] = ["fullName", "line1", "city", "state", "pincode", "phone"];
      const missing = required.find((k) => !address[k].trim());
      if (missing) {
        toast.error("Fill in all required shipping fields.");
        return;
      }
      if (!/^\d{6}$/.test(address.pincode)) {
        toast.error("Enter a valid 6-digit pincode.");
        return;
      }
    }
    setStep((s) => Math.min(STEPS.length - 1, s + 1));
  }

  return (
    <div className="mx-auto max-w-2xl">
      <StepProgress steps={STEPS} current={step} />

      <div className="mt-10">
        <AnimatePresence mode="wait">
          {step === 0 && (
            <motion.div
              key="shipping"
              initial={{ opacity: 0, x: 16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -16 }}
              className="flex flex-col gap-4"
            >
              <div className="grid gap-4 sm:grid-cols-2">
                <Field name="fullName" label="Full name" value={address.fullName} onChange={(v) => setAddress({ ...address, fullName: v })} className="sm:col-span-2" />
                <Field name="line1" label="Address line 1" value={address.line1} onChange={(v) => setAddress({ ...address, line1: v })} className="sm:col-span-2" />
                <Field name="line2" label="Address line 2 (optional)" value={address.line2} onChange={(v) => setAddress({ ...address, line2: v })} className="sm:col-span-2" />
                <Field name="city" label="City" value={address.city} onChange={(v) => setAddress({ ...address, city: v })} />
                <Field name="state" label="State" value={address.state} onChange={(v) => setAddress({ ...address, state: v })} />
                <Field name="pincode" label="Pincode" value={address.pincode} onChange={(v) => setAddress({ ...address, pincode: v })} />
                <Field name="phone" label="Phone" value={address.phone} onChange={(v) => setAddress({ ...address, phone: v })} />
              </div>
              <Button size="lg" className="mt-2 self-end" onClick={next}>
                Continue to Payment
              </Button>
            </motion.div>
          )}

          {step === 1 && (
            <motion.div key="payment" initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -16 }} className="flex flex-col gap-4">
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Payment method (simulated)</p>
              <div className="grid grid-cols-3 gap-3">
                {PAYMENT_METHODS.map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setPayment(m.id)}
                    className={cn(
                      "flex flex-col items-center gap-2 border p-4 transition",
                      payment === m.id ? "border-acid bg-acid/5 text-acid" : "border-border text-muted-foreground hover:border-acid/50"
                    )}
                  >
                    <m.icon className="size-5" />
                    <span className="font-mono text-[11px] uppercase">{m.label}</span>
                  </button>
                ))}
              </div>
              {payment === "card" && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label="Card number" value="" onChange={() => {}} placeholder="4242 4242 4242 4242" className="sm:col-span-2" />
                  <Field label="Expiry" value="" onChange={() => {}} placeholder="MM/YY" />
                  <Field label="CVV" value="" onChange={() => {}} placeholder="123" />
                </div>
              )}
              <p className="font-mono text-[10px] text-muted-foreground">
                Demo checkout — no real payment is processed. Funds are simulated as held in escrow until delivery.
              </p>
              <div className="mt-2 flex justify-between">
                <Button variant="outline" onClick={() => setStep(0)}>
                  Back
                </Button>
                <Button size="lg" onClick={next}>
                  Review Order
                </Button>
              </div>
            </motion.div>
          )}

          {step === 2 && (
            <motion.form
              key="review"
              action={formAction}
              initial={{ opacity: 0, x: 16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -16 }}
              className="flex flex-col gap-4"
            >
              {items.map((item) => (
                <input key={item.listingId} type="hidden" name="listingId" value={item.listingId} />
              ))}
              {Object.entries(insurance)
                .filter(([, v]) => v !== false)
                .map(([listingId]) => (
                  <input key={listingId} type="hidden" name="insuranceListingId" value={listingId} />
                ))}
              {insuranceEligible
                .filter((i) => insurance[i.listingId] === undefined)
                .map((i) => (
                  <input key={`default-${i.listingId}`} type="hidden" name="insuranceListingId" value={i.listingId} />
                ))}
              <input type="hidden" name="fullName" value={address.fullName} />
              <input type="hidden" name="line1" value={address.line1} />
              <input type="hidden" name="line2" value={address.line2} />
              <input type="hidden" name="city" value={address.city} />
              <input type="hidden" name="state" value={address.state} />
              <input type="hidden" name="pincode" value={address.pincode} />
              <input type="hidden" name="phone" value={address.phone} />

              <div className="flex flex-col gap-2">
                {items.map((item) => (
                  <div key={item.listingId} className="flex items-center gap-3 border border-border bg-card p-3">
                    <div className="relative size-14 shrink-0 overflow-hidden bg-vault-3">
                      <Image src={item.image} alt={item.productName} fill className="object-cover" />
                    </div>
                    <div className="flex-1">
                      <p className="line-clamp-1 text-sm font-semibold">{item.productName}</p>
                      <p className="text-xs text-muted-foreground">
                        {item.condition.replace(/_/g, " ")}
                        {item.size ? ` · ${item.size}` : ""}
                      </p>
                    </div>
                    <p className="font-mono text-sm font-bold text-acid">₹{item.price.toLocaleString("en-IN")}</p>
                  </div>
                ))}
              </div>

              {insuranceEligible.length > 0 && (
                <div className="flex flex-col gap-2 border border-border bg-card p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold">
                    <ShieldCheck className="size-4 text-acid" />
                    Shipping insurance
                  </div>
                  {insuranceEligible.map((item) => (
                    <label key={item.listingId} className="flex items-center justify-between gap-2 text-sm">
                      <span className="flex items-center gap-2">
                        <Checkbox
                          checked={insurance[item.listingId] !== false}
                          onCheckedChange={(checked) =>
                            setInsurance((prev) => ({ ...prev, [item.listingId]: checked === true }))
                          }
                        />
                        <span className="line-clamp-1 text-muted-foreground">{item.productName}</span>
                      </span>
                      <span className="font-mono text-xs">₹{Math.round(item.price * INSURANCE_RATE).toLocaleString("en-IN")}</span>
                    </label>
                  ))}
                  <p className="font-mono text-[10px] text-muted-foreground">
                    Recommended for items over ₹{INSURANCE_THRESHOLD_INR.toLocaleString("en-IN")} — covers loss or damage in transit.
                  </p>
                </div>
              )}

              <div className="flex flex-col gap-1 border-t border-border pt-3 font-mono text-sm">
                <div className="flex justify-between text-muted-foreground">
                  <span>Subtotal</span>
                  <span>₹{subtotal.toLocaleString("en-IN")}</span>
                </div>
                <div className="flex justify-between text-muted-foreground">
                  <span>Insurance</span>
                  <span>₹{insuranceTotal.toLocaleString("en-IN")}</span>
                </div>
                <div className="mt-1 flex justify-between text-base font-bold text-acid">
                  <span>Total</span>
                  <span>₹{total.toLocaleString("en-IN")}</span>
                </div>
              </div>

              {state.error && <p className="text-sm text-hype">{state.error}</p>}

              <div className="mt-2 flex justify-between">
                <Button type="button" variant="outline" onClick={() => setStep(1)}>
                  Back
                </Button>
                <Button type="submit" size="lg" disabled={pending}>
                  {pending ? "Placing order..." : `Place Order — ₹${total.toLocaleString("en-IN")}`}
                </Button>
              </div>
            </motion.form>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

function Field({
  name,
  label,
  value,
  onChange,
  placeholder,
  className,
}: {
  name?: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <Label htmlFor={name}>{label}</Label>
      <Input id={name} name={name} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </div>
  );
}
