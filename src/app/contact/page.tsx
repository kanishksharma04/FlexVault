"use client";

import { useState } from "react";
import { SectionHeading } from "@/components/vault/section-heading";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

export default function ContactPage() {
  const [sent, setSent] = useState(false);

  return (
    <div className="mx-auto max-w-lg px-4 py-16 sm:px-6">
      <SectionHeading eyebrow="Support" title="CONTACT US" description="Questions about an order, listing, or dispute? We're here." className="mb-8" />

      {sent ? (
        <p className="border border-acid/30 bg-acid/5 p-5 text-sm text-acid">
          Message sent — the Flex Vault support desk will get back to you within 24 hours.
        </p>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setSent(true);
          }}
          className="flex flex-col gap-4"
        >
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="contact-name">Name</Label>
            <Input id="contact-name" required />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="contact-email">Email</Label>
            <Input id="contact-email" type="email" required />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="contact-message">Message</Label>
            <Textarea id="contact-message" required className="min-h-32" />
          </div>
          <Button type="submit" size="lg" className="w-fit">Send Message</Button>
        </form>
      )}
    </div>
  );
}
