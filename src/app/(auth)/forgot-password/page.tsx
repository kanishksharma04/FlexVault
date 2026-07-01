"use client";

import { useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function ForgotPasswordPage() {
  const [sent, setSent] = useState(false);

  if (sent) {
    return (
      <div className="text-center">
        <h1 className="font-display text-3xl tracking-wide">CHECK YOUR INBOX</h1>
        <p className="mt-3 text-sm text-muted-foreground">
          If that email is in the vault, a reset link is on its way.
        </p>
        <Link href="/login" className="mt-6 inline-block text-sm text-acid hover:underline">
          Back to log in
        </Link>
      </div>
    );
  }

  return (
    <>
      <h1 className="font-display text-3xl tracking-wide">RESET PASSWORD</h1>
      <p className="mt-1 text-sm text-muted-foreground">
        Enter your email and we&apos;ll send you a reset link.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setSent(true);
        }}
        className="mt-6 flex flex-col gap-4"
      >
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="email">Email</Label>
          <Input id="email" name="email" type="email" required autoComplete="email" />
        </div>
        <Button type="submit" size="lg" className="mt-2">
          Send reset link
        </Button>
      </form>
      <p className="mt-6 text-center text-sm text-muted-foreground">
        <Link href="/login" className="text-acid hover:underline">
          Back to log in
        </Link>
      </p>
    </>
  );
}
