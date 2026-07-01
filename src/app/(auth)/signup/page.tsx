"use client";

import { useActionState, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { signIn } from "next-auth/react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { registerUser, type SignupState } from "@/actions/auth";

const initialState: SignupState = {};

export default function SignupPage() {
  const router = useRouter();
  const [role, setRole] = useState<"BUYER" | "SELLER">("BUYER");
  const [state, formAction, pending] = useActionState(registerUser, initialState);

  useEffect(() => {
    if (!state.success) return;
    const form = document.getElementById("signup-form") as HTMLFormElement | null;
    const email = form?.email?.value;
    const password = form?.password?.value;
    if (!email || !password) return;

    signIn("credentials", { email, password, redirect: false }).then((res) => {
      if (res?.error) {
        toast.error("Account created — please log in.");
        router.push("/login");
        return;
      }
      toast.success("Account created. Welcome to the vault.");
      router.push(role === "SELLER" ? "/dashboard/seller" : "/dashboard/buyer");
      router.refresh();
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.success]);

  return (
    <>
      <h1 className="font-display text-3xl tracking-wide">SIGN UP</h1>
      <p className="mt-1 text-sm text-muted-foreground">Join the vault as a buyer or seller.</p>

      <div className="mt-6 grid grid-cols-2 gap-2 rounded-md border border-border p-1">
        {(["BUYER", "SELLER"] as const).map((r) => (
          <button
            key={r}
            type="button"
            onClick={() => setRole(r)}
            className={cn(
              "rounded py-2 font-mono text-xs uppercase tracking-widest transition",
              role === r ? "bg-acid text-acid-foreground" : "text-muted-foreground hover:text-foreground"
            )}
          >
            {r === "BUYER" ? "Buyer" : "Seller"}
          </button>
        ))}
      </div>

      <form id="signup-form" action={formAction} className="mt-6 flex flex-col gap-4">
        <input type="hidden" name="role" value={role} />
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="name">Full name</Label>
          <Input id="name" name="name" required autoComplete="name" />
          {state.errors?.name && <p className="text-xs text-hype">{state.errors.name[0]}</p>}
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="email">Email</Label>
          <Input id="email" name="email" type="email" required autoComplete="email" />
          {state.errors?.email && <p className="text-xs text-hype">{state.errors.email[0]}</p>}
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="password">Password</Label>
          <Input id="password" name="password" type="password" required autoComplete="new-password" />
          {state.errors?.password && <p className="text-xs text-hype">{state.errors.password[0]}</p>}
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="confirmPassword">Confirm password</Label>
          <Input id="confirmPassword" name="confirmPassword" type="password" required autoComplete="new-password" />
          {state.errors?.confirmPassword && (
            <p className="text-xs text-hype">{state.errors.confirmPassword[0]}</p>
          )}
        </div>
        {state.formError && <p className="text-sm text-hype">{state.formError}</p>}
        <Button type="submit" size="lg" disabled={pending} className="mt-2">
          {pending ? "Creating account..." : `Create ${role === "SELLER" ? "seller" : "buyer"} account`}
        </Button>
      </form>

      <p className="mt-6 text-center text-sm text-muted-foreground">
        Already have an account?{" "}
        <Link href="/login" className="text-acid hover:underline">
          Log in
        </Link>
      </p>
    </>
  );
}
