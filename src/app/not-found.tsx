import Link from "next/link";
import { ShieldOff } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="flex min-h-[70vh] flex-col items-center justify-center gap-4 px-4 text-center">
      <ShieldOff className="size-10 text-muted-foreground" />
      <h1 className="font-display text-4xl tracking-wide">404 — NOT IN THE VAULT</h1>
      <p className="max-w-sm text-sm text-muted-foreground">
        This page doesn&apos;t exist, or it&apos;s been archived.
      </p>
      <Button asChild>
        <Link href="/">Back to the Vault</Link>
      </Button>
    </div>
  );
}
