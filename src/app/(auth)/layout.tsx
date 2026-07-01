import Link from "next/link";
import { ShieldCheck } from "lucide-react";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-4 py-16">
      <div className="w-full max-w-md">
        <Link
          href="/"
          className="mb-8 flex items-center justify-center gap-1.5 font-display text-2xl tracking-wide"
        >
          <ShieldCheck className="size-6 text-acid" />
          FLEX <span className="text-acid">VAULT</span>
        </Link>
        <div className="card-hype border border-border bg-card p-8">{children}</div>
      </div>
    </div>
  );
}
