import { ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type AuthState = "APPROVED" | "PENDING" | "REJECTED";

const CONFIG: Record<AuthState, { icon: typeof ShieldCheck; label: string; className: string }> = {
  APPROVED: { icon: ShieldCheck, label: "Vault Verified", className: "border-transparent bg-acid/15 text-acid" },
  PENDING: { icon: ShieldQuestion, label: "Authenticating", className: "border-transparent bg-gold/15 text-gold" },
  REJECTED: { icon: ShieldAlert, label: "Flagged", className: "border-transparent bg-hype/15 text-hype" },
};

export function AuthBadge({ status, className }: { status: AuthState; className?: string }) {
  const config = CONFIG[status];
  const Icon = config.icon;
  return (
    <Badge className={cn(config.className, className)}>
      <Icon />
      {config.label}
    </Badge>
  );
}
