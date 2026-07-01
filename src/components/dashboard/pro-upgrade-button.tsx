"use client";

import { useTransition } from "react";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { upgradeToPro } from "@/actions/membership";

export function ProUpgradeButton() {
  const [pending, startTransition] = useTransition();
  const router = useRouter();

  return (
    <Button
      size="lg"
      disabled={pending}
      onClick={() =>
        startTransition(async () => {
          const res = await upgradeToPro();
          if ("error" in res) {
            toast.error(res.error);
            return;
          }
          toast.success("Welcome to Flex Vault Pro.");
          router.refresh();
        })
      }
    >
      {pending ? "Upgrading..." : "Upgrade to Pro"}
    </Button>
  );
}
