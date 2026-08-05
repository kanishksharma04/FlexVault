"use client";

import { Toaster as Sonner, type ToasterProps } from "sonner";
import { useTheme } from "@/hooks/use-theme";

const Toaster = ({ ...props }: ToasterProps) => {
  const theme = useTheme();
  return (
    <Sonner
      theme={theme}
      className="toaster group"
      style={
        {
          "--normal-bg": "var(--card)",
          "--normal-text": "var(--card-foreground)",
          "--normal-border": "var(--border)",
          "--success-bg": "var(--card)",
          "--success-border": "var(--acid)",
          "--success-text": "var(--acid)",
          "--error-bg": "var(--card)",
          "--error-border": "var(--hype)",
          "--error-text": "var(--hype)",
        } as React.CSSProperties
      }
      {...props}
    />
  );
};

export { Toaster };
