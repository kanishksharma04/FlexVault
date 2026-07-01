"use client";

import { Toaster as Sonner, type ToasterProps } from "sonner";

const Toaster = ({ ...props }: ToasterProps) => {
  return (
    <Sonner
      theme="dark"
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
