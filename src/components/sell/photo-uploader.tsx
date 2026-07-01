"use client";

import { useRef, useState } from "react";
import Image from "next/image";
import { UploadCloud, X, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export function PhotoUploader({ urls, onChange }: { urls: string[]; onChange: (urls: string[]) => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);

  async function handleFiles(files: FileList | null) {
    if (!files || files.length === 0) return;
    setUploading(true);
    try {
      const formData = new FormData();
      Array.from(files).forEach((f) => formData.append("files", f));
      const res = await fetch("/api/uploads", { method: "POST", body: formData });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Upload failed");
      onChange([...urls, ...data.urls]);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        className={cn(
          "flex flex-col items-center justify-center gap-2 border border-dashed border-border py-10 text-muted-foreground transition hover:border-acid hover:text-acid",
          uploading && "pointer-events-none opacity-60"
        )}
      >
        {uploading ? <Loader2 className="size-6 animate-spin" /> : <UploadCloud className="size-6" />}
        <span className="font-mono text-xs uppercase tracking-widest">
          {uploading ? "Uploading..." : "Upload inspection photos"}
        </span>
        <span className="text-[11px]">JPG, PNG, or WEBP — up to 8MB each</span>
      </button>
      <input
        ref={inputRef}
        type="file"
        accept="image/jpeg,image/png,image/webp"
        multiple
        hidden
        onChange={(e) => handleFiles(e.target.files)}
      />

      {urls.length > 0 && (
        <div className="grid grid-cols-4 gap-2 sm:grid-cols-6">
          {urls.map((url, i) => (
            <div key={url} className="group relative aspect-square overflow-hidden rounded-sm border border-border">
              <Image src={url} alt={`Inspection photo ${i + 1}`} fill className="object-cover" />
              <button
                type="button"
                onClick={() => onChange(urls.filter((u) => u !== url))}
                className="absolute right-1 top-1 flex size-5 items-center justify-center rounded-full bg-vault/80 text-foreground opacity-0 transition group-hover:opacity-100"
              >
                <X className="size-3" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
