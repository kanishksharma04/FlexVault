import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { uploadAdapter } from "@/lib/uploads";
import { rateLimit } from "@/lib/rate-limit";
import { sniffImageMimeType } from "@/lib/file-signature";

const ALLOWED_TYPES = new Set(["image/jpeg", "image/png", "image/webp"]);
const MAX_SIZE = 8 * 1024 * 1024;

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const limited = await rateLimit(req, "uploads", 20, "1 m");
  if (limited) return limited;

  const formData = await req.formData();
  const files = formData.getAll("files").filter((f): f is File => f instanceof File);

  if (files.length === 0) return NextResponse.json({ error: "No files provided" }, { status: 400 });

  const urls: string[] = [];
  for (const file of files) {
    if (!ALLOWED_TYPES.has(file.type)) {
      return NextResponse.json({ error: `Unsupported file type: ${file.type}` }, { status: 400 });
    }
    if (file.size > MAX_SIZE) {
      return NextResponse.json({ error: "File too large (max 8MB)" }, { status: 400 });
    }

    // Don't trust the client-supplied Content-Type — verify the file's
    // actual magic bytes match a real image before writing it to disk.
    const sniffedType = await sniffImageMimeType(file);
    if (!sniffedType || !ALLOWED_TYPES.has(sniffedType)) {
      return NextResponse.json({ error: `File content does not match an allowed image type: ${file.name}` }, { status: 400 });
    }

    urls.push(await uploadAdapter.save(file));
  }

  return NextResponse.json({ urls });
}
