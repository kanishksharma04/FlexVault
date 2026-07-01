import { mkdir, writeFile } from "fs/promises";
import path from "path";
import { randomUUID } from "crypto";

export interface UploadAdapter {
  save(file: File): Promise<string>;
}

const UPLOAD_DIR = path.join(process.cwd(), "public", "uploads");

/**
 * Local-disk adapter for dev. Swap for an S3/Cloudinary adapter in
 * production by implementing the same UploadAdapter interface.
 */
class LocalUploadAdapter implements UploadAdapter {
  async save(file: File): Promise<string> {
    await mkdir(UPLOAD_DIR, { recursive: true });
    const ext = file.name.split(".").pop() || "jpg";
    const filename = `${randomUUID()}.${ext}`;
    const buffer = Buffer.from(await file.arrayBuffer());
    await writeFile(path.join(UPLOAD_DIR, filename), buffer);
    return `/uploads/${filename}`;
  }
}

export const uploadAdapter: UploadAdapter = new LocalUploadAdapter();
