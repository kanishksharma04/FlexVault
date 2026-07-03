import { mkdir, writeFile } from "fs/promises";
import path from "path";
import { randomUUID } from "crypto";
import { put } from "@vercel/blob";

export interface UploadAdapter {
  save(file: File): Promise<string>;
}

const UPLOAD_DIR = path.join(process.cwd(), "public", "uploads");

function randomFilename(file: File) {
  const ext = file.name.split(".").pop() || "jpg";
  return `${randomUUID()}.${ext}`;
}

/**
 * Local-disk adapter for dev without Blob storage configured. Files written
 * here don't survive a redeploy/serverless cold start, so this is not safe
 * for production — see VercelBlobUploadAdapter below.
 */
class LocalUploadAdapter implements UploadAdapter {
  async save(file: File): Promise<string> {
    await mkdir(UPLOAD_DIR, { recursive: true });
    const filename = randomFilename(file);
    const buffer = Buffer.from(await file.arrayBuffer());
    await writeFile(path.join(UPLOAD_DIR, filename), buffer);
    return `/uploads/${filename}`;
  }
}

/**
 * Object-storage adapter backed by Vercel Blob. Used automatically once the
 * project's Blob store is connected (Vercel injects BLOB_READ_WRITE_TOKEN),
 * so uploads survive redeploys instead of writing to ephemeral disk.
 */
class VercelBlobUploadAdapter implements UploadAdapter {
  async save(file: File): Promise<string> {
    const { url } = await put(`uploads/${randomFilename(file)}`, file, {
      access: "public",
      contentType: file.type,
    });
    return url;
  }
}

export const uploadAdapter: UploadAdapter = process.env.BLOB_READ_WRITE_TOKEN
  ? new VercelBlobUploadAdapter()
  : new LocalUploadAdapter();
