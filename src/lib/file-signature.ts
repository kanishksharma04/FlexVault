// Sniffs a file's actual format from its magic bytes rather than trusting
// the client-supplied `File.type`, which is just whatever Content-Type the
// browser/OS guessed from the filename and can be spoofed freely.
const SIGNATURES: { mime: string; matches: (bytes: Uint8Array) => boolean }[] = [
  { mime: "image/jpeg", matches: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  {
    mime: "image/png",
    matches: (b) =>
      b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 && b[4] === 0x0d && b[5] === 0x0a,
  },
  {
    mime: "image/webp",
    matches: (b) =>
      b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && // "RIFF"
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50, // "WEBP"
  },
];

export async function sniffImageMimeType(file: File): Promise<string | null> {
  const head = new Uint8Array(await file.slice(0, 12).arrayBuffer());
  return SIGNATURES.find((sig) => sig.matches(head))?.mime ?? null;
}
