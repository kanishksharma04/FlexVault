import { ImageResponse } from "next/og";

export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          background: "#0a0a0b",
          color: "#f2f2ee",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", fontSize: 64, fontWeight: 700, letterSpacing: 1 }}>
          DRIP. <span style={{ color: "#c6f135", marginLeft: 16 }}>VERIFIED.</span>
          <span style={{ marginLeft: 16 }}>DELIVERED.</span>
        </div>
        <div style={{ display: "flex", marginTop: 24, fontSize: 28, color: "#9a9a94" }}>
          India&apos;s Authenticated Hype Marketplace
        </div>
      </div>
    ),
    { ...size }
  );
}
