import { ImageResponse } from "next/og";

import {
  OG_BLUE,
  OG_FRAME,
  OG_MUTED,
  OG_RULE,
  OG_SIZE,
  OgBrand,
  ogFonts,
} from "@/lib/og";
import { getResearchSnapshot, getResearchTimeline } from "@/lib/research-data";

export const dynamic = "force-static";
export const alt = "Vibe Security Radar";
export const size = OG_SIZE;
export const contentType = "image/png";

export default async function OpengraphImage() {
  const { snapshot } = getResearchSnapshot();
  const timeline = getResearchTimeline();
  const max = Math.max(1, ...timeline.map((month) => month.count));
  return new ImageResponse(
    <div style={OG_FRAME}>
      <OgBrand />
      <div
        style={{
          display: "flex",
          marginTop: 56,
          fontSize: 60,
          fontWeight: 600,
          lineHeight: 1.08,
          letterSpacing: -2,
        }}
      >
        CVEs traced to AI-generated code
      </div>
      <div
        style={{
          display: "flex",
          marginTop: 22,
          maxWidth: 960,
          fontSize: 32,
          lineHeight: 1.35,
          color: OG_MUTED,
        }}
      >
        {`${snapshot.case_count} published vulnerabilities, each traced from the AI-assisted change to the security fix. Georgia Tech SSLab.`}
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "flex-end",
          gap: 12,
          height: 140,
          marginTop: "auto",
          borderBottom: `2px solid ${OG_RULE}`,
        }}
      >
        {timeline.map((month) => (
          <div
            key={month.month}
            style={{
              width: 40,
              height: month.count ? Math.max(4, (month.count / max) * 136) : 0,
              background: OG_BLUE,
              borderRadius: "6px 6px 0 0",
            }}
          />
        ))}
      </div>
    </div>,
    { ...size, fonts: await ogFonts() },
  );
}
