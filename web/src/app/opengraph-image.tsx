import { ImageResponse } from "next/og";

import { getResearchSnapshot, getResearchTimeline } from "@/lib/research-data";

export const dynamic = "force-static";
export const alt = "Vibe Security Radar";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpengraphImage() {
  const { snapshot } = getResearchSnapshot();
  const timeline = getResearchTimeline();
  const max = Math.max(1, ...timeline.map((month) => month.count));
  return new ImageResponse(
    (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          width: "100%",
          height: "100%",
          padding: "72px 80px",
          background: "#f7f7f4",
          color: "#17191f",
        }}
      >
        <div
          style={{
            display: "flex",
            fontSize: 24,
            letterSpacing: 3,
            color: "#2357e6",
            textTransform: "uppercase",
          }}
        >
          Georgia Tech SSLab · Security research
        </div>
        <div
          style={{
            display: "flex",
            marginTop: 20,
            fontSize: 84,
            letterSpacing: -3,
          }}
        >
          Vibe Security Radar
        </div>
        <div
          style={{
            display: "flex",
            marginTop: 20,
            maxWidth: 940,
            fontSize: 36,
            lineHeight: 1.35,
            color: "#626977",
          }}
        >
          {`${snapshot.case_count} AI-contributed vulnerabilities, each traced from the AI-assisted change to the security fix.`}
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "flex-end",
            gap: 12,
            height: 150,
            marginTop: "auto",
            borderBottom: "2px solid #d8dbe2",
          }}
        >
          {timeline.map((month) => (
            <div
              key={month.month}
              style={{
                width: 40,
                height: month.count ? Math.max(4, (month.count / max) * 146) : 0,
                background: "#2357e6",
                borderRadius: "6px 6px 0 0",
              }}
            />
          ))}
        </div>
      </div>
    ),
    size,
  );
}
