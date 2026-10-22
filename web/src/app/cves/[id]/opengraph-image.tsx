import { ImageResponse } from "next/og";

import { getIconDimensions } from "@/components/tool-icon";
import {
  OG_FRAME,
  OG_INK,
  OG_MUTED,
  OG_RULE,
  OG_SIZE,
  OgBrand,
  ogFonts,
  ogToolIcon,
} from "@/lib/og";
import {
  formatContributionClass,
  getAiFamilyIconKey,
  getAiToolLabel,
  getCaseHeadline,
  getCauseCategoryLabel,
  getResearchCaseById,
  preferredCaseId,
} from "@/lib/research-data";
import { severityLevel } from "@/lib/research-format";

export { generateStaticParams } from "./page";

export const dynamic = "force-static";
export const alt = "Vibe Security Radar finding";
export const size = OG_SIZE;
export const contentType = "image/png";

const SEVERITY = {
  CRITICAL: { label: "Critical", color: "#b91c1c" },
  HIGH: { label: "High", color: "#c2410c" },
  MEDIUM: { label: "Medium", color: "#854d0e" },
  LOW: { label: "Low", color: OG_MUTED },
} as const;

function fitHeadline(text: string): { text: string; size: number } {
  if (text.length <= 90) return { text, size: 60 };
  if (text.length <= 140) return { text, size: 52 };
  if (text.length <= 200) return { text, size: 44 };
  const cut = text.slice(0, 236).replace(/\s+\S*$/, "");
  return { text: `${cut}…`, size: 40 };
}

export default async function Image({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const item = getResearchCaseById((await params).id);
  const fonts = await ogFonts();
  if (!item) {
    return new ImageResponse(
      <div style={OG_FRAME}>
        <OgBrand />
      </div>,
      { ...size, fonts },
    );
  }

  const identified = item.ai_provenance.coverage === "complete";
  const iconKey = getAiFamilyIconKey(
    identified ? item.ai_provenance.family : null,
  );
  const icon = await ogToolIcon(iconKey);
  const level = severityLevel(item.severity);
  const headline = fitHeadline(getCaseHeadline(item));
  const facts = [
    formatContributionClass(item.contribution_class),
    ...(item.cause_category && item.cause_category !== "other_ambiguous"
      ? [getCauseCategoryLabel(item.cause_category)]
      : []),
  ];

  return new ImageResponse(
    <div style={OG_FRAME}>
      <OgBrand />
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 18,
          marginTop: 52,
          fontFamily: "Geist Mono",
          fontWeight: 500,
          fontSize: 28,
        }}
      >
        <div style={{ display: "flex", flexShrink: 0 }}>
          {preferredCaseId(item)}
        </div>
        {item.repository ? (
          <div
            style={{
              display: "block",
              minWidth: 0,
              overflow: "hidden",
              whiteSpace: "nowrap",
              textOverflow: "ellipsis",
              color: OG_MUTED,
            }}
          >
            {item.repository}
          </div>
        ) : null}
        {level ? (
          <div
            style={{
              display: "flex",
              flexShrink: 0,
              padding: "2px 16px",
              border: `2px solid ${SEVERITY[level].color}`,
              borderRadius: 999,
              color: SEVERITY[level].color,
              fontFamily: "Geist",
              fontWeight: 600,
              fontSize: 24,
            }}
          >
            {SEVERITY[level].label}
          </div>
        ) : null}
      </div>
      <div
        style={{
          display: "flex",
          marginTop: 22,
          maxHeight: 286,
          overflow: "hidden",
          fontSize: headline.size,
          fontWeight: 600,
          lineHeight: 1.22,
          letterSpacing: headline.size >= 52 ? -1.5 : -1,
        }}
      >
        {headline.text}
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 14,
          marginTop: "auto",
          paddingTop: 26,
          borderTop: `2px solid ${OG_RULE}`,
          fontSize: 26,
          color: OG_MUTED,
        }}
      >
        {icon ? (
          <img src={icon} alt="" {...getIconDimensions(iconKey, 30)} />
        ) : null}
        <div
          style={{
            display: "flex",
            color: OG_INK,
            fontWeight: 600,
            whiteSpace: "nowrap",
          }}
        >
          {identified ? getAiToolLabel(item) : "Unidentified AI tool"}
        </div>
        {facts.map((fact) => (
          <div key={fact} style={{ display: "flex", gap: 14 }}>
            <span>·</span>
            <span>{fact}</span>
          </div>
        ))}
      </div>
    </div>,
    { ...size, fonts },
  );
}
