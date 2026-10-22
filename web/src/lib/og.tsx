import { readFile } from "node:fs/promises";
import path from "node:path";

export const OG_SIZE = { width: 1200, height: 630 };
export const OG_INK = "#17191f";
export const OG_MUTED = "#5d6472";
export const OG_RULE = "#d8dbe2";
export const OG_BLUE = "#2357e6";

const asset = (...parts: string[]) => path.join(process.cwd(), ...parts);

export async function ogFonts() {
  const [regular, semibold, mono] = await Promise.all(
    ["Geist-Regular.woff", "Geist-SemiBold.woff", "GeistMono-Medium.woff"].map(
      (file) => readFile(asset("src", "assets", "fonts", file)),
    ),
  );
  return [
    {
      name: "Geist",
      data: regular,
      weight: 400 as const,
      style: "normal" as const,
    },
    {
      name: "Geist",
      data: semibold,
      weight: 600 as const,
      style: "normal" as const,
    },
    {
      name: "Geist Mono",
      data: mono,
      weight: 500 as const,
      style: "normal" as const,
    },
  ];
}

export async function ogToolIcon(key: string): Promise<string | null> {
  const file = key === "openai_codex" ? "chatgpt-64.png" : `${key}.svg`;
  try {
    const data = await readFile(asset("public", "icons", "tools", file));
    const type = file.endsWith(".png") ? "image/png" : "image/svg+xml";
    return `data:${type};base64,${data.toString("base64")}`;
  } catch {
    return null;
  }
}

export function OgBrand() {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <svg width="44" height="44" viewBox="0 0 64 64">
          <rect width="64" height="64" rx="14" fill={OG_BLUE} />
          <circle
            cx="32"
            cy="32"
            r="21"
            fill="none"
            stroke="#fff"
            strokeWidth="3.5"
            strokeOpacity=".4"
          />
          <circle
            cx="32"
            cy="32"
            r="12"
            fill="none"
            stroke="#fff"
            strokeWidth="3.5"
            strokeOpacity=".7"
          />
          <path
            d="M32 32 47 17"
            fill="none"
            stroke="#fff"
            strokeWidth="4"
            strokeLinecap="round"
          />
          <circle cx="32" cy="32" r="4" fill="#fff" />
          <circle cx="42.5" cy="42" r="4" fill="#ffb020" />
        </svg>
        <div
          style={{
            display: "flex",
            fontSize: 30,
            fontWeight: 600,
            letterSpacing: -0.6,
          }}
        >
          Vibe Security Radar
        </div>
      </div>
      <div style={{ display: "flex", fontSize: 24, color: OG_MUTED }}>
        vibesecradar.com
      </div>
    </div>
  );
}

export const OG_FRAME = {
  display: "flex",
  flexDirection: "column",
  width: "100%",
  height: "100%",
  padding: "60px 72px 56px",
  background: "#f7f7f4",
  color: OG_INK,
  fontFamily: "Geist",
  fontWeight: 400,
} as const;
