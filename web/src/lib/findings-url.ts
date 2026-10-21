const KEY = "vsr:findings-url";

export function rememberFindingsUrl(url: string) {
  try {
    window.sessionStorage.setItem(KEY, url);
  } catch {}
}

export function rememberedFindingsUrl(): string {
  try {
    const url = window.sessionStorage.getItem(KEY);
    return url?.startsWith("/cves") ? url : "/cves";
  } catch {
    return "/cves";
  }
}
