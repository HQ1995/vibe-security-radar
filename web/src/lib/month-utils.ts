const MONTH_NAMES_SHORT = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

export function formatMonthShort(month: string): string {
  // "2025-09" -> "Sep 2025"
  const [year, m] = month.split("-");
  return MONTH_NAMES_SHORT[Number(m) - 1] + " " + year;
}
