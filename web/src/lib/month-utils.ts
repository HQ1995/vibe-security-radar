const MONTH_NAMES_SHORT = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

export function formatMonthShort(month: string): string {
  const [year, m] = month.split("-");
  return MONTH_NAMES_SHORT[Number(m) - 1] + " " + year;
}
