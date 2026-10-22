const MONTH_NAMES_SHORT = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

export function formatMonthShort(month: string): string {
  const [year, m] = month.split("-");
  return MONTH_NAMES_SHORT[Number(m) - 1] + " " + year;
}

export function formatDay(value: string): string {
  const [year, month, day] = value.slice(0, 10).split("-");
  return `${MONTH_NAMES_SHORT[Number(month) - 1]} ${Number(day)}, ${year}`;
}
