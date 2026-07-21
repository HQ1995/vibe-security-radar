import { Section } from "@/components/ui/section";

interface CollapsibleNonAiCommitsProps {
  readonly count: number;
  readonly children: React.ReactNode;
}

export function CollapsibleNonAiCommits({
  count,
  children,
}: CollapsibleNonAiCommitsProps) {
  return (
    <Section
      size="sm"
      title={`${count} commit${count !== 1 ? "s" : ""} without AI attribution`}
      className="mt-2"
    >
      {children}
    </Section>
  );
}
