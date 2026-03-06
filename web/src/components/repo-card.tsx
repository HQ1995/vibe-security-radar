import { EntityCard } from "@/components/entity-card";

interface RepoCardProps {
  readonly repo: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

export function RepoCard({ repo, count, severities }: RepoCardProps) {
  const owner = repo.split("/")[0];
  return (
    <EntityCard
      href={`/cves?repo=${encodeURIComponent(repo)}`}
      label={repo}
      icon={
        <img
          src={`https://github.com/${owner}.png?size=40`}
          alt={owner}
          width={22}
          height={22}
          className="h-[22px] w-[22px] shrink-0 rounded-full"
        />
      }
      count={count}
      severities={severities}
    />
  );
}
