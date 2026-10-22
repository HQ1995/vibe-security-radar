import type { Metadata } from "next";
import { notFound } from "next/navigation";

import {
  TopicPage,
  topicDescription,
  topicHeading,
} from "@/components/topic-page";
import { clampDescription, pageMetadata } from "@/lib/page-metadata";
import { getTopic, getTopics, topicPath } from "@/lib/topics";

export const dynamicParams = false;

export function generateStaticParams() {
  return getTopics("cause").map((topic) => ({ slug: topic.slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const topic = getTopic("cause", (await params).slug);
  if (!topic) return { title: "Not found" };
  return pageMetadata({
    title: topicHeading(topic),
    description: clampDescription(topicDescription(topic), 220),
    path: topicPath(topic),
  });
}

export default async function Page({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const topic = getTopic("cause", (await params).slug);
  if (!topic) notFound();
  return <TopicPage topic={topic} />;
}
