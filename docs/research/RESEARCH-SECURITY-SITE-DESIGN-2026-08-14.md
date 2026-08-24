# Security-Site Visual Research for Vibe Security Radar

Date: 2026-08-14
Scope: current first-party websites, rendered at desktop width and inspected for information architecture, visual hierarchy, evidence presentation, freshness, and motion. Socket's rendered site stopped at its bot-verification page, so Socket findings below are limited to the information architecture exposed by its official published pages.

## Recommendation

Vibe Security Radar should look like a public research index, not a cyber-product landing page. The closest structural model is [Trail of Bits](https://trailofbits.com/): light, dense, searchable, dated, and organized around published work. Pair that structure with the search/filter clarity of the [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database), the chart contract of [Cloudflare Radar](https://radar.cloudflare.com/) and the [GitHub Innovation Graph](https://innovationgraph.github.com/global-metrics/git-pushes), the freshness and provenance cues of [Chainguard](https://www.chainguard.dev/), and the restrained product-data presentation of [Semgrep](https://semgrep.dev/).

Do not copy the black-neon treatment used by [Snyk](https://snyk.io/) or [Aikido](https://www.aikido.dev/). It works as promotional theater for a commercial platform, but it makes an evidence ledger feel less neutral and is too close to the current dark-glow direction the user rejected.

The redesign should therefore be light-first, compact, chart-first, and explicit about data state. Color should encode evidence state, not atmosphere.

## What the strongest current examples do

| First-party example | Direct observation | Appropriate translation for Vibe |
| --- | --- | --- |
| [Trail of Bits](https://trailofbits.com/) | Warm near-white canvas, black ink, a small red signal color, mono metadata, thin rules, square modules, prominent global search, corpus totals in the header, dates and type/topic tags on every entry. Its homepage says that all published reviews, research, tools, and talks live in one browsable index. | Make the corpus itself the brand. Put search, exact counts, dates, status, and categories ahead of decorative storytelling. Use this as the primary structural reference. |
| [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database) | A compact dark search header opens into a light database: popular filters, separate "High Profile" and "Most Recent" tables, severity, fix availability, and published dates. | Give Cases a database posture. On the homepage, expose one search field, useful filters, a current trend, and a short recent-cases table. |
| [Chainguard](https://www.chainguard.dev/) | White background, black display type, purple used selectively, rigid grid, and concrete inventory metrics. Its navigation labels the Image Directory "Updated daily," while the page ties verification to SBOMs, provenance, source builds, and traceability rather than a generic trust badge. | Show the generation cutoff and artifact provenance beside every aggregate. Prefer exact operational nouns such as snapshot, source, gate, replay, and correction. |
| [Semgrep](https://semgrep.dev/) | Near-white hero, muted green rather than neon, thin borders, large authentic product-data composites, and charts embedded inside the product view. The page leads with a narrow promise and then shows findings and backlog data. | Keep the main chart visually quiet and let labels, values, and tooltips carry meaning. Reuse the existing Geist typefaces; hierarchy matters more than a new brand font. |
| [Vanta](https://www.vanta.com/) and its [Trust Center](https://www.vanta.com/products/trust-center) | Lilac editorial hero, serif display type, real product UI, and strong separation between claim and supporting interface. Vanta's own guidance describes overview, controls, resources, FAQs, and updates as distinct trust-center areas, and emphasizes continuously monitored evidence. | Keep status, method, evidence links, and update history distinct. A correction log is a trust feature, not footer trivia. Do not imitate the sales framing or customer-logo wall. |
| [Socket Labs](https://socket.dev/labs) and [Socket Blog](https://socket.dev/blog) | The official content separates long-horizon Labs research from a high-frequency threat-intelligence/news stream; both are searchable and categorized. | Preserve Vibe's two evidence tempos: a strict research ledger and a live case catalog. Explain the relationship without merging their counts. |
| [Wiz Research](https://www.wiz.io/research) | Dark charcoal, saturated cobalt and pink, illustration-led sections, a moving post strip, and clear research categories. | Categories and recent discoveries translate; the saturated campaign aesthetic does not. Vibe needs ledger neutrality, not a separate superhero identity. |

These are observations of the current pages. The recommendation to combine them is an inference for Vibe, not a claim that any source prescribes this design.

## Focused homepage and time-series benchmark

The following observations were made on the current first-party pages on 2026-08-14. Recommendations are separated below; they are design inferences for Vibe rather than statements made by the sources.

### Observed current patterns

- **Microsoft Security:** The main [Microsoft Security](https://www.microsoft.com/en-us/security) homepage is a broad commercial hierarchy: campaign hero, enterprise/business/home segmentation, local navigation for overview, products, news, industry recognition, and customer stories, followed by product families, reports, events, analyst recognition, stories, and sales calls to action. [Microsoft Security Insider](https://www.microsoft.com/en-us/security/security-insider/) is the more relevant editorial reference: it leads with featured material, then groups the stream by research theme, while each card carries a category, exact date, and read or watch duration. This is a useful freshness pattern, but the product taxonomy and campaign hero are not a suitable core structure for a small empirical index.
- **Google Project Zero:** [Project Zero](https://projectzero.google/) is a narrow, text-first, reverse-chronological research feed. Entries expose the title, exact date, author, substantial excerpt, and a direct continuation link; the landing page does not interpose a KPI dashboard or aggregate chart above the research. Its strength is authorship and temporal specificity, while its lack of an at-a-glance corpus view would be a poor fit for Vibe's quantitative homepage.
- **Cloudflare Radar:** [Cloudflare Radar](https://radar.cloudflare.com/) puts the global scope and date range above its principal time series, then gives each module a metric description, copyable link, methodology link, and action menu. Its first chart compares current traffic with the previous period and pairs the time series with a compact composition summary. The official [Radar API response contract](https://developers.cloudflare.com/api/resources/radar/subresources/http/subresources/timeseries_groups/) exposes aggregation interval, adjusted date range, `lastUpdated`, normalization, units, and confidence annotations; the [normalization documentation](https://developers.cloudflare.com/radar/concepts/normalization/) warns that min-max-normalized comparisons must be requested together. Its [About page](https://radar.cloudflare.com/about) also identifies data sources, licensing, and per-widget citation support. This is the strongest reference for a reproducible chart contract, though its full product sidebar and many downstream widgets exceed Vibe's scope.
- **Wiz:** The [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database) moves directly from search to technology shortcuts and popular filters, then separates high-profile from most-recent records. Its tables keep severity, score, technology, component, CISA KEV presence, fix availability, and publication date in the scan path. This is the clearest reference for Vibe's latest-cases block and case-index density.
- **Trail of Bits:** [Trail of Bits](https://trailofbits.com/) combines global search and corpus totals in the masthead with featured research, a dated/type-tagged work index, topic filters, recent reports, latest talks, and a featured repository. It makes the body of published work feel primary. The services row and contact path are commercial context that Vibe should omit.
- **GitHub:** The [GitHub Advisory Database](https://github.com/advisories) places reviewed/unreviewed and ecosystem counts beside a search field and a dense current list; severity, CWE, and sort controls remain attached to the results. GitHub's [official browsing documentation](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/browse-advisory-database) documents qualifiers for reviewed state, malware, ecosystem, severity, package, CWE, credit, created/updated dates, withdrawn status, and created/updated sorting. The [GitHub Innovation Graph](https://innovationgraph.github.com/) takes the complementary data-product approach: its homepage defines each metric before linking to data, while an individual [time-series page](https://innovationgraph.github.com/global-metrics/git-pushes) puts the metric definition before the plot and follows each plot with "How to read this chart," methodological notes, controls, and a raw CSV link. Its [methodology page](https://innovationgraph.github.com/methodology) states the cadence, reporting delay, public-activity scope, suppression threshold, and limitations path.

### Recommendations derived for Vibe

1. **Make the first viewport an evidence overview.** Use a compact purpose statement and status strip, then show the trend immediately. Microsoft-style product navigation, carousels, analyst proof, and sales conversion should not precede the data.
2. **Use one global scope row.** Put `Evidence layer`, `Admission state`, `Coverage through`, and `Range` above the chart. The visible title, values, latest-case list, permalink, and download must all resolve from that same state.
3. **Give the chart a publication contract.** Directly below the title, define the event counted, grouping date, denominator, and incomplete-period behavior. In the footer expose `Generated`, `Snapshot`, `Interval`, `Download data`, `Copy link`, and `Method`; place a two-sentence "How to read" note below the plot.
4. **Keep the default plot deliberately small.** One monthly total series is the primary view; the three mutually exclusive causal classes may be an optional comparison. Do not default to a many-series legend or a stacked AI-tool chart. Tool attribution is multi-valued and belongs in a filter or tooltip.
5. **Pair aggregate and records.** Place a five-row latest-cases table directly under or beside the chart, with case ID, repository, causal class, evidence state, publication date, and fix state. This joins the chart discipline of Radar and Innovation Graph to the index discipline of Wiz and GitHub Advisories without copying either interface.
6. **Keep research authorship after the data.** A short latest-research or methodology rail may use Project Zero and Security Insider's date/author/category conventions, but it should follow the current status, chart, and cases.
7. **Expose reproducibility, not merely freshness.** Treat `lastUpdated`, source coverage, aggregation interval, snapshot identity, corrections, and comparability constraints as data, not tooltip trivia. If the catalog is snapshot-generated, never substitute a pulsing live indicator for that contract.

## First-screen composition audit — 2026-08-14

Inspection conditions: the current official pages were rendered at approximately 1280 × 720 and 390 × 844 CSS pixels. The following are direct observations; the rules afterward are recommendations for Vibe.

| Official page | Desktop first screen | Narrow-screen collapse |
| --- | --- | --- |
| [Cloudflare Radar](https://radar.cloudflare.com/) | An intentionally asymmetric application shell places a fixed navigation rail beside a wide work canvas. Scope and date controls sit directly above the principal card; inside that card, the time series takes most of the width and a narrow composition summary occupies the right rail. Compact gutters and thin boundaries create density without crowding. | The navigation rail becomes a menu, global controls stack full width, and the plot remains the first substantial object. The composition summary moves below the plot inside the same card, preserving hierarchy rather than shrinking two columns beyond legibility. |
| [GitHub Innovation Graph](https://innovationgraph.github.com/) | A visually balanced but unequal two-column hero puts oversized identity and one sentence on the left and a commit-square illustration on the right. Large white margins make it calm, but no data chart appears in the first screen. | Navigation collapses cleanly, then copy and the repository action stack before the illustration. The tall hero preserves a large empty interval before the image, delaying the data product; this is not an appropriate mobile model for Vibe. |
| [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database) | A dark two-column hero balances title and description against one illustration, then lets a single search field span nearly the full content grid. The first light database section begins at the bottom of the viewport, so identity, primary action, and data-entry path all appear in one screen. | Navigation collapses and the illustration moves above the heading; title, description, search, and one contextual link then form a single column. Technology and popular-filter groups stack below, while the results table retains desktop-like width. The full-width search is useful for Vibe; the illustration priority and wide table are not. |

### Exact layout rules for Vibe

1. **Use one shared canvas:** `max-width: 1200px`; `24px` desktop and `16px` mobile side padding. Hero copy, status, chart, and case table must share the same outer edges.
2. **Budget the first screen:** after a `64px` header, keep the introduction/status row to `180–220px`, then a `24px` gap. The chart header should begin by roughly `320px` from the top and at least `300px` of the chart module should be visible in a `768px`-high viewport.
3. **Balance information, not decoration:** use a `7/5` desktop split for purpose copy and current snapshot status. Limit the heading to two lines, body to three lines, and actions to one row. Do not reserve a column for an illustration.
4. **Make the chart the dominant rectangle:** use a full-width card with a `3/1` internal split: plot on the left; exact case count, evidence state, cutoff, and snapshot on the right. Put shared scope/range controls above both. Below `768px`, stack the metadata rail under the plot.
5. **Do not preserve desktop emptiness on mobile:** mobile order is wordmark/menu, heading, one-sentence scope, snapshot line, range controls, chart, then recent cases. Hide non-evidentiary visuals. No blank vertical interval should exceed `64px`.
6. **Fit the chart to the phone:** use the available width, reduce the x-axis to four to six labels, and keep an accessible table fallback. Do not force a `760px` plotting canvas or require horizontal panning for the default series.
7. **Keep density functional:** use `24–32px` between modules, `12–16px` inside control groups, thin rules instead of floating cards, and no more than one primary action in the first screen. Search and the latest five cases should follow the chart; secondary tool/cause distributions belong later or on Trends.

## Vibe's actual trust contract

The site should never present a model name as the top-level proof. The current live data contains 30 case files marked `gpt-5.4-high` and 6 marked `independent-audit`; the previous detail page rendered `Verified by ...`. That is provenance, not verification in the scientific sense.

Replace the public trust hierarchy with:

1. **Evidence state:** admitted, held, excluded, or unknown.
2. **Gate result:** seven explicit gate outcomes, with failures and missing evidence visible.
3. **Artifact identity:** snapshot name, generation ID or digest, and replay date.
4. **Review provenance:** models, reasoning modes, and independent reviewers shown in a secondary disclosure.
5. **Primary evidence:** advisory, vulnerable commit, carrier/member topology, fix, and release witness.

On a case page, the headline metadata should read like `Admission: PASS | 7/7 gates | snapshot <id> | replayed <date>`. A neutral "Review provenance" disclosure may then list GPT-5.4, GPT-5.5, GPT-5.6, or independent audit as the underlying record actually requires. Green belongs to a passed evidence contract, never to a model brand.

Repository observation: the homepage currently hard-codes the strict snapshot in `web/src/lib/research-status.ts`, while the public catalog is generated separately. Keep the two visible, but bind both to generated artifacts before claiming they are current.

## Homepage information hierarchy

The first two screens should contain the useful product, not an oversized manifesto.

1. **Header, 64 px:** wordmark; Cases, Trends, Method, Data status; global search; a compact HOLD/PASS status chip.
2. **Compact introduction, 180-220 px:** one-sentence purpose on the left; on the right, an evidence-state panel showing strict-admitted cases, live case pages, pending/unknown, snapshot ID, and generated/replayed dates. Keep the heading near 52 px on desktop, not 72-80 px.
3. **Trend and latest activity:** the trend chart should begin in the first viewport on common laptop screens or immediately below it. Place a five-row latest-cases table beside or directly below the chart.
4. **Scope contract:** the three causal classes and the seven admission gates, compact and scannable.
5. **Corrections and sources:** latest corrections, excluded/held cases, source coverage, and links to replay artifacts.
6. **Institutional context:** Georgia Tech SSLab and project links in the footer, without a commercial logo wall.

Primary navigation should use task nouns: `Cases`, `Trends`, `Method`, `Data status`. "Patterns" is less direct than "Trends" for the chart the user expects. Search should accept CVE/GHSA ID, repository, ecosystem, tool, and causal class.

## The homepage trend chart

Surface the existing chart, but correct its semantic contract before calling it live.

- Title: **Published cases by month**.
- Subtitle: **Live catalog; grouped by advisory publication month**.
- Freshness line: **Snapshot generated <timestamp> | coverage through <date> | 36 case pages**.
- Show 12 months by default, with a single bar per month and the exact total printed or available in a tooltip.
- Use filters for causal class, ecosystem, AI tool, and admission state. Filters should change the denominator shown beside the chart.
- Link a selected month to the corresponding filtered case list.
- Mark the partial current month with an outline or hatch, not a misleading full bar.
- Provide an accessible table fallback and do not rely on color alone.

Do not stack by AI tool when one case can credit multiple tools. The current component already notes that tool credits can exceed the real CVE count; stacking those credits makes bar height disagree with the true total. Use total cases for bar height and show tools in the tooltip or as a separate filter. Add a strict-ledger series only after its monthly data is generated from the same canonical snapshot.

"Real-time" is only truthful if the source is continuously updated. With a generated snapshot, label the module **Latest snapshot** or **Updated daily** and show the timestamp. [Chainguard](https://www.chainguard.dev/) exposes an explicit update cadence, [Wiz](https://www.wiz.io/vulnerability-database) pairs "Most Recent" with published dates, and [Vanta's product guidance](https://help.vanta.com/en/articles/11345372-home-page) treats trends as an at-a-glance view that links into filtered detail. Those are better freshness patterns than an unqualified live dot.

## Recommended visual system

Use a light evidence-paper palette. It is distinct from the source sites while inheriting their restraint.

```css
:root {
  color-scheme: light;
  --background: #f7f7f4;
  --foreground: #17191f;
  --surface: #ffffff;
  --surface-muted: #eff1f4;
  --border: #d8dbe2;
  --muted-foreground: #626977;

  --primary: #2357e6;
  --primary-soft: #eaf0ff;
  --verified: #13795b;
  --verified-soft: #e7f6ef;
  --hold: #8a5100;
  --hold-soft: #fff1d6;
  --failed: #c9362b;
  --failed-soft: #fdebe8;
  --provenance: #6657c7;
  --provenance-soft: #f0edff;

  --chart-direct: #2357e6;
  --chart-contribution: #6657c7;
  --chart-incomplete-fix: #b85014;
  --chart-unknown: #6e7787;
}
```

The core text and state colors above meet WCAG AA contrast for normal text on the background or white surface. Use the pale colors only as fills with their dark semantic counterpart as text.

- **Typography:** keep installed Geist Sans and Geist Mono. Sans for all prose and headings; mono only for IDs, hashes, dates, counts, and state labels. No new font dependency is needed.
- **Grid:** 12 columns, 1200 px maximum content width, 24 px gutters, 1 px rules. Use subtle grid marks only in the hero/status area, never as a full-page texture.
- **Density:** 8/12/16/24/32/48 spacing scale. Tables and charts should be moderately dense; narrative sections may breathe.
- **Shape:** 8-12 px radius for panels, 4-6 px for controls, pills only for statuses and filters. Avoid 24-32 px rounded cards everywhere.
- **Depth:** borders first, one low-opacity shadow only for floating controls. Remove colored glows and blurred blobs.
- **Motion:** functional transitions only: 120-180 ms hover/focus, chart tooltip, and filter changes. No ambient pulsing dot, marquee, parallax, or looping hero animation. Honor `prefers-reduced-motion`.
- **Charts:** thin neutral gridlines, direct labels where practical, tabular numerals, no gradients, no faux radar sweep, and no animation that delays reading.

## Disclosure and freshness pattern

Every aggregate module should carry a small contract line:

`Layer | denominator | coverage cutoff | generated at | snapshot/digest | status`

Example:

`Live catalog | 36 pages | advisories through 2026-08-09 | generated 2026-08-09 09:41 UTC | <generation id> | HOLD`

Use an always-visible Data status page for source coverage, last successful generation, verifier version, snapshot digest, known holds, corrections, and the difference between the strict ledger, live catalog, recall population, and pending review. [Vanta's Trust Center documentation](https://help.vanta.com/en/articles/11345469-vanta-trust-center) explicitly treats updates as a maintained record; for Vibe, corrections and negative results should serve that role.

## Anti-patterns

- Dark navy plus neon green/purple as the entire brand.
- Giant hero copy that pushes the trend below the fold.
- Decorative radar sweeps, scan lines, glowing borders, or "cyber" particles.
- A page-level `Verified by GPT-5.4` badge or any model name styled as a trust seal.
- Mixing strict-ledger, live-catalog, recall, or pending counts without naming the denominator.
- Calling a generated snapshot real-time without a timestamp and refresh contract.
- Stacking multi-valued tool attribution as though the segments were mutually exclusive.
- Hiding HOLD, UNKNOWN, false positives, removed identities, or stale generation behind a green aggregate.
- Customer-logo walls, testimonials, sales CTAs, or copied mascot/illustration systems.
- Excessive cards, pills, gradients, and motion that compete with evidence.

## Design acceptance checks

- A first-time visitor can identify the current status, strict count, live count, data cutoff, and trend definition without scrolling past the second screen.
- Every count names its evidence layer and denominator.
- Model names appear only under provenance, never as the admission result.
- The chart's visible bar height equals the displayed case total.
- HOLD and stale data remain conspicuous in light and dark environments and without color vision.
- Keyboard users can search, filter, inspect chart values, and reach the equivalent case table.
- The page remains credible with all illustrations, logos, and motion removed.
