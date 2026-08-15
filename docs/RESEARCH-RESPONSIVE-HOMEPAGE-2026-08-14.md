# Responsive Homepage Research for Vibe Security Radar

Date: 2026-08-14

Scope: responsive layout, container and grid behavior, fluid type and spacing, charts, and AI tool icon accessibility for the current Next.js and Tailwind CSS homepage. Sources are official platform documentation or first-party design systems.

## Recommendation

Treat the complaint as a composition problem, not a request to fill every pixel. Keep the bounded `max-w-6xl` research canvas, but let each component change layout when its content no longer fits. web.dev explicitly says that breakpoints should be determined by content rather than device classes, and recommends starting small and adding only the breakpoints the content needs. Tailwind's responsive system is likewise mobile-first: unprefixed utilities are the base and prefixed utilities apply from their threshold upward. [web.dev responsive design basics](https://web.dev/articles/responsive-web-design-basics?hl=en#how_to_choose_breakpoints), [Tailwind responsive design](https://tailwindcss.com/docs/responsive-design#working-mobile-first)

For this homepage, the practical result is:

1. Keep the hero and chart stacked until the page content area can give the copy about 23rem and the chart about 41rem after the gap.
2. Keep the four analytical sections in a 1-column or 2-column grid. Do not force four narrow columns inside the capped canvas.
3. Restore the existing AI tool marks at a visible 20px size beside their text labels.
4. Keep the chart responsive to its own allocated width, with a compact narrow version and an accessible data table.
5. Use fluid type and spacing only for fine adjustment between the few structural breakpoints.

This preserves density without returning to an oversized vertical homepage.

## What happened to the AI tool icons

The assets were not deleted. At inspection time, 46 SVG files remained in the [tool icon directory](../web/public/icons/tools/), including light and dark variants. The [homepage](../web/src/app/page.tsx) mapped only four aggregate keys, and [DistributionBars](../web/src/components/distribution-bars.tsx) rendered those marks at 14px. That makes the icons visually incidental even though they technically exist.

Reuse the existing [ToolIcon](../web/src/components/tool-icon.tsx) at its default 20px size. Do not add another icon package and do not redraw the SVGs. Carbon's first-party icon system uses 16, 20, 24, and 32px sizes, so 20px is an established compact UI size and already matches this repository's component default. [Carbon icon usage](https://carbondesignsystem.com/elements/icons/usage/)

Accessibility depends on context:

- When a logo sits beside the visible tool name inside the same row or link, the image is redundant and should use `alt=""` or be inside an `aria-hidden="true"` wrapper. WAI uses this exact pattern for a logo that supplements visible link text. [WAI functional images, example 2](https://www.w3.org/WAI/tutorials/images/functional/#logo-image-within-link-text)
- When an icon is the only content of a control, its accessible name must describe the action or destination, not the artwork. WAI gives examples such as `W3C home`, `search`, and `print this page`. [WAI functional images](https://www.w3.org/WAI/tutorials/images/functional/)
- If a whole tool row is clickable, make the row the target rather than the 20px mark. WCAG 2.2 requires pointer targets to be at least 24 by 24 CSS pixels unless an exception such as sufficient spacing applies. [WAI target size minimum](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html)
- Preserve the existing intrinsic-width logic for non-square marks rather than forcing every SVG into a square. SVG `preserveAspectRatio` with its default `meet` behavior preserves the aspect ratio and keeps the full `viewBox` visible. [MDN `preserveAspectRatio`](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Attribute/preserveAspectRatio)

## Layout contract

The following thresholds are starting points derived from the actual homepage content. They describe available content width, not named devices; the final breakpoint should be moved if real text, labels, or controls fail earlier. That follows web.dev's rule to resize from small upward and introduce a breakpoint when the content needs it. [web.dev breakpoint guidance](https://web.dev/articles/responsive-web-design-basics?hl=en#pick_major_breakpoints_by_starting_small_then_working_up)

| Available content width | Hero and trend | Pattern sections | Side padding |
| --- | --- | --- | --- |
| Below 40rem | Copy, then chart | 1 column | 1rem |
| 40rem to below 67rem | Copy, then chart | 2 columns | 1.5rem |
| 67rem and above | About 36% copy / 64% chart | 2 columns | 1.5rem |

Use the existing centered `max-w-6xl` canvas rather than stretching the page across ultrawide monitors. Observable Framework caps its normal documentation and report layout at 1152px, while GOV.UK uses a bounded page width and limits readable text lines; both are first-party precedents for a compact information product. [Observable Framework layout](https://observablehq.com/framework/getting-started#layout), [GOV.UK layout](https://design-system.service.gov.uk/styles/layout/#screen-size)

The hero split can use a container threshold instead of a viewport threshold:

```tsx
<div className="@container">
  <div className="grid gap-7 @min-[67rem]:grid-cols-[minmax(0,0.72fr)_minmax(0,1.28fr)] @min-[67rem]:gap-10">
    ...
  </div>
</div>
```

Tailwind CSS v4 supports container queries in core: `@container` establishes the query container and variants such as `@md:` or `@min-[...]` respond to the parent's actual width. No plugin or JavaScript resize listener is needed for this layout. [Tailwind container queries](https://tailwindcss.com/docs/responsive-design#container-queries)

For the four pattern sections, the simplest correct rule is `grid-cols-1 sm:grid-cols-2` with no later four-column override. In the rejected four-column arrangement, a 1120px viewport left about 1072px after side padding; three 32px gaps then left about 244px per column. Even at the capped canvas width, each column was only about 252px. That is too little for the current multi-line headings, descriptions, labels, and values.

If the number or content of these modules later changes, CSS Grid can calculate the column count intrinsically with `repeat(auto-fit, minmax(..., 1fr))`; MDN documents this as the pattern for creating only as many columns as fit. [MDN CSS Grid, as many columns as will fit](https://developer.mozilla.org/en-US/docs/Learn_web_development/Core/CSS_layout/Grids#as_many_columns_as_will_fit)

## Fluid type and spacing

Use structural breakpoints for structural changes and `clamp()` for small continuous changes between them. MDN documents that `clamp(minimum, preferred, maximum)` can scale type with viewport width while enforcing lower and upper bounds. For font sizes, MDN advises a relative maximum at least twice the minimum so text can still scale to 200% under zoom. [MDN `clamp()`](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Values/clamp)

A suitable starting point is:

```css
.home-title {
  font-size: clamp(1.75rem, 1.25rem + 2vw, 3.5rem);
}

.home-section {
  padding-block: clamp(1.5rem, 1rem + 2vw, 2.75rem);
}
```

Keep prose widths bounded. web.dev recommends introducing a text-width constraint when lines grow beyond roughly 70 to 80 characters, and GOV.UK recommends no more than about 75 characters per line for its service layouts. [web.dev text optimization](https://web.dev/articles/responsive-web-design-basics?hl=en#optimize_text_for_reading), [GOV.UK layout](https://design-system.service.gov.uk/styles/layout/#screen-size)

## Responsive chart contract

The current server-rendered SVG approach is appropriate. Keep a `viewBox`, `w-full`, and proportional height for the wide chart; the SVG `viewBox` defines the internal coordinate system that scales into the rendered viewport. [MDN `viewBox`](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Attribute/viewBox), [MDN `preserveAspectRatio`](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Attribute/preserveAspectRatio)

Do not merely shrink the 720-unit desktop chart until its labels are illegible. When the chart container becomes narrow, switch tick density or representation based on the chart container. Observable's first-party dashboard guidance likewise renders charts from the containing cell's width and collapses multi-column grids on narrow windows. [Observable Framework layout](https://observablehq.com/framework/getting-started#layout)

For this chart:

- Below about 28rem of chart width, use the compact bar representation and at most six visible x-axis labels.
- At 28rem and above, use the full SVG line chart.
- Keep exact values in visible labels or tooltips, mark a partial month with text or a symbol, and never rely on color alone. WCAG says color cannot be the only visual means of conveying information. [WAI use of color](https://www.w3.org/WAI/WCAG22/Understanding/use-of-color)
- Keep the short accessible chart name and the complete data table. WAI classifies charts as complex images and requires both a short identification and a detailed textual equivalent; its examples use structured text and tables for the detail. [WAI complex images](https://www.w3.org/WAI/tutorials/images/complex/)
- Do not add a chart library for this. The existing SVG, CSS/container variants, and table already cover the requirement.

## Acceptance checks

1. Test 320, 390, 639, 640, 1119, 1120, 1440, and 1920 CSS-pixel viewports, plus 200% and 400% zoom. The 320px case is required because WCAG Reflow expects horizontally written content to fit a width equivalent to 320 CSS pixels without two-dimensional scrolling, except where a two-dimensional layout is essential. [WAI Reflow](https://www.w3.org/WAI/WCAG22/Understanding/reflow)
2. At every width, verify no page-level horizontal overflow, no clipped focus outline, no hero orphaned beside an undersized chart, and no analytical column narrower than its longest unbreakable label.
3. Verify the AI tooling rows show the 20px marks in both themes, preserve non-square aspect ratios, and still expose each visible tool name once to the accessibility tree.
4. Verify the narrow chart has readable labels, the wide chart does not collide, the partial-period marker is not color-only, and the table contains the same month/value pairs as the graphic.
5. Check immediately below and above each real breakpoint. Tailwind's mobile-first variants apply at the threshold and continue upward, so boundary checks catch the most likely cascade mistakes. [Tailwind responsive design](https://tailwindcss.com/docs/responsive-design)

## Minimal implementation order

1. Keep the page canvas and 16px/24px gutters.
2. Keep the pattern grid at one then two columns; remove any four-column promotion.
3. Switch the hero/chart at the content-led 67rem container threshold.
4. Render the existing AI tool marks at 20px beside labels.
5. Make the chart's compact/full switch depend on chart-container width.
6. Run the breakpoint and zoom checks above.

This requires no new dependency, no new icon assets, and no new design-system abstraction.
