# GHSA-W28W-GP39-M4P6 fix-gap closure

## Decisive result

- Published case `GHSA-W28W-GP39-M4P6` currently resolves to canonical row `alias-50a179b091fae05cd3c940e9`, live revision `2`, change set `df53d33c-4109-44a2-9e6e-b607c99658b9`. That row has no canonical `code_evidence`, which is why its generated page has candidate evidence but no fix hunk.
- The older identity row `alias-3a0294dfd1f9cff8531aacfd` is live revision `1` and explicitly folds into the kept row; it must not become a second published case.
- `e4a0ebf49e3a78d5d7796c8480bf9a4f0c54d19e` is the direct, single-parent security fix. Its parent is `70912ce716e00d64cf5eff31ad3aabab8b1365c7`; it changes the Nunjucks renderer plus regression tests. The first-party advisory describes the same three controls: own-data-only input sanitization, rejection of constructor/prototype traversal, and prohibition of template function calls.
- `047756f4c8caf91c5868eeb42520c938393277b0` is only PR #404's merge commit. It contains `e4a0ebf4…`, but it is not an ancestor of the fixed `typescript/2.0.0-beta.5` release commit `d8891f66b93bfa37f0611186258c953e12e87fd3`. Conversely, `e4a0ebf4…` is the direct parent of `d8891f66…`. Therefore the honest `minimum_fix_set` is exactly `["e4a0ebf49e3a78d5d7796c8480bf9a4f0c54d19e"]`; do not substitute the merge SHA.
- The local primary-source clone is `.ai-slop/state/repos/microsoft_prompty`; it is non-shallow and contains the candidate, direct fix, merge, and both release objects. No `unresolved_reason` is warranted (`null`/absent).

Primary sources: [first-party advisory](https://github.com/microsoft/prompty/security/advisories/GHSA-w28w-gp39-m4p6), [direct fix](https://github.com/microsoft/prompty/commit/e4a0ebf49e3a78d5d7796c8480bf9a4f0c54d19e), [fixed source](https://github.com/microsoft/prompty/blob/e4a0ebf49e3a78d5d7796c8480bf9a4f0c54d19e/runtime/typescript/packages/core/src/renderers/nunjucks.ts#L16-L110), [PR #404 merge](https://github.com/microsoft/prompty/commit/047756f4c8caf91c5868eeb42520c938393277b0).

## JSON-ready fix evidence

- `fix_url`: `https://github.com/microsoft/prompty/commit/e4a0ebf49e3a78d5d7796c8480bf9a4f0c54d19e`
- `fix_marker`: `Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>`
- `fix_patch_files`: `["runtime/typescript/packages/core/src/renderers/nunjucks.ts"]`
- `fix_patch_sha256`: `61f2622257aa8beb39bee219cd58dd68a77a4ac93b7ead24b70df5cd8d05ad4c`
- Hash rule: SHA-256 of `hunk_1.code + "\n" + hunk_2.code`, with the two strings below and no trailing newline.
- `annotation_mode`: `hunk_specific`
- `required_anchors.fix`: `["UNSAFE_PROPERTIES", "Object.getOwnPropertyDescriptor", "runtime.callWrap = safeCallWrap", "renderSafely(template, sanitizeInputs(modified))"]`

Both entries use file `runtime/typescript/packages/core/src/renderers/nunjucks.ts`, role `fix`.

Hunk 1 annotation: `The fix replaces unrestricted JavaScript object traversal with own-data-only lookup, strips unsafe constructor and prototype keys from inputs, and blocks every template function call while Nunjucks renders. Restoring the original runtime hooks in finally confines those guards to this render operation.`

```diff
@@ -13,11 +13,91 @@ import type { Prompty } from "../model/agent/prompty.js";
 import type { Renderer } from "../core/interfaces.js";
 import { prepareRenderInputs } from "./common.js";
 
+type NunjucksRuntime = {
+  memberLookup: (object: unknown, property: unknown) => unknown;
+  callWrap: (callable: unknown, name: string, context: unknown, args: unknown[]) => unknown;
+};
+
+const UNSAFE_PROPERTIES = new Set(["__proto__", "constructor", "prototype"]);
+
 const env = new nunjucks.Environment(null, {
   autoescape: false,
   throwOnUndefined: false,
 });
 
+function safeMemberLookup(object: unknown, property: unknown): unknown {
+  if (typeof property === "string" && UNSAFE_PROPERTIES.has(property)) {
+    throw new Error(`Unsafe template member access: ${property}`);
+  }
+
+  if (
+    (typeof property !== "string" && typeof property !== "number") ||
+    object === null ||
+    typeof object !== "object"
+  ) {
+    return undefined;
+  }
+
+  const descriptor = Object.getOwnPropertyDescriptor(object, property);
+  return descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
+}
+
+function safeCallWrap(_callable: unknown, name: string, _context: unknown, _args: unknown[]): never {
+  throw new Error(`Template function calls are not allowed: ${name}`);
+}
+
+function sanitizeValue(value: unknown, seen = new WeakMap<object, unknown>()): unknown {
+  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
+    return value;
+  }
+
+  if (typeof value !== "object") {
+    return undefined;
+  }
+
+  const existing = seen.get(value);
+  if (existing !== undefined) {
+    return existing;
+  }
+
+  if (Array.isArray(value)) {
+    const result: unknown[] = [];
+    seen.set(value, result);
+    for (const item of value) {
+      result.push(sanitizeValue(item, seen));
+    }
+    return result;
+  }
+
+  const result = Object.create(null) as Record<string, unknown>;
+  seen.set(value, result);
+  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
+    if (!UNSAFE_PROPERTIES.has(key) && "value" in descriptor) {
+      result[key] = sanitizeValue(descriptor.value, seen);
+    }
+  }
+  return result;
+}
+
+function sanitizeInputs(inputs: Record<string, unknown>): Record<string, unknown> {
+  return sanitizeValue(inputs) as Record<string, unknown>;
+}
+
+function renderSafely(template: string, inputs: Record<string, unknown>): string {
+  const runtime = nunjucks.runtime as unknown as NunjucksRuntime;
+  const memberLookup = runtime.memberLookup;
+  const callWrap = runtime.callWrap;
+  runtime.memberLookup = safeMemberLookup;
+  runtime.callWrap = safeCallWrap;
+
+  try {
+    return env.renderString(template, inputs);
+  } finally {
+    runtime.memberLookup = memberLookup;
+    runtime.callWrap = callWrap;
+  }
+}
+
 export class NunjucksRenderer implements Renderer {
   async render(
     agent: Prompty,
```

Hunk 2 annotation: `The vulnerable sink previously passed prepared host values straight to the unrestricted environment. This call-site replacement makes both input sanitization and the guarded Nunjucks runtime mandatory on the actual render path.`

```diff
@@ -25,6 +105,6 @@ export class NunjucksRenderer implements Renderer {
     inputs: Record<string, unknown>,
   ): Promise<string> {
     const [modified] = prepareRenderInputs(agent, inputs);
-    return env.renderString(template, modified);
+    return renderSafely(template, sanitizeInputs(modified));
   }
 }
```

The two source hunks are the minimal complete causal fix evidence. The test-file changes are useful regression evidence but are not needed in `fix_hunks` because they do not close the runtime sink.
