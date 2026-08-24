# unr-adj2 slice-2 forward-map report

## Verdict: 0 countable / 25 FALSE_POSITIVE. No proposal forwarded to leader replay.

Every row is an unreviewed GHSA whose details field names a concrete mechanism. I read the advisory JSONs from the local advisory-database clone (origin/main) and fetched/read every candidate AI commit diff (git smart-HTTP, blobless depth-1 into /home/hanqing/.cache/ghsa200-sweep-fetch; no GitHub API, no blame/SZZ). In all 25 rows the candidate commit's touched files and hunk are disjoint from the named mechanism; the candidates are feature/CI/docs work, unrelated modules, or security fixes. None is the introduction, so ai_hunk_gate and but_for_gate FAIL on every row and nothing is countable.

## Per-row reasoning

- **GHSA-XR38-W5RC-H3Q4** (zevorn/rt-claw) - FALSE_POSITIVE (no_ai_origin). claw/services/tools/script.c (tool_run_script_execute). candidates add a USB HID mouse driver, Linux functional tests, and a claw_init double-collection fix; none touches script.c.
- **GHSA-RJJH-VX7V-M7MF** (parse-community/parse-server) - FALSE_POSITIVE (no_ai_origin). src/GraphQL/ (introspection 'Did you mean' suggestion). candidates are a prettier Definitions.js regen, an Auth.js validation fix, a clientMetadata option, and a Cloud Function response feature; none touches src/GraphQL.
- **GHSA-5FC6-2494-X3Q8** (parse-community/parse-server) - FALSE_POSITIVE (no_ai_origin). src/GraphQL/ (validation/coercion error class-name disclosure). same parse-server candidate set; disjoint from src/GraphQL.
- **GHSA-JXRP-R7GX-Q4J8** (cure53/DOMPurify) - FALSE_POSITIVE (no_ai_origin). CUSTOM_ELEMENT_HANDLING.tagNameCheck / afterSanitizeElements hook. candidates add SVG presentation attributes, sync 3.4.2, prep 3.4.0, and apply SAFE_FOR_TEMPLATES in RETURN_DOM; none touches custom-element tagNameCheck or the hook.
- **GHSA-V9G2-R7JF-7J84** (parse-community/parse-server) - FALSE_POSITIVE (no_ai_origin). src/GraphQL/ (validation error names custom input fields). same parse-server candidate set; disjoint from src/GraphQL.
- **GHSA-Q2C2-JWJG-8CXX** (mealie-recipes/mealie) - FALSE_POSITIVE (no_ai_origin). mealie/pkgs/safehttp/transport.py (AsyncSafeTransport SSRF guard). candidates improve duplicate-recipe-name error handling in recipe_crud_routes.py + frontend; disjoint from safehttp/transport.py.
- **GHSA-PHH7-MPPP-4JX8** (goauthentik/authentik) - FALSE_POSITIVE (no_ai_origin). authentik SCIM group ingest (source-scoped token adopts admin group). candidates are a FleetDM endpoints connector, outpost/proxyv2 changes, and website docs; disjoint from SCIM source ingest.
- **GHSA-F25X-J567-FFXH** (goauthentik/authentik) - FALSE_POSITIVE (no_ai_origin). authentik SCIM user ingest (source-scoped token takes over matching user). same authentik candidate set; disjoint from SCIM source ingest.
- **GHSA-PX44-P4FG-H68V** (filebrowser/filebrowser) - FALSE_POSITIVE (no_ai_origin). TUS upload cache eviction symlink swap (out-of-scope delete). candidates fix an unreadable-dir panic, address three DIFFERENT disclosures (archive traversal/login DoS/symlink-escape read-write), and a signup error message; none introduces TUS eviction.
- **GHSA-6G9F-8X2V-MQ2C** (filebrowser/filebrowser) - FALSE_POSITIVE (no_ai_origin). self-signup CreateUserDir scope inheritance. same filebrowser candidate set; the security fix addresses other GHSAs, not self-signup scope.
- **GHSA-XCVF-46F4-XWXF** (go-chi/chi) - FALSE_POSITIVE (no_ai_origin). middleware/middleware.go RedirectSlashes (Host header open redirect). candidates touch recoverer, compress, and a new ClientIP middleware; disjoint from RedirectSlashes.
- **GHSA-9F4G-6WHF-F3PV** (go-chi/chi) - FALSE_POSITIVE (no_ai_origin). middleware/realip.go RealIP (first X-Forwarded-For trust). candidates add middleware.ClientIP as a replacement; realip.go is not modified.
- **GHSA-QGXV-HQXP-4RCX** (go-chi/chi) - FALSE_POSITIVE (no_ai_origin). middleware/realip.go RealIP (leftmost XFF trust). candidates add middleware.ClientIP as a replacement; realip.go is not modified.
- **GHSA-XG24-PMHH-M4M9** (go-chi/chi) - FALSE_POSITIVE (no_ai_origin). middleware/realip.go realIP() (True-Client-IP/X-Real-IP/XFF overwrite). candidates add middleware.ClientIP (never mutates RemoteAddr); realip.go is not modified.
- **GHSA-8JX5-5RQ8-69M2** (filebrowser/filebrowser) - FALSE_POSITIVE (no_ai_origin). path canonicalization before access-rule evaluation. same filebrowser candidate set; the security fix is a fix, not an introduction.
- **GHSA-6X93-4CV7-M749** (filebrowser/filebrowser) - FALSE_POSITIVE (no_ai_origin). createUserDir isolation in proxy/hook auto-provisioning. same filebrowser candidate set; disjoint.
- **GHSA-966J-X6RP-F492** (coze-dev/coze-studio) - FALSE_POSITIVE (no_ai_origin). backend/domain/plugin/encrypt/aes.go (hard-coded key). candidates are CI workflow permissions, MCP config/CLAUDE.md, and vscode settings; disjoint from aes.go.
- **GHSA-RXPP-HM83-Q524** (istio/istio) - FALSE_POSITIVE (no_ai_origin). pilot iptables excludeInterfaces annotation (reporter disputes vuln). candidates are InferencePool multi-targetPorts and an echo EPP test mock; disjoint from sidecar injector/iptables.
- **GHSA-3QGQ-R69M-F2F7** (root-project/root) - FALSE_POSITIVE (no_ai_origin). builtins/zlib inftrees.C (OOB read). candidates fix config/thisroot.sh PATH removal; disjoint from bundled zlib.
- **GHSA-9549-FWQ2-P6HG** (davisking/dlib) - FALSE_POSITIVE (no_ai_origin). dlib/external/zlib inflate.C (buffer overflow). candidates are ARC-AGI loader, ACT layer, transformer example, YOLO loss fix, reshape_to; disjoint from external/zlib.
- **GHSA-FM67-X2FW-2G76** (root-project/root) - FALSE_POSITIVE (no_ai_origin). builtins/zlib inffast.C. candidates fix config/thisroot.sh; disjoint from bundled zlib.
- **GHSA-3V74-FJ6R-9QVP** (ixray-team/ixray-1.6-stcop) - FALSE_POSITIVE (no_ai_origin). ixray-1.6-stcop (infinite loop, unspecified). candidates are AI backports of OpenSSL security fixes (memory leak, subgroup, BN_bn2dec, BN_mod_sqrt); remediation, not origin.
- **GHSA-H443-VFP4-X2WP** (ixray-team/ixray-1.6-stcop) - FALSE_POSITIVE (no_ai_origin). ixray-1.6-stcop (info disclosure, unspecified). same OpenSSL fix backports; remediation, not origin.
- **GHSA-WH8R-3R39-MCJJ** (ixray-team/ixray-1.6-stcop) - FALSE_POSITIVE (no_ai_origin). ixray-1.6-stcop (out-of-bounds write, unspecified). same OpenSSL fix backports; remediation, not origin.
- **GHSA-WHPV-427C-7HC3** (kubernetes/kubernetes) - FALSE_POSITIVE (cross_bound). ingress-nginx auth-proxy-set-headers annotation (cross-bound repo). candidates are agnhost/etcd bumps, vendored dep updates, kubelet devicemanager and podresources fixes; component is kubernetes/ingress-nginx, not kubernetes/kubernetes.

## Blockers
- all 25 rows are false positives: no candidate AI commit introduces the advisory's named mechanism (0 countable)
- GHSA-WHPV-427C-7HC3 is cross-bound: advisory names kubernetes/ingress-nginx but the row repository is kubernetes/kubernetes
- advisories are unreviewed with empty affected[] and no fix commit, so release/fix_reversal/topology stay UNKNOWN even where a mechanism is named
