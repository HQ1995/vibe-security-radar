# fwd-slice-6 timeboxed adjudication

Verdict-first: 0 CONFIRM, 21 FALSE_POSITIVE (no_ai_origin), 4 UNKNOWN, 0 countable. Worker proposal only.

Assigned 25 no-fix-ref rows from fwd-slice-6. Method was agentic file-list and local subject reading. Git blame and SZZ were not used. Unique candidate diffs were not fully readable because pools were missing or promisor blobs required github.com and DNS failed. Missing evidence was not converted into FAIL; unread overlapping rows stay UNKNOWN.

Identity used the assigned GHSA public IDs plus summaries; local first-party advisory JSON paths from extract.py were missing, so identity_gate stays UNKNOWN on every row. Fix-reversal, release, topology, and uniqueness stay UNKNOWN on every row because this slice has no fix refs and no countable PASS.

## Row 1: GHSA-FFQ7-898W-9JC4 — FALSE_POSITIVE

Repository: dnnsoftware/Dnn.Platform. Candidate `5888d71f3547` files: Dnn.AdminExperience/Dnn.PersonaBar.Extensions/Components/Pages/PagesControllerImpl.cs, Dnn.AdminExperience/EditBar/Dnn.EditBar.UI/Items.

Candidate only touches PersonaBar PagesControllerImpl and EditBar items. That cannot create stored XSS via SVG upload.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 2: GHSA-FPJ4-9QHX-5M6M — FALSE_POSITIVE

Repository: dnnsoftware/Dnn.Platform. Candidate `5888d71f3547` files: Dnn.AdminExperience/Dnn.PersonaBar.Extensions/Components/Pages/PagesControllerImpl.cs, Dnn.AdminExperience/EditBar/Dnn.EditBar.UI/Items.

Candidate is PersonaBar page/edit-bar code, not the friend-request acceptance path.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 3: GHSA-2RHW-GW3F-477J — FALSE_POSITIVE

Repository: dnnsoftware/Dnn.Platform. Candidate `5888d71f3547` files: Dnn.AdminExperience/Dnn.PersonaBar.Extensions/Components/Pages/PagesControllerImpl.cs, Dnn.AdminExperience/EditBar/Dnn.EditBar.UI/Items.

Candidate files are admin page/edit-bar UI, not install-time HostGUID generation.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 4: GHSA-R7P8-XQ5M-436C — FALSE_POSITIVE

Repository: jetty/jetty.project. Candidate `c1e300d75731` files: jetty-core/jetty-osgi/src/main/java/org/eclipse/jetty/osgi/util/BundleClassLoaderHelper.java.

Candidate only touches OSGi BundleClassLoaderHelper, not JASPIAuthenticator.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 5: GHSA-W54J-7WPM-CRHJ — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate is an SVG gradientTransform double-free fix in coders/svg.c plus SVG tests. That cannot create an FTXT encoder overflow.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 6: GHSA-Q8H3-JV9V-57QX — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate only touches SVG gradientTransform parsing, not morphology origin validation.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 7: GHSA-98CP-RJ9F-6V5G — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate files are SVG coder and SVG tests, not the MNG encoder.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 8: GHSA-8VFJ-Q2CP-5M5J — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate is SVG gradientTransform parsing, not the magnify operator.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 9: GHSA-PMPG-6PWW-FG6Q — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate only edits SVG coder and SVG tests, not ConnectedComponentsImage.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 10: GHSA-X928-4434-CRQJ — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate is an SVG gradientTransform double-free fix, not PNG/MNG encoder leak handling.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 11: GHSA-FCPV-W245-R2Q7 — FALSE_POSITIVE

Repository: dnnsoftware/Dnn.Platform. Candidate `5888d71f3547` files: Dnn.AdminExperience/Dnn.PersonaBar.Extensions/Components/Pages/PagesControllerImpl.cs, Dnn.AdminExperience/EditBar/Dnn.EditBar.UI/Items.

Candidate only touches PersonaBar PagesControllerImpl and EditBar items, not a Core security-analysis rule surface named by the advisory summary.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 12: GHSA-355H-QMC2-WPWF — FALSE_POSITIVE

Repository: jetty/jetty.project. Candidate `c1e300d75731` files: jetty-core/jetty-osgi/src/main/java/org/eclipse/jetty/osgi/util/BundleClassLoaderHelper.java.

Candidate only touches OSGi classloader helpers, not HTTP chunked parsing.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 13: GHSA-MP82-FMJ6-F22V — FALSE_POSITIVE

Repository: pyload/pyload. Candidate `23c48a5c3cdd` files: src/pyload/plugins/downloaders/DarkiboxCom.py.

Candidate only adds a DarkiboxCom downloader plugin. That cannot create the X-Forwarded-Proto cookie-secure downgrade.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 14: GHSA-4FXQ-2X3X-6XQX — FALSE_POSITIVE

Repository: openziti/zrok. Candidate `6eb8fe8c667e` files: website/docusaurus.config.ts.

Candidate only edits website/docusaurus.config.ts, not the OAuth callback error renderer.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 15: GHSA-CPF9-PH2J-CCR9 — FALSE_POSITIVE

Repository: openziti/zrok. Candidate `6eb8fe8c667e` files: website/docusaurus.config.ts.

Candidate is a Docusaurus website config change, not session-cookie parsing.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 16: GHSA-3JPJ-V3XR-5H6G — FALSE_POSITIVE

Repository: openziti/zrok. Candidate `6eb8fe8c667e` files: website/docusaurus.config.ts.

Candidate only touches website/docusaurus.config.ts, not the unaccess API ownership check.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 17: GHSA-JHM7-29PJ-4XVF — UNKNOWN

Repository: node-oauth/node-oauth2-server. Candidate `6f04e2e92c19` files: lib/utils/crypto-util.js.

Candidate lib/utils/crypto-util.js overlaps a PKCE/verifier crypto path, but the pool clone is missing so the diff was not read. Overlap is not converted into FAIL.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=UNKNOWN, topology_gate=UNKNOWN, but_for_gate=UNKNOWN, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Unread overlapping candidate. Identity, topology, fix-reversal, release, and uniqueness stay UNKNOWN because advisory JSON and fix refs were not closed.

## Row 18: GHSA-VP6R-9M58-5XV8 — UNKNOWN

Repository: omnifaces/omnifaces. Candidate `19edc2de50f9` files: src/main/java/org/omnifaces/ApplicationInitializer.java, src/main/java/org/omnifaces/ApplicationListener.java.

Candidate ApplicationInitializer/ApplicationListener files can carry CDN mapping, but the pool clone is missing so the diff was not read. Overlap is not converted into FAIL.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=UNKNOWN, topology_gate=UNKNOWN, but_for_gate=UNKNOWN, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Unread overlapping candidate. Remaining gates stay UNKNOWN.

## Row 19: GHSA-V9WW-2J6R-98Q6 — UNKNOWN

Repository: fastify/middie. Candidate `3d27e847737f` files: lib/engine.js, test/req-url-stripping.test.js.

Candidate lib/engine.js plus req-url-stripping tests overlap the duplicate-slash bypass, but git cat-file/fetch failed on github.com DNS so the diff was not read. Overlap is not converted into FAIL.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=UNKNOWN, topology_gate=UNKNOWN, but_for_gate=UNKNOWN, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Unread overlapping candidate. Remaining gates stay UNKNOWN.

## Row 20: GHSA-X3CV-R3G3-FPG9 — UNKNOWN

Repository: neo4j-contrib/mcp-neo4j. Candidate `1d3c88743e2e` files: servers/mcp-neo4j-data-modeling/CHANGELOG.md, servers/mcp-neo4j-data-modeling/src/mcp_neo4j_data_modeling/server.py.

Candidate mcp-neo4j-data-modeling server.py overlaps an MCP server surface that could host read_only/CALL handling, but the diff was not read before timebox. Overlap is not converted into FAIL.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=UNKNOWN, topology_gate=UNKNOWN, but_for_gate=UNKNOWN, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Unread overlapping candidate. Remaining gates stay UNKNOWN.

## Row 21: GHSA-F58V-P6J9-24C2 — FALSE_POSITIVE

Repository: YesWiki/yeswiki. Candidate `eb440b844320` files: tools/bazar/presentation/javascripts/jquery.galleriffic.js.

Candidate only touches jquery.galleriffic.js presentation script, not EntryManager::formatData or id_fiche SQL construction.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File-list mismatch is affirmative exclusion. Advisory JSON was not local; remaining gates stay UNKNOWN.

## Row 22: GHSA-6384-M2MW-RF54 — FALSE_POSITIVE

Repository: traefik/traefik. Candidate `8ac8473554d7` files: docs/content/expose/docker.md.

Candidate only edits docs/content/expose/docker.md (whoami docker-guide middleware docs). That cannot create ForwardAuth X-Forwarded-Prefix bypass.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 23: GHSA-5M6W-WVH7-57VM — FALSE_POSITIVE

Repository: traefik/traefik. Candidate `8ac8473554d7` files: docs/content/expose/docker.md.

Candidate is docker-guide documentation, not forwarded-alias authentication code.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 24: GHSA-6JWX-7VP4-9847 — FALSE_POSITIVE

Repository: traefik/traefik. Candidate `8ac8473554d7` files: docs/content/expose/docker.md.

Candidate only touches docker expose docs, not StripPrefixRegex middleware.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 25: GHSA-6X2Q-H3CR-8J2H — FALSE_POSITIVE

Repository: traefik/traefik. Candidate `8ac8473554d7` files: docs/content/expose/docker.md.

Candidate is a docker-guide markdown edit, not BasicAuth credential comparison.

Gates: identity_gate=UNKNOWN, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

