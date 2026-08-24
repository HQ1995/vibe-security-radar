# Adjudication report — unr-adj2-slice-8 (25 rows)

Verdict: **0 countable**. 25 REJECT. Every candidate AI commit is in a code area disjoint from the mechanism named by its advisory; none authors the vulnerable hunk.

Method: read each first-party advisory JSON from the local advisory-database clone (13 rows; the 12 newest getgrav advisories read from the live github.com/advisories page because they are not yet in the DB sync), fetched each candidate AI commit into the sweep pool via git smart-HTTP (--filter=blob:none, no GitHub API, no blame/SZZ), then compared the commit changed files (git diff-tree) and message against the advisory mechanism.

Cross-cutting: (1) all 25 advisories are unreviewed (github_reviewed:false) with empty affected[]; (2) 13 getgrav advisories name grav plugins (login/form/api) and 1 rustdesk advisory names rustdesk-client, yet the slice maps them to getgrav/grav and rustdesk/hbb_common respectively — cross-repo mappings whose candidates cannot author the plugin/client mechanism.

### GHSA-38MM-MXVC-J98Q — getgrav/grav → REJECT

- aliases: CVE-2026-65603; CWE CWE-269
- mechanism: The Grav Login plugin (grav-plugin-login) versions <= 3.8.11 contain a privilege escalation flaw in the authenticated profile self-update handler (processUserProfile(), the update_user task). Unlike the registration handler, this handler does not strip privilege fields ('groups','access') from user-submitted form data before persisting them. When an administrator has added 'groups' and/or 'access' to plugins.login.user_registration.fields and the default 'regular'/DataUser account backend is in use, a low-privilege authenticated user can POST crafted profile form data (e.g. access[admin][super]=true) to escalate to super-admin, enabling admin panel access, scheduler abuse (RCE), and Twig evaluation. Fixed in 3.8.12.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-login profile self-update privilege escalation (unstripped groups/access fields)): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-X4CG-FXGX-67GM — getgrav/grav → REJECT

- aliases: CVE-2026-66400; CWE CWE-613
- mechanism: Grav Login Plugin versions before 3.8.13 contain an insufficient session expiration vulnerability in TokenStorage.php where the findTriplet() method fails to properly validate Remember Me token timestamps. Attackers with a captured Remember Me cookie can authenticate indefinitely instead of the configured timeout period, as the expiry check compares an array to a scalar value which always evaluates incorrectly in PHP.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-login Remember Me token timestamp not validated (TokenStorage.findTriplet)): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-85VC-29FC-65GW — getgrav/grav → REJECT

- aliases: CVE-2026-69087; CWE CWE-601
- mechanism: The Grav form plugin (getgrav/grav-plugin-form) before 9.1.13 contains an open redirect vulnerability. Since v9.1.11, the redirect process action evaluates user-supplied form data inside Twig expressions, and Grav::redirect() accepts external URLs without origin validation. When a form blueprint defines a redirect target such as redirect: "{{ form.value('next') }}" using an attacker-controllable field, an unauthenticated form submitter can supply a value like https://evil.com to cause a 302 redirect to an arbitrary external site, enabling phishing.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-form open redirect via Twig redirect action): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-VJ8J-973F-R65J — getgrav/grav → REJECT

- aliases: CVE-2026-69088; CWE CWE-94
- mechanism: Grav CMS versions 2.0.7 through 2.0.10 fail to validate fully-qualified static method calls (Class::method) in blueprint dynamic-field directives because Blueprint::isSafeDynamicCall() only applies its dangerous-callable denylist to strings that do not contain '::'. An account with only page-editing rights (admin.pages, not super-admin or admin.pages_twig) can plant a directive in a page's form-field frontmatter that invokes an arbitrary public static PHP method with attacker-controlled arguments. Using built-in gadget methods this allows reading of any server-readable file (disclosed to anonymous visitors of the crafted page) and arbitrary creation/copying of files and directories under the web-server account. Fixed in 2.0.11.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Grav CMS blueprint dynamic-field Class::method validation gap (Blueprint::isSafeDynamicCall)): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-83X3-QGQ9-RFCQ — jenkinsci/jenkins → REJECT

- aliases: CVE-2026-19429; CWE CWE-59
- mechanism: Jenkins FilePath.untarFrom() (all versions) validates symlink destinations but not targets, bypassing CVE-2026-33001. Any user with Item/Build access triggers tar extraction via POST /job/{name}/build, writing persistent symlinks into the tool cache. Symlinks to secrets/master.key, hudson.util.Secret, credentials.xml, and users/*/config.xml read via GET /job/{name}/lastBuild/consoleText enable offline AES decryption of all credentials and admin API tokens without bcrypt cracking, achieving RCE.
- candidates: 33b3b3b82b41, c2fd9da8bc9c, e01dd6450959, 188baf00e23d, c701361ec7bc
- candidate files: src/main/js/util/dom.js; core/src/main/java/hudson/security/HudsonPrivateSecurityRealm.java; core/src/main/java/jenkins/views/Header.java + navigation/header actions (java/jelly)
- AI marker: Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Jenkins FilePath.untarFrom symlink target validation bypass): src/main/js/util/dom.js; core/src/main/java/hudson/security/HudsonPrivateSecurityRealm.java; core/src/main/java/jenkins/views/Header.java + navigation/header actions (java/jelly)

### GHSA-3MPX-XV5P-92MV — getgrav/grav → REJECT

- aliases: CVE-2026-72821
- mechanism: Grav Form plugin versions before 9.1.15 contain a stored cross-site scripting vulnerability in radio and toggle field option labels rendered with the Twig |raw filter. Attackers with form authoring permissions can inject HTML and script payloads in option labels that execute in the browsers of visitors and administrators viewing the form.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-form stored XSS via |raw radio/toggle labels): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-993X-642G-H4X5 — getgrav/grav → REJECT

- aliases: CVE-2026-72822
- mechanism: The getgrav/grav-plugin-api Composer package before 1.0.13 (affected <= 1.0.12) fails to enforce API key scope caps on the disable2fa endpoint. Unlike the sibling generate2fa endpoint, disable2fa authorizes the admin (non-self) path solely via ACL reads (isSuperAdmin/hasPermission) and never invokes requirePermission(), so the api_key_scopes cap is never applied. As a result, a holder of a narrow-scope API key on a super account, or a non-super account whose ACL includes api.users.write, can force-disable two-factor authentication on any non-super target account via POST /api/v1/users/{user}/2fa/disable without providing a TOTP code, facilitating account takeover.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-api disable2fa API-key scope-cap bypass): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-WVXR-6V52-GFMH — getgrav/grav → REJECT

- aliases: CVE-2026-72819
- mechanism: Grav CMS before 2.0.13 contains a remote code execution vulnerability in the Flex Objects plugin settings validation that allows authenticated users to execute arbitrary code by uploading a ZIP file containing PHP code. Attackers can bypass routine name validation by using array notation instead of string notation, call the unZip routine with a malicious archive, and write PHP files to the web root for execution.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Grav CMS Flex Objects settings validation RCE (ZIP upload)): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-4JRC-QC5X-3WRR — getgrav/grav → REJECT

- aliases: CVE-2026-72827
- mechanism: Grav CMS before 2.0.13 contains a server-side template injection vulnerability in email-action parameters that allows low-privileged page editors to execute arbitrary operating-system commands. Attackers can inject Twig payloads using the unsandboxed find filter in email subject, body, to, or from fields to achieve remote code execution when forms are submitted.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Grav CMS email-action parameter SSTI (unsandboxed find filter)): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-6959-H8J7-RR7M — getgrav/grav → REJECT

- aliases: CVE-2026-72826
- mechanism: The getgrav/grav-plugin-api plugin before 1.0.13 fails to validate that the scopes of a newly created API key are a subset of the caller's scopes in createApiKey. The self-target path of requireApiKeyPermission() requires only the baseline api.access scope, and the new key's scopes are read directly from the request body with no subset check. An attacker holding a minimal-scope API key on a super account can submit an empty scopes array to mint an unscoped, full-access super key, bypassing scope restrictions (and enabling further chains such as configuration write to RCE).
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-api createApiKey scope-subset validation bypass): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-G77X-8H46-Q78G — getgrav/grav → REJECT

- aliases: CVE-2026-72828
- mechanism: Grav Plugin API (getgrav/grav-plugin-api) before 1.0.13 fails to enforce API-key scope caps in InvitationsController. The strip-super and accept-groups decisions are gated on a bare isSuperAdmin() check rather than a scope-aware permission check, so a least-privilege API key (scoped to api.users.write) minted on a super account can create an invitation record containing super-admin access flags. When the invitation is accepted, those flags are written verbatim to the new account, resulting in privilege escalation to a fully controlled super account.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-api InvitationsController scope-cap bypass): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-MFHQ-GHCJ-C36Q — getgrav/grav → REJECT

- aliases: CVE-2026-72823
- mechanism: The Grav API plugin (getgrav/grav-plugin-api) before 1.0.13 contains an API-key scope cap bypass in DemoController. Its private requireSuper() method checks isSuperAdmin() and returns early before invoking requirePermission(), so the api_key_scopes cap (enforced only in requirePermission()) is skipped. As a result, any scoped API key minted on a super account can bypass its scope restrictions when calling the baseline() and reset() operations (e.g. POST /api/v1/demo/reset), allowing it to capture the demo baseline or force a demo reset. Impact is bounded to demo-engine control and is conditional on demo mode being configured with writable resources.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-api DemoController scope-cap bypass): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-PRPX-FHMF-2G8P — getgrav/grav → REJECT

- aliases: CVE-2026-72829
- mechanism: The Grav API plugin (getgrav/grav-plugin-api) before 1.0.13 contains an API-key scope-cap bypass in UsersController's create() and update() methods. These methods enforce the scope cap only for api.users.write, but gate super-privilege grants on a bare isSuperAdmin() check that reads access.api.super directly without consulting the key's scopes. As a result, an api.users.write-scoped key minted on a super account can set access.api.super or assign a super-granting group to mint or promote a full super account, then authenticate as that account for uncapped administrative privileges.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-api UsersController scope-cap bypass): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-Q6CM-X4F7-73R6 — getgrav/grav → REJECT

- aliases: CVE-2026-72830
- mechanism: Grav API plugin versions before 1.0.13 fail to enforce API key scope caps in ConfigController super-scope gates, allowing scoped keys to write scheduler configuration. Attackers with a scoped api.config.write key can inject arbitrary commands into scheduler.custom_jobs that execute via Symfony Process for remote code execution.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-api ConfigController scope-cap bypass (scheduler RCE)): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-QPVV-MV8X-VG3C — getgrav/grav → REJECT

- aliases: CVE-2026-72824
- mechanism: The Grav API plugin (getgrav/grav-plugin-api) before 1.0.13 contains an API key scope-cap bypass in PagesController::guardTwigContent(). The Twig-toggle check uses a bare isSuperAdmin() gate that does not consult api_key_scopes, so a least-privilege API key scoped only to api.pages.write and minted on a super account can enable process.twig on a page save even though admin.pages_twig is intentionally outside the api.pages scope. When security.twig_content.process_enabled=true and editor_enabled=false, this allows Twig-in-content to execute server-side, resulting in server-side template injection (SSTI) and remote code execution.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-api PagesController Twig-content scope-cap bypass (SSTI)): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-RV98-5GW8-6HF9 — getgrav/grav → REJECT

- aliases: CVE-2026-72825
- mechanism: The getgrav/grav-plugin-api plugin before 1.0.13 contains an API-key scope cap bypass in the POST /reports/twig-content/allowlist endpoint (ReportsController). The endpoint enforces requirePermission('api.config.write') followed by a bare isSuperAdmin() check instead of requireSuper(). Because isSuperAdmin() reads access.api.super directly and never consults api_key_scopes, a least-privilege API key scoped to api.config.write minted on a super account passes the gate, allowing an attacker to append attacker-chosen tokens to the security.twig_sandbox allowlist (persisted to user/config/security.yaml). Widening the allowlist turns any subsequent Twig-in-content render into an SSTI/RCE sink.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-api ReportsController twig-sandbox allowlist scope-cap bypass): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-72V8-H9PQ-46P7 — getgrav/grav → REJECT

- aliases: CVE-2026-72833
- mechanism: The Grav API plugin (getgrav/grav-plugin-api) versions >= 1.0.6 and <= 1.0.11 contain a privilege escalation vulnerability. A scoped API key minted on a super-admin account bypasses its declared scope cap on four isSuperAdmin()-gated write endpoints (in GroupsController, AccountsConfigController, PreferencesController, and DashboardWidgetController). These endpoints authorize via a super-admin early-return that never invokes requirePermission()—the sole enforcement point of the scope cap—so a 'read-only'-scoped key (e.g. api.pages.read) can perform super-only write operations, including rewriting group ACL maps to grant super-admin privileges to arbitrary accounts. A leaked or delegated read-only CI/monitoring key can therefore gain full super-admin write capability. Fixed in 1.0.13.
- candidates: 2c517b012ee0, e3ff054db23d, 2dcf91799901, bf7dd2e6c808, 508650583aae
- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php
- AI marker: Claude Opus 4.5/4.6 <noreply@anthropic.com>; Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (grav-plugin-api four super-gated write endpoints scope-cap bypass): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php; system/blueprints/config/media.yaml (+languages); system/src/Grav/Common/GPM/* + Upgrade/SafeUpgradeService.php + Console/Gpm/* + Installer/Install.php

### GHSA-C7RR-QHWX-6Q49 — Zie619/n8n-workflows → REJECT

- aliases: CVE-2025-55526; CWE CWE-22
- mechanism: n8n-workflows Main Commit ee25413 allows attackers to execute a directory traversal via the download_workflow function within api_server.py
- candidates: a54fc2fb5d9f, 879e0d4f1a32, e4a3ba4f72ac, ff958e486e1f, dc3dce1a2231, f197ef419b17
- candidate files: .devcontainer/*; workflows/*.json (renames); *.md docs; generate_documentation.py; batch_rename.py
- AI marker: Claude Code (generated with); author_identity_pair
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (n8n-workflows download_workflow directory traversal): .devcontainer/*; workflows/*.json (renames); *.md docs; generate_documentation.py; batch_rename.py

### GHSA-83V8-C68X-GCPR — rustdesk/hbb_common → REJECT

- aliases: CVE-2026-30793; CWE CWE-285
- mechanism: Cross-Site Request Forgery (CSRF) vulnerability in rustdesk-client RustDesk Client rustdesk-client on Windows, MacOS, Linux, iOS, Android (Flutter URI scheme handler, FFI bridge modules) allows Privilege Escalation. This vulnerability is associated with program files flutter/lib/common.Dart, src/flutter_ffi.Rs and program routines URI handler for rustdesk://password/, bind.MainSetPermanentPassword().

This issue affects RustDesk Client: through 1.4.5.
- candidates: 652f68fd54c9, 2dc15df250a7, 13ef3411d9ca, b10a96b7bce3, 6463ba0e5241, 47dc73de1e68
- candidate files: examples/webrtc.rs, examples/webrtc_dummy.rs, src/webrtc.rs
- AI marker: Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: FAIL (cross-repo)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (RustDesk client URI-scheme CSRF privilege escalation): examples/webrtc.rs, examples/webrtc_dummy.rs, src/webrtc.rs

### GHSA-HVPF-8PX2-F567 — rrweb-io/rrweb → REJECT

- aliases: CVE-2025-45806; CWE CWE-79
- mechanism: A cross-site scripting (XSS) vulnerability in rrweb-snapshot before v2.0.0-alpha.18 allows attackers to execute arbitrary web scripts or HTML via a crafted payload.
- candidates: 22bc4c334e88, ad5ac17422f4, d17011b6387c
- candidate files: packages/all/package.json + .changeset/* + ci-cd.yml (vite@6); packages/rrweb/src/replay/index.ts (shadow-DOM stylesheet fix); vitest.config.ts
- AI marker: Copilot <175728472+Copilot@users.noreply.github.com>; copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (rrweb-snapshot XSS via crafted payload): packages/all/package.json + .changeset/* + ci-cd.yml (vite@6); packages/rrweb/src/replay/index.ts (shadow-DOM stylesheet fix); vitest.config.ts

### GHSA-GV3J-FJGF-469V — jsonpickle/jsonpickle → REJECT

- aliases: CVE-2021-47952; CWE CWE-502/CWE-94
- mechanism: python jsonpickle 2.0.0 contains a remote code execution vulnerability that allows attackers to execute arbitrary Python commands by deserializing malicious JSON payloads containing py/repr objects. Attackers can craft JSON strings with py/repr directives that invoke the eval function during deserialization to execute system commands and arbitrary code.
- candidates: eb27cf084a90, f238e7ab3e89, d00740675d0c, b0201099041d, 739348868b2e, a0ac44b6f695
- candidate files: jsonpickle/ext/{numpy,pandas}.py; jsonpickle/{pickler,unpickler,tags,util}.py + tests
- AI marker: Claude Code; Assisted-by
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (jsonpickle py/repr deserialization RCE): jsonpickle/ext/{numpy,pandas}.py; jsonpickle/{pickler,unpickler,tags,util}.py + tests

### GHSA-W5XJ-CQGX-J5QJ — hestiacp/hestiacp → REJECT

- aliases: CVE-2026-12196; CWE CWE-287
- mechanism: HestiaCP panel cronjob feature is affected by a broken access control vulnerability. Low privilege users can modify the panel cronjob to execute scripts HestiaCP management scripts with passwordless sudo. This could result in the takeover of administrator users in the application and the underlying webserver.
- candidates: 99fd9a41ee70, f381e294500f, d2d3aaee25a2, 725cdc1c2cdf, ce3e464dabfd
- candidate files: CHANGELOG.md/README.md + bin/v-* (1.9.5 release; v-add-cron-job $7 quote fix); web/templates/* tohtml escaping; web/login + web/inc proxy-header trust
- AI marker: Copilot <175728472+Copilot@users.noreply.github.com>
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (HestiaCP cronjob broken access control (sudo escalation)): CHANGELOG.md/README.md + bin/v-* (1.9.5 release; v-add-cron-job $7 quote fix); web/templates/* tohtml escaping; web/login + web/inc proxy-header trust

### GHSA-7PQV-WJ3V-FCQ3 — openwrt/luci → REJECT

- aliases: CVE-2026-59260; CWE CWE-269
- mechanism: OpenWrt luci-app-samba4 read ACL grants file.exec permission on /usr/sbin/smbd, allowing authenticated delegated users to execute the Samba daemon with caller-controlled command-line arguments. Attackers can pass arbitrary Samba global options such as message command to a root smbd process, triggering command execution when SMB protocol messages are processed.
- candidates: 9e70fd02f8e5, 7af3cf4f00b1, e9fc1b61c4b8, a31eccfa1494, a5bedae64827
- candidate files: modules/luci-base/.../{dhcp.js,cbi.js}; luci-mod-network wireless.js; luci-app-ocserv users.js + status/80_ocserv.js
- AI marker: Assisted-by; Claude Sonnet 4.6 / Claude Opus 4.6 <noreply@anthropic.com>
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (luci-app-samba4 read ACL file.exec on smbd): modules/luci-base/.../{dhcp.js,cbi.js}; luci-mod-network wireless.js; luci-app-ocserv users.js + status/80_ocserv.js

### GHSA-8GVQ-R3C7-VWMV — openwrt/luci → REJECT

- aliases: CVE-2026-61876; CWE CWE-79
- mechanism: LuCI versions fail to properly encode DHCPv6 lease hostnames before rendering in status tables, allowing adjacent network attackers to inject HTML markup. Attackers can send a DHCPv6 Client FQDN containing script tags that execute in the administrator's browser when viewing DHCP lease pages.
- candidates: 9e70fd02f8e5, 7af3cf4f00b1, e9fc1b61c4b8, a31eccfa1494, a5bedae64827
- candidate files: modules/luci-base/.../{dhcp.js,cbi.js}; luci-mod-network wireless.js; luci-app-ocserv users.js + status/80_ocserv.js
- AI marker: Assisted-by; Claude Sonnet 4.6 / Claude Opus 4.6 <noreply@anthropic.com>
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (LuCI DHCPv6 lease hostname XSS): modules/luci-base/.../{dhcp.js,cbi.js}; luci-mod-network wireless.js; luci-app-ocserv users.js + status/80_ocserv.js

### GHSA-XWGP-PPRM-VCX3 — openwrt/luci → REJECT

- aliases: CVE-2026-61875; CWE CWE-79
- mechanism: luci-app-upnp contains a stored cross-site scripting vulnerability that allows unauthenticated LAN clients to inject JavaScript via UPnP IGD AddPortMapping SOAP requests. Attackers can send malicious HTML in the NewPortMappingDescription field, which miniupnpd stores and luci-app-upnp renders without output encoding, executing the payload when administrators view the UPnP or Status pages.
- candidates: 9e70fd02f8e5, 7af3cf4f00b1, e9fc1b61c4b8, a31eccfa1494, a5bedae64827
- candidate files: modules/luci-base/.../{dhcp.js,cbi.js}; luci-mod-network wireless.js; luci-app-ocserv users.js + status/80_ocserv.js
- AI marker: Assisted-by; Claude Sonnet 4.6 / Claude Opus 4.6 <noreply@anthropic.com>
- identity_gate: PASS
- reasoning: candidate AI commit(s) do not introduce the named mechanism (luci-app-upnp stored XSS (NewPortMappingDescription)): modules/luci-base/.../{dhcp.js,cbi.js}; luci-mod-network wireless.js; luci-app-ocserv users.js + status/80_ocserv.js
