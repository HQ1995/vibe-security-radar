# Queue audit: Mautic + Formwork (canonical93)

**REJECT all five. PASS_PROPOSAL=0. Packet delta 0. Canonical93 stays 93 HOLD.**

Worker PASS is proposal only; this packet emits none. Prefer zero PASS over one false positive.
Conservation: assigned=5, reviewed=5, unreviewed=0. Equation `5=5+0`.

Source packet `herdr-260814-nextqueue-v2-grok46-low` is routing only and is not evidence.
Admission requires exact PASS on identity, ai_hunk, topology, but_for, fix_reversal, release, and uniqueness.
NA, UNKNOWN, BLOCKED, or NARROW is not PASS.

## Freeze

Assigned exactly these identities, in this order, and no others:

1. GHSA-3GGV-QWCP-J6XG
2. GHSA-438M-6MHW-HQ5W
3. GHSA-HJ6F-7HP7-XG69
4. GHSA-34P4-7W83-35G2
5. GHSA-7J46-F57W-76PJ

Canonical93 ledger SHA256 `6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d` overlap: none.
Source assignment SHA256 `5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3`.
CONTRACT SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
First-party github-reviewed cache HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
MATCHER_CONTRACT `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.

## Verdicts

| case | verdict | failing gates | why |
|---|---|---|---|
| GHSA-3GGV-QWCP-J6XG | REJECT | ai_hunk, but_for, release | AI candidates never author the login timing oracle |
| GHSA-438M-6MHW-HQ5W | REJECT | ai_hunk, but_for, release | AI candidates never author elfinder/config secret disclosure |
| GHSA-HJ6F-7HP7-XG69 | REJECT | ai_hunk, but_for, release | AI candidates never author webhook SSRF |
| GHSA-34P4-7W83-35G2 | REJECT | ai_hunk, but_for, release | Copilot hits are sibling files; role assignment closer is human |
| GHSA-7J46-F57W-76PJ | REJECT | ai_hunk, but_for, release | tags innerHTML is human history; Copilot on closer is AI-on-fix |

identity_gate PASS and uniqueness_gate PASS on all five. topology_gate PASS: every routing candidate is `n_parents=1`; fix merges were peeled to members; no authorship transfer. fix_reversal_gate PASS for the named first-party closers. release_gate FAIL because there is no AI contribution to the advisory mechanism to contain. CVE aliases are not counted.

## GHSA-3GGV-QWCP-J6XG (Mautic login timing)

First-party GHSA-3ggv-qwcp-j6xg, not withdrawn, Packagist `mautic/core`, CWE-204. Advisory JSON SHA256 `9099081e8114bb03d5e028561fd285a558f4d32beb7f6367a1f560fb31e237d1`.

Advisory-named closer `6bc4f5f1aabb` is a 7.x merge (`n_parents=2`). Member `b4264c717ce3` (Nick Vanpraet, MST-46, no AI trailer) adds `TimingSafeFormLoginAuthenticator.php`. 6.x backport `700c9d79a724` is an ancestor of tag `6.0.5` (`d03b55e2d025`) and not of `6.0.4`. 5.x uses a different human patch `940e68f8b590` on `FormAuthenticator.php` inside tag `5.2.8`. Packagist and git tags have no `4.4.17`.

The eight routing candidates edit ProjectBundle, GrapesJsBuilderBundle, AssetBundle, PageBundle, and FormBundle. Zero path overlap with the authenticator files. Two of them are 7.x-only. AssetBundle Claude commits sit in both `5.2.7` and `5.2.8` (inherited sibling). Same-repo fix is not causal proof. Shared SHA with the other Mautic rows is not identity dedupe.

## GHSA-438M-6MHW-HQ5W (Mautic elfinder secrets)

First-party GHSA-438m-6mhw-hq5w, CWE-283, same package ranges. Advisory JSON SHA256 `34686bf84c20cdfc55c0bd74c40dcd826746edde75d94ee476ba027de2a4aadc`.

Closer merge `882c2c5be646` first-parent-diff is `CoreBundle/Form/Type/ConfigType.php`. Member `a310b1933de7` (lenonleite, mst-75, no AI trailer) is 7.x. 6.x backport `6585e7360fa3` is in `6.0.5`. Routing AI files do not include ConfigType.php.

## GHSA-HJ6F-7HP7-XG69 (Mautic webhook SSRF)

First-party GHSA-hj6f-7hp7-xg69, CWE-918. Advisory JSON SHA256 `0275843e433361f8ef12a33770b2d1388643d684d844e806933d5184e36a7f56`.

Closer merge `6084f6de4c88` second parent `dc5bb1466c9a` (Zdeno Kuzmany, MST-78 M7, no AI trailer) adds `PrivateAddressChecker.php` and WebhookBundle HTTP guards. 5.2.8 contains the file via `8fd5bd7c4d57` (M5); 6.0.5 via `f5be8a57f5a2` (M6); 5.2.7 and 6.0.4 do not. Routing AI files do not include WebhookBundle.

## GHSA-34P4-7W83-35G2 (Formwork user-creation privilege)

First-party GHSA-34p4-7w83-35g2, Packagist `getformwork/formwork`, CWE-269, introduced `2.0.0`, fixed `2.3.4`. Advisory JSON SHA256 `e32aa20f9dc1e2d96f8a2c66ec229ebc9d8daf00b199cbe7ad21a1277f179d69`.

Tag peels: `2.3.3=69b7f934abad`, `2.3.4=bc64eac82798`. Merge `19390a0b408e` parents are those 2.3.3 tag and member `6a7d1538c87d` (Giuseppe Criscione, no AI trailer). Member tree `e749a8a261ec` equals the merge tree. UsersController blob `104bba2aa21b` at the member equals tag `2.3.4`; `2.3.3` still has `19194aca333a` with `$form->data()->get('role')`.

Copilot candidates: markdown placeholder, ErrorsController, pages.ts/validation.ts, AbstractCollection, fr.yaml, AuthenticationController (one-line login `return`). None touch `UsersController.php` or `newUser.yaml`. `055e0df0b766` is AI-on-fix of the XSS advisory, not this privilege hole. Human `ac6814d8a0e1` added the role field with no AI marker. Sibling fields and inherited old bugs are not origin.

## GHSA-7J46-F57W-76PJ (Formwork stored XSS in tags)

First-party GHSA-7j46-f57w-76pj, CWE-79, introduced `0`, fixed `2.2.0`. Advisory JSON SHA256 `a70132c96197e36b4c2bfd8ceb09649b56934dee4ea6cca4cfd6e9b3adeae73b`.

Tag peels: `2.1.5=9cd70120e8cd` still has `tag.innerHTML = value` (blob `03f6e17782df`). Human `45f20bec6f34` (`n_parents=1`, no AI trailer) switches tags-input innerHTML to innerText. Merge `4abcd60ae769` (#791) second parent is Copilot `055e0df0b766`, whose parent is that human closer. `055e0df0b766` only changes `pages.ts` `innerText` and `makeSlug` hyphen collapsing. That is AI-on-fix, not origin, and not incomplete remediation of an AI-added boundary. Assigned pre-fix Copilot hits never touch `tags-input.ts`. innerHTML is human history from 2024.

## What was not counted as proof

Routing from the source packet, shared SHA across the three Mautic rows, trailer on a squash/merge carrier, AI-on-fix, inherited old bugs, sibling fields, incomplete hardening that only reduces risk, and a fix in the same repo.

Allowed classes (atomic AI direct root, exact scoped contributor/new surface, necessary indirect chain member, AI incomplete remediation with a later closer on the same residual boundary) were tested and not met.

## Conservation and claim boundary

`5=5+0` holds. Did not pad. Canonical93 not edited. Publication HOLD. Greater-than-200 remains unsupported.
Temporary clones and pages used for investigation were deleted. Replay is offline pin checks only.
