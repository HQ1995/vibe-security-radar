# Upstream advisory catalog vs funnel ledger (2026-08-26)

Independent rebuild from GitHub `advisory-database` (reviewed + windowed unreviewed)
and NVD 2025/2026. Ledger was **not** modified.

Window: `2025-05-01` .. `2026-08-26`.

## Upstream catalog

- GHSA files parsed: **110054**
- NVD 2025/2026 records: **94119**
- Alias clusters (GHSA connected components): **110054**
- Extra NVD-only CVE singletons: **15874**
- Total upstream clusters: **125928**
- In window: **93441** (reviewed 12004 / unreviewed-only 75297 / NVD-only 6140)
- Withdrawn in window: **391**

## Ledger (old book, unchanged)

- Rows: **24124**
- Hash-ok `advisory_ids`: **21119**
- Hash-fail: **114**
- Missing `advisory_ids`: **2891**

## Join by class_id

- Ledger class_id equals an upstream cluster: **24004**
- Ledger class_id is a unique subset of an upstream cluster: **105**
- Ledger class_id not in today's GHSA/NVD graph: **15**

Among rows currently **missing** `advisory_ids`:

- Exact upstream cluster: **2843**
- Subset of an upstream cluster: **43**
- Still unexplained: **5**

Among rows currently **hash-fail**:

- Exact upstream cluster: **86**
- Subset of an upstream cluster: **27**
- Still unexplained: **1**

The 5 unexplained missing rows: 4× `openclaw/openclaw` (k=2; GHSA clone aliases do not form that pair) and 1× `meshtastic/firmware` `alias-bd1066d6c07a95b9fb97e4a2` (k=1; ID not in GHSA clone or NVD).

Hash-fail rows whose ledger IDs equal the upstream pair are usually a **CVE-only `class_id`** with a later GHSA twin appended onto `advisory_ids` (the 25 window-extend attachments). Upstream cluster is `{CVE, GHSA}`; ledger `class_id` is still `hash({CVE})`.

## New upstream clusters not in the ledger

In-window, not withdrawn, class_id absent from the book. **Not added.**

| Filter | Count |
|---|---:|
| Reviewed, class_id not in book (raw) | 2802 |
| …of which a k=1 member class_id is already in the book (GHSA twin of an existing row) | 92 |
| …of which a member ID already appears on some row's `advisory_ids` | 4 |
| **Reviewed, no class_id / member overlap with the book** | **2706** |
| …with a parsed repo slug | 2619 |
| …of those, published `>= 2026-08-17` | 3 |
| Unreviewed-only | 63431 |
| NVD-only CVE singletons | 2814 |

The original 23,861-class funnel was repo-narrowed github-reviewed quality, not “every reviewed GHSA in the window”. The 263 rows appended on 2026-08-26 are already in the book; they are not in the 2706. The 2619 first-party reviewed clusters missing from the book are almost all from 2025-05 .. 2026-08-16 — leftover from that original narrowing, not a new 08/17–08/26 flood.

### Sample missing-ledger rows that pin exactly to an upstream cluster

- `alias-002082d11b0ba1722e5fb2b2` `git.kernel.org/pub/scm/linux/kernel/git/stable/linux` status=UNANALYZED → `CVE-2026-64583, GHSA-vq5j-5625-rcfr`
- `alias-0024f4aec0b530bb5269b3d5` `python/cpython` status=PARTIALLY_ANALYZED → `CVE-2025-12781, GHSA-hfpw-x3fg-wmmg`
- `alias-0082f14737db01c100812419` `polarnl/polarlearn` status=UNANALYZED → `CVE-2026-39322`
- `alias-008dff2ad6f280ebc77402f0` `openclaw/openclaw` status=PARTIALLY_ANALYZED → `CVE-2026-32924, GHSA-988c-qpg2-7hpv`
- `alias-008e6d517b5c24cd718c56f3` `gitlab.com/gitlab-org/gitlab` status=UNANALYZED → `CVE-2025-2254, GHSA-27jm-6pj2-8w7g`
- `alias-00b3f81960d4375d531bbd7c` `flowiseai/flowise` status=PARTIALLY_ANALYZED → `CVE-2026-56273, GHSA-g8g5-48h4-5r8h`
- `alias-00decd4165a7b7a7b163b8a8` `openclaw/openclaw` status=PARTIALLY_ANALYZED → `CVE-2026-53834, GHSA-35c7-4r45-9gv3`
- `alias-00f490cfbbc18a707bd21dfd` `freerdp/freerdp` status=PARTIALLY_ANALYZED → `CVE-2026-67303, GHSA-4wq4-c34j-gg99`
- `alias-00f7362a4b77655696c61b8c` `git.kernel.org/pub/scm/linux/kernel/git/stable/linux` status=UNANALYZED → `CVE-2026-64585, GHSA-88mv-jf2p-hpm8`
- `alias-01064ad767498fdff5f26d9e` `vrana/adminer` status=PARTIALLY_ANALYZED → `CVE-2026-63771, GHSA-hvv2-8jpj-gr8h`
- `alias-01276200ba84623c5582653a` `git.kernel.org/pub/scm/linux/kernel/git/stable/linux` status=UNANALYZED → `CVE-2026-64552, GHSA-6c34-77j2-7g8c`
- `alias-0144e5d91383a461b3a7b586` `nanocoai/nanoclaw` status=PARTIALLY_ANALYZED → `CVE-2026-17433, GHSA-6frr-4xvp-cwch`
- `alias-019ba9e880fae0f408a9683b` `open-webui/open-webui` status=PARTIALLY_ANALYZED → `CVE-2026-70494, GHSA-3cg5-48j3-v4gv`
- `alias-01a8d0be858c9f7f195fe640` `pytorch/pytorch` status=PARTIALLY_ANALYZED → `CVE-2025-55557, GHSA-765f-85mc-5qmw`
- `alias-01aec8238e680773d2e18f3d` `rclone/rclone` status=UNANALYZED → `CVE-2026-71311, GHSA-8c48-q9wj-3w37`

### Sample hash-fail rows whose class_id is a subset of today's cluster

- `alias-023b2dccb33d12582d0920c1` `elixir-grpc/grpc` ledger=['CVE-2026-48853', 'GHSA-grp7-v8xh-rj7h'] upstream=['CVE-2026-48853', 'GHSA-grp7-v8xh-rj7h']
- `alias-22e2fe4a2ad88ede4e0b29ec` `aquasecurity/trivy` ledger=['CVE-2026-55092', 'GHSA-mcj4-mphf-j9ff'] upstream=['CVE-2026-55092', 'GHSA-mcj4-mphf-j9ff']
- `alias-2f2b17e015e5a965126520ef` `udecode/plate` ledger=['CVE-2026-55596', 'GHSA-qj6x-xx2h-8hvv'] upstream=['CVE-2026-55596', 'GHSA-qj6x-xx2h-8hvv']
- `alias-309188ea955eb3fafa4a7f72` `mervinpraison/praisonai` ledger=['CVE-2026-55522', 'GHSA-hxmv-c4g6-5fqc'] upstream=['CVE-2026-55522', 'GHSA-hxmv-c4g6-5fqc']
- `alias-32ca9287149071943efd34d3` `team-alembic/ash_authentication` ledger=['CVE-2026-49757', 'GHSA-777c-2fxx-qr28'] upstream=['CVE-2026-49757', 'GHSA-777c-2fxx-qr28']
- `alias-38811b30715da262e181ff42` `elixir-grpc/grpc` ledger=['CVE-2026-48599', 'GHSA-mwr4-5g34-j5cq'] upstream=['CVE-2026-48599', 'GHSA-mwr4-5g34-j5cq']
- `alias-47f077ed24263c892969c261` `arikusi/deepseek-mcp-server` ledger=['CVE-2026-55604', 'GHSA-fh3r-g96v-f578'] upstream=['CVE-2026-55604', 'GHSA-fh3r-g96v-f578']
- `alias-5031229bc602aac073e2d4a5` `wagtail/wagtail` ledger=['CVE-2026-54262', 'GHSA-8634-mr4j-r72c'] upstream=['CVE-2026-54262', 'GHSA-8634-mr4j-r72c']
- `alias-52324aedaaa8381a5593b512` `budibase/budibase` ledger=['GHSA-c8vc-7pv3-g98p', 'CVE-2026-73303'] upstream=['CVE-2026-73303', 'GHSA-c8vc-7pv3-g98p']
- `alias-52c8d98cfe3f63c749c7fe94` `wagtail/wagtail` ledger=['CVE-2026-54263', 'GHSA-23m2-mghx-vqmf'] upstream=['CVE-2026-54263', 'GHSA-23m2-mghx-vqmf']

### Sample new reviewed in-window clusters not in the book

- `alias-73dc4b94208ce92d6a3a75a8` published=2025-06-10 `CVE-2025-48067, GHSA-m9jh-jf9h-x3h2` repos=['octoprint/octoprint']
- `alias-e908cd2e34a3d02e988670f0` published=2025-06-10 `CVE-2025-48879, GHSA-9wj4-8h85-pgrw` repos=['octoprint/octoprint']
- `alias-85d0675f6625be89e0c3be7c` published=2025-06-11 `GHSA-v33j-v3x4-42qg` repos=['orange-opensource/hurl']
- `alias-b3a467cde488aa6be47ab052` published=2025-06-09 `CVE-2025-49130, GHSA-j226-63j7-qrqh` repos=['barryvdh/laravel-translation-manager']
- `alias-73bcfc3b125b5ae2b6ecbed1` published=2025-06-11 `CVE-2025-48444, GHSA-c424-hgg9-9c4w` repos=[]
- `alias-94d28d375b28ba2ab2193974` published=2025-06-04 `CVE-2025-30360, GHSA-9jgg-88mc-972h` repos=['webpack/webpack-dev-server']
- `alias-9887d95950913c7ff5378ebc` published=2025-06-03 `CVE-2025-48387, GHSA-8cj5-5rvv-wf4v` repos=['google/security-research', 'mafintosh/tar-fs']
- `alias-5deb98f68f105456e5524a36` published=2025-06-09 `CVE-2025-5897, GHSA-79vf-hf9f-j9q8` repos=['vuejs/vue-cli']
- `alias-6738cdad49e23b6ebc67eb79` published=2025-06-09 `CVE-2025-5891, GHSA-x5gf-qvw8-r2rm` repos=['unitech/pm2']
- `alias-a72d4ee33e313471e5a24630` published=2025-06-05 `CVE-2025-5791, GHSA-m65q-v92h-cm7q` repos=['ogham/rust-users']
- `alias-c4cb1226e2976f243730944a` published=2025-06-05 `CVE-2025-48994, GHSA-6vx8-pcwv-xhf4` repos=['xml-security/signxml']
- `alias-9e418cc4a466befd2a37d456` published=2025-06-06 `CVE-2025-49009, GHSA-qx7g-fx8q-545g` repos=['erudika/para']
- `alias-85cce2e9d3ca4aedea9fbecd` published=2025-06-26 `CVE-2025-6700, GHSA-2jfg-73q2-24qv` repos=['shenxiusec/cve-proofs', 'xuxueli/xxl-sso']
- `alias-1ba618fecc039169befbde6a` published=2025-06-05 `CVE-2025-48995, GHSA-gmhf-gg8w-jw42` repos=['xml-security/signxml']
- `alias-d5288d6c4a41614fe648809e` published=2025-06-13 `GHSA-r7pm-mw8g-p7px` repos=['ezsystems/ezplatform-admin-ui']
