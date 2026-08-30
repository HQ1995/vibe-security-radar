# Round11 top-500 remaining-open TP-likelihood audits

Wave of 500 `UNANALYZED`/`PARTIALLY_ANALYZED` ledger cases ranked for
true-positive likelihood after excluding every class/advisory in
`research/round10-top200-20260828/`. Protocol:
`docs/AUDIT-PROTOCOL.md`. The reconciled results were landed to the canonical
Neon ledger and exported to the repository after all publication gates passed.

## Selection

- eligible open after round10 exclude: 27541
- selected: 500
- statuses: `{'UNANALYZED': 499, 'PARTIALLY_ANALYZED': 1}`
- repositories: 224 (cap 5)
- score range: 211.0 .. 147.61
- clone-ready at freeze: 78
- known-TP-repo cases: 29
- excluded overlap: 0
- ledger sha256 at freeze: `a4363c412889e029530cdac09e5336da4b07652d9c2a61807f27cb0033b4cabc`
- ledger sha256 at verification: `cb2d41daa464c00f81a59e46c9810273c352a60c8397d19828f5fb5d0c2be617`
- ledger changed since freeze: `True`
- frozen selection recomputed from live ledger: `False`

## Verdict histogram

- `NOT_AI`: 477
- `AI_ROOT_CAUSE`: 9
- `FALSE_POSITIVE`: 7
- `EVIDENCE_GAP`: 6
- `AI_CODE_FLAWED`: 1

## Independent review of the original completed set

- reviewed records: 389
- `CONFIRMED`: 280
- `CORRECTION_REQUIRED`: 94
- `EVIDENCE_GAP`: 15

These are the historical second-pass findings for the original 389-record set.

### CORRECTION_REQUIRED

w002 w006 w007 w008 w011 w019 w021 w023 w025 w039 w040 w046 w048 w049 w052 w053 w055 w065 w067 w068 w070 w072 w074 w075 w078 w079 w081 w085 w086 w087 w089 w090 w099 w112 w117 w120 w124 w125 w132 w136 w149 w151 w152 w153 w164 w167 w180 w181 w187 w188 w189 w191 w206 w207 w221 w227 w228 w232 w237 w241 w246 w259 w260 w262 w263 w267 w270 w276 w277 w278 w279 w282 w296 w298 w303 w304 w307 w311 w312 w317 w320 w321 w326 w327 w339 w354 w357 w363 w364 w368 w371 w375 w379 w395

### EVIDENCE_GAP

w010 w029 w088 w115 w122 w123 w133 w139 w165 w166 w252 w280 w289 w358 w387

## Disagreement re-review landing

- re-researched cases: 33
- `CORRECTION_REQUIRED`: 18
- `FIELD_ERRATUM`: 7
- `CONFIRMED`: 6
- `EVIDENCE_GAP`: 2

The 33-case clean-context disagreement re-review has been reconciled into
the canonical primary records. `FIELD_ERRATUM` is a derived landing scope,
not a new protocol review-verdict enum. Six `CONFIRMED` cases required no
canonical field change.

## Independent review of the final 111 and reconciliation

- reviewed records: 111
- `CONFIRMED`: 92
- `CORRECTION_REQUIRED`: 17
- `EVIDENCE_GAP`: 2
- substantive reconciliation records: 25
- accepted verdict changes: `w350 NOT_AI → EVIDENCE_GAP`; `w434 EVIDENCE_GAP → NOT_AI`
- rejected verdict change: `w440 FALSE_POSITIVE → NOT_AI`

## Canonical ledger landing

- run id: `a5427fbc-7520-575e-be07-b56ecfdc51d0`
- change set id: `829910c2-b608-4125-ac18-54b21357358b`
- rows finalized: 500
- assessments appended: 500
- exported ledger sha256: `cb2d41daa464c00f81a59e46c9810273c352a60c8397d19828f5fb5d0c2be617`
- local export equals canonical database: `True`
- publication records: 260
- publication gate: `pass`

## Cases

| worker | class_id | case_id | repo | verdict | introducer | fix |
|---|---|---|---|---|---|---|
| w000 | `alias-7a67e4c2cdfe7bc6ade411ee` | GHSA-723w-crw6-p9hx | jahlives/openssl_encrypt | AI_ROOT_CAUSE | `fafdfeed1b27` | `f4a1ba660063` |
| w001 | `alias-7e22d7fa18af10c1d907af89` | GHSA-2664-hr5v-554w | n8n-io/n8n | AI_CODE_FLAWED | `562d867483e8` | `ca3d42d83865` |
| w002 | `alias-7e64c88c0c888e3970b52934` | GHSA-c7vw-vfxj-3mvh | jahlives/openssl_encrypt | AI_ROOT_CAUSE | `8a5ed7e62417` | `e0c999ea4442` |
| w003 | `alias-836fd8cd5fc2ca104f082da3` | GHSA-j3gw-mm62-q9gj | n8n-io/n8n | NOT_AI | `98fb09eefb7a` | `2222fe3a6c88` |
| w004 | `alias-83777bf84c8decf57a1040f6` | GHSA-m6wx-qjxf-vr9v | n8n-io/n8n | NOT_AI | `4b06a2c6f9e7` | `2222fe3a6c88` |
| w005 | `alias-85011a48722a9639c2f0a160` | GHSA-hf5p-745p-2j3h | n8n-io/n8n | NOT_AI | `d184bf77fee4` | `ca3d42d83865` |
| w006 | `alias-85443fa0b01cc0d808288b99` | GHSA-h5rm-9fhh-5phj | n8n-io/n8n | AI_ROOT_CAUSE | `6d88b9e1e9f2` | `ca3d42d83865` |
| w007 | `alias-877be5bb530812a4d6690884` | GHSA-243r-jm6r-f6pp | jahlives/openssl_encrypt | FALSE_POSITIVE | `—` | `—` |
| w008 | `alias-8e92c18748b743d8804419d4` | GHSA-jw8h-gwjw-g7rc | jahlives/openssl_encrypt | FALSE_POSITIVE | `—` | `—` |
| w009 | `alias-9402a2a390a2eb47bc0e4e2c` | GHSA-w672-239g-c3gr | gitpython-developers/gitpython | NOT_AI | `0cd09bd30648` | `f2550b65bf60` |
| w010 | `alias-950b2e4a9ba1a6d6dbeb274f` | GHSA-2726-phmx-rc26 | gitpython-developers/gitpython | NOT_AI | `b425301ad16f` | `ffcb5359e876` |
| w011 | `alias-96f4c59aa038773f281647b9` | GHSA-gvq9-cmxr-844m | jahlives/openssl_encrypt | AI_ROOT_CAUSE | `fafdfeed1b27` | `1d519a1eb1a2` |
| w012 | `alias-9a594a7143ab4a4c32745a8f` | GHSA-78pq-g4m8-fx2c | gitpython-developers/gitpython | NOT_AI | `3fd37230e76a` | `a495ccd3b547` |
| w013 | `alias-afab3229357f1f461e4dc206` | GHSA-mhfq-f35q-x62m | gitpython-developers/gitpython | NOT_AI | `1047b41e2e92` | `3af0c2516c5e` |
| w014 | `alias-b0e8aaafaceec891c37780c1` | GHSA-m3x4-5jfw-2mqc | gitpython-developers/gitpython | NOT_AI | `b67bd4c73027` | `7a4f5dcb7bf3` |
| w015 | `alias-928d29923af79983ffdc29e2` | GHSA-7rwv-fqq2-88c4 | lin-snow/ech0 | NOT_AI | `3f7c5a6c885f` | `1b2adc9b5d2e` |
| w016 | `alias-9e0672fd644f341c296fbe2a` | GHSA-3r5q-vfpj-wprr | lin-snow/ech0 | NOT_AI | `06c9290a6821` | `eab62379c795` |
| w017 | `alias-9f86fe98cd5e320fab857870` | GHSA-m3r5-hc33-p4wf | lin-snow/ech0 | NOT_AI | `896116abca94` | `9ce19a3b0d07` |
| w018 | `alias-d492ba1b45be4598a185b391` | GHSA-7v7f-8gw6-2q2x | lin-snow/ech0 | NOT_AI | `5aa2fd32f9f8` | `cecc2c19b590` |
| w019 | `alias-db82daf2886088440e14b14f` | GHSA-q8hh-m6v5-4f3x | lin-snow/ech0 | AI_ROOT_CAUSE | `b47fa1c75d89` | `—` |
| w020 | `alias-e03a488b396dbfba39fde27d` | GHSA-wcrg-p6mv-jx2j | scriban/scriban | NOT_AI | `46054810b50b` | `7fdf19df7db0` |
| w021 | `alias-e882f68bc400d7b151121ca2` | GHSA-q84q-h76q-mqp7 | scriban/scriban | NOT_AI | `774f70d8aea6` | `205ca6a7c234` |
| w022 | `alias-f4fa8f88498d39fc78df240f` | GHSA-q5qx-vc88-69hw | scriban/scriban | NOT_AI | `46054810b50b` | `2d01bd15a111` |
| w023 | `alias-f5c966ddda3595b2c4e9bdde` | GHSA-6g73-98rg-crm7 | scriban/scriban | NOT_AI | `46054810b50b` | `f55280a09575` |
| w024 | `alias-ff0bc356cfdad14a17563556` | GHSA-3qxv-x8gq-wgff | scriban/scriban | NOT_AI | `779161586560` | `4227fdee198e` |
| w025 | `alias-fb99494bb546805f329c2d76` | GHSA-wg7g-xr7v-hf69 | budibase/budibase | NOT_AI | `f2a025013ea0` | `2d6c1d17cff8` |
| w026 | `alias-bb9221fb3bacaa4409bb135d` | GHSA-3mm3-wfpv-q85g | clerk/javascript | FALSE_POSITIVE | `—` | `—` |
| w027 | `alias-d4db04925ed384518e216f7c` | GHSA-9p42-c923-p9c9 | misp/cti-transmute | NOT_AI | `3b521470283e` | `ac495641ef3c` |
| w028 | `alias-e1f5d74fde29fa9707d2396a` | GHSA-fq55-48v3-mc95 | misp/cti-transmute | NOT_AI | `a584a9da2a2f` | `c5b024a8ef56` |
| w029 | `alias-5f8a2e7d0e048764bb0f852c` | GHSA-xm98-3vcf-fph7 | ibm/mcp-context-forge | NOT_AI | `cb5cd12a5882` | `63a2900e6301` |
| w030 | `alias-faf726fbb3b04c3e28280d0d` | GHSA-5p7p-jgvj-4v95 | gitlab.freedesktop.org/xorg/xserver | NOT_AI | `1c4a0db2c6bf` | `f5abfb619944` |
| w031 | `alias-a27ace3f273f328e306294c9` | GHSA-4rc3-7j7w-m548 | harttle/liquidjs | NOT_AI | `a3af44dc10fd` | `e2311dfd6e82` |
| w032 | `alias-d0236c4fef46a57778dbf6c5` | GHSA-6q5m-63h6-5x4v | harttle/liquidjs | NOT_AI | `4595e2872e78` | `35d523026345` |
| w033 | `alias-d6fb8815dd17e964c6646e7b` | GHSA-g357-x5c3-c72p | harttle/liquidjs | NOT_AI | `258780e9a87c` | `8a0c74a7fcb1` |
| w034 | `alias-de1110ee7bad63b7586c5161` | GHSA-v273-448j-v4qj | harttle/liquidjs | NOT_AI | `822ba0be0f1c` | `f41c1fc02fe9` |
| w035 | `alias-ea822041965c4e8d4b9b5bbd` | GHSA-9x9p-qf8f-mvjg | harttle/liquidjs | NOT_AI | `d48991623177` | `dbbf62880305` |
| w036 | `alias-7f17283b838be600010459e9` | GHSA-jf73-858c-54pg | olivetin/olivetin | NOT_AI | `a62d58f11955` | `d7962710e7c4` |
| w037 | `alias-8cbdbac2766da9ea59ee2d3f` | GHSA-xpxj-f2fm-rqch | olivetin/olivetin | NOT_AI | `6a7187fb5b6a` | `ec114e95d297` |
| w038 | `alias-d8e1c7b6be457d7858f996d8` | GHSA-4fqm-6fmh-82mq | olivetin/olivetin | NOT_AI | `7cd67fc4ce45` | `d9804182eae4` |
| w039 | `alias-e123eec885a07c29d00d91b9` | GHSA-g962-2j28-3cg9 | olivetin/olivetin | NOT_AI | `5fe07448584b` | `e97d8ecbd8d6` |
| w040 | `alias-eb7492cd36307deac1cd86f7` | GHSA-p443-p7w5-2f7f | olivetin/olivetin | NOT_AI | `4744169aa013` | `cb46a597b246` |
| w041 | `alias-2d2c017e69531c56cbf42ce8` | GHSA-pw35-9xmg-v8xw | gitlab.freedesktop.org/xorg/xserver | NOT_AI | `e167299f6050` | `ab02fb96b1c7` |
| w042 | `alias-37d47a9ab0c9685427a52d0b` | GHSA-c5wx-c74v-9c3g | gitlab.freedesktop.org/xorg/xserver | NOT_AI | `ded6147bfb5d` | `03731b326a80` |
| w043 | `alias-448c36e83f68e8837ebfcfa6` | GHSA-69rm-w9qj-3x45 | gitlab.freedesktop.org/xorg/xserver | NOT_AI | `cf88363db0eb` | `d55c54cecb5e` |
| w044 | `alias-6ddd858f402b023a1816e063` | GHSA-gpcr-p5wh-5x85 | gitlab.freedesktop.org/xorg/xserver | NOT_AI | `66d92afeaeed` | `3c3a4b767b16` |
| w045 | `alias-a04219f826d600efc2db317b` | GHSA-9m2v-hc5g-5jpv | krayin/laravel-crm | NOT_AI | `fabc2c41978b` | `f96e2f71e444` |
| w046 | `alias-d73a78ad7526fd6c59b3b8c3` | GHSA-2xx8-j85v-j7wh | krayin/laravel-crm | NOT_AI | `5666961a5437` | `e1eb78586fc1` |
| w047 | `alias-b1be3271257f0c5a1b297d7e` | GHSA-375f-4r2h-f99j | mtrudel/bandit | NOT_AI | `221dcba08528` | `45feea20dea8` |
| w048 | `alias-d9e8952efb861d2ad55904ec` | GHSA-9q9q-324x-93r2 | mtrudel/bandit | NOT_AI | `57b9722b589c` | `ae3520dfdbfa` |
| w049 | `alias-f08fc08cd6c111f05c9206e1` | GHSA-cvxm-645q-p574 | containerd/containerd | NOT_AI | `9e6beafd5391` | `0c0918fa8fb4` |
| w050 | `alias-7c49095e0a86bde51147c2c0` | GHSA-vqph-xhj8-62wp | appneta/tcpreplay | NOT_AI | `745a71184c9d` | `c8ee39133c53` |
| w051 | `alias-e205f1df5be469a1a7976bc1` | GHSA-mvf2-f6gm-w987 | nearform/fast-jwt | NOT_AI | `15a6e92c9adb` | `597c4b6e6af3` |
| w052 | `alias-00bd6dba6118a2df34338df2` | GHSA-47f2-6xxj-8w97 | git.kernel.org/pub/scm/linux/kernel/git/stable/linux | NOT_AI | `41aaff2a2ac0` | `11d7cfe0c119` |
| w053 | `alias-00d9047abcf5bdf7d8144996` | GHSA-56rg-f4qq-ghhv | git.kernel.org/pub/scm/linux/kernel/git/stable/linux | NOT_AI | `28acb12014fb` | `8d7a30c50c2e` |
| w054 | `alias-011e1b8fb73e82a7cd4a959b` | GHSA-6rv6-hxhf-8gw6 | git.kernel.org/pub/scm/linux/kernel/git/stable/linux | NOT_AI | `1da177e4c3f4` | `e5b811fe7931` |
| w055 | `alias-0157e5debe5f4235ad716950` | GHSA-c23v-2w7h-h6m9 | git.kernel.org/pub/scm/linux/kernel/git/stable/linux | NOT_AI | `b48c24c2d710` | `5ebb3ed757be` |
| w056 | `alias-01b40b043cf8877097d30cf0` | GHSA-25w8-qg97-7fjr | git.kernel.org/pub/scm/linux/kernel/git/stable/linux | NOT_AI | `62610ad21870` | `539dfcf69105` |
| w057 | `alias-0bed64c405da307b02928d41` | GHSA-g7vj-qw6x-g3p8 | mmaitre314/picklescan | NOT_AI | `c1d5abdcc740` | `bf26452ae2e3` |
| w058 | `alias-128099ff89397869f907e82b` | GHSA-v3h3-59vx-wx73 | siyuan-note/siyuan | NOT_AI | `e9c8cd0e0d3b` | `f16b159ea49a` |
| w059 | `alias-2724a86af5938557c725bebe` | GHSA-xf8j-hfm6-vc9v | siyuan-note/siyuan | NOT_AI | `acfc02ee8a04` | `64c26e74bb82` |
| w060 | `alias-2a3e3756ad19bfeb21b92cee` | GHSA-jwj6-pgg9-m3v5 | siyuan-note/siyuan | NOT_AI | `f40ed985e10b` | `991d693c97f8` |
| w061 | `alias-2ef9c21e374ab0b07aa1e591` | GHSA-x3p9-xqgm-hxww | siyuan-note/siyuan | NOT_AI | `dfa4e79d831b` | `590e4ecd26da` |
| w062 | `alias-318f43da67785f3839c7a2ff` | GHSA-75xh-mp4f-f2rf | siyuan-note/siyuan | NOT_AI | `9b8e8956f997` | `899f5b07394e` |
| w063 | `alias-53c0052826738b27609fafe4` | GHSA-6hj8-q7v2-996c | apache/airflow | NOT_AI | `933d5676f96d` | `41a3be7076ef` |
| w064 | `alias-55959aa1f991e81f1e7ff1d7` | GHSA-gw74-gwm4-8crp | rocketchat/rocket.chat | NOT_AI | `4126d14b92f3` | `ea163f56b53b` |
| w065 | `alias-580e062d7c557c3e99bea50d` | GHSA-75mg-c62r-v95g | apache/airflow | NOT_AI | `d30331060352` | `e0cac1f6b2dd` |
| w066 | `alias-5af06070f7e1b333f88142d5` | GHSA-hqgf-f82p-fjh7 | mmaitre314/picklescan | NOT_AI | `c1d5abdcc740` | `4d9bc9cd34bc` |
| w067 | `alias-5e05862d35973d2798ac8f44` | GHSA-8vh5-mgjj-w6hg | nltk/nltk | NOT_AI | `4386e344d94c` | `155e40343cff` |
| w068 | `alias-5f8752a75c44a73eea66b378` | GHSA-64vj-7c55-24w2 | jovancoding/network-ai | NOT_AI | `ff375adc3d19` | `f294d33642a9` |
| w069 | `alias-62720f66229a6e06862f123e` | GHSA-9qx4-4584-p9h2 | cachethq/cachet | NOT_AI | `f94b6e75e36d` | `beea6f1d4afa` |
| w070 | `alias-632a622f8428e0e7a4b22ac5` | GHSA-f3c2-j7g8-vpp8 | apache/airflow | NOT_AI | `12b6fa60256e` | `b968192cd3ae` |
| w071 | `alias-63a63d2ac404b72097a6e79e` | GHSA-cjxw-hmxq-h489 | lobehub/lobe-chat | NOT_AI | `7f13f6afb8e7` | `—` |
| w072 | `alias-68744106359bf962e52a3017` | GHSA-984p-rgj2-h89x | apache/airflow | NOT_AI | `ff7c8eb1cdb5` | `0191b1199ea0` |
| w073 | `alias-6c28b345a0929fd7f1586bcd` | GHSA-54xp-3ww7-6wjg | nltk/nltk | NOT_AI | `b271b4def63f` | `1a3cd1764ab3` |
| w074 | `alias-6e442676d299a88a25ec5f0b` | GHSA-5247-m8w9-2v4m | apache/airflow | NOT_AI | `6d0142061cae` | `f81459835adb` |
| w075 | `alias-768b5fe8ae7440d752f7eb8d` | GHSA-58vh-2xxg-v7j2 | sparklemotion/nokogiri | NOT_AI | `1e7d38affc10` | `873948ac21d1` |
| w076 | `alias-7875e54bf013d1b99e2ba3a9` | GHSA-jqpp-mfm2-hfw2 | thorsten/phpmyfaq | NOT_AI | `5611aa5356c9` | `10636a21189b` |
| w077 | `alias-7ac78b85f51eac0d4c3f4a11` | GHSA-gf32-cmjh-8m9v | nltk/nltk | NOT_AI | `fa242f5e1051` | `7a5740af89fe` |
| w078 | `alias-7c031e998c13768caf64a245` | GHSA-jj45-w38g-gfrj | thorsten/phpmyfaq | AI_ROOT_CAUSE | `086c8ad58f91` | `17b7f5b0e181` |
| w079 | `alias-7c401778404a8fc933d1c7b4` | GHSA-2mwq-hcmq-fqq4 | thorsten/phpmyfaq | NOT_AI | `d28770dc075c` | `ad858dfb3a55` |
| w080 | `alias-7e719aaac2a9c50aee8a9d22` | GHSA-2f59-92g6-qm58 | dayuanjiang/next-ai-draw-io | NOT_AI | `64268b0fac5f` | `5bfd7b24680c` |
| w081 | `alias-7ed098aa8faaeea434093792` | GHSA-5jhf-fpp7-v2pv | sparklemotion/nokogiri | NOT_AI | `9246422c850b` | `7501a63b9f42` |
| w082 | `alias-7f3d6094eefe8d0aa8a8d8d4` | GHSA-rh9x-7xjc-vwx2 | sparklemotion/nokogiri | NOT_AI | `d20552c9a3e3` | `caeaac41f874` |
| w083 | `alias-83f8a43e9a2c1c090951cde0` | GHSA-wg4g-rgc9-r6gj | thorsten/phpmyfaq | NOT_AI | `05c3e6d48a98` | `2e07416d51c5` |
| w084 | `alias-85b84f54ef3642ca97c665da` | GHSA-w5q8-6jpp-4246 | nltk/nltk | NOT_AI | `a2167eb7a17f` | `10d34b3f4fe3` |
| w085 | `alias-8758abd6d0e114d0ae71a70f` | GHSA-5gfg-jpw3-fppq | renovatebot/renovate | NOT_AI | `bce4f50dbb6b` | `59de985bb27c` |
| w086 | `alias-886999097a38f0cb7e798141` | GHSA-qp76-pq9f-gr9m | nltk/nltk | NOT_AI | `99527a7c3ab7` | `7d1389d0789c` |
| w087 | `alias-95d59874178ef31f5a8d1bce` | GHSA-jfh6-w7r2-rj74 | rocketchat/rocket.chat | NOT_AI | `063bb1851315` | `3a61c3afed2d` |
| w088 | `alias-9d3e7a272b8adcc0e52a1eef` | GHSA-gvqv-x9gq-w33g | thorsten/phpmyfaq | NOT_AI | `8b14f8c1f097` | `bb3f06bd27c1` |
| w089 | `alias-a1b1c4999647159e698005ee` | GHSA-7g3f-prg4-fg23 | renovatebot/renovate | NOT_AI | `cac941dcacb8` | `4d2d86f9024e` |
| w090 | `alias-a1ffae1bc129147e50587eaf` | GHSA-2ccr-52p8-6754 | karakeep-app/karakeep | NOT_AI | `942aac691225` | `f7d042971d0d` |
| w091 | `alias-ae26194e37c245ca76ae19d4` | GHSA-g3wj-5278-jq3m | karakeep-app/karakeep | NOT_AI | `93049e864ae6` | `—` |
| w092 | `alias-bbc49a380904cdd63ec41325` | GHSA-jjmm-46cq-987q | renovatebot/renovate | NOT_AI | `b96f4e3d9144` | `59de985bb27c` |
| w093 | `alias-c1c247c618bb54f97b64b4fb` | GHSA-hw36-j4q7-vjxx | vllm-project/vllm | AI_ROOT_CAUSE | `9dbcf8c3d5de` | `d83eb0b36bfb` |
| w094 | `alias-ddc393c85932b2b9370f4a23` | GHSA-x628-p4h4-vf39 | owen2345/camaleon-cms | NOT_AI | `341593927249` | `ae10da7cfce9` |
| w095 | `alias-efdc2ff3e43af5f13a858220` | GHSA-8rp2-gc6p-4hgp | renovatebot/renovate | NOT_AI | `342a5069804f` | `59de985bb27c` |
| w096 | `alias-f606e1d015bb6a499ee40b04` | GHSA-rvgr-q8fx-r93h | owen2345/camaleon-cms | NOT_AI | `671a7ed178c7` | `39130b3c9091` |
| w097 | `alias-f8c9e777923b94f9c244b7a8` | GHSA-mf3v-84v4-vjjc | owen2345/camaleon-cms | NOT_AI | `31f1971504d1` | `e9e034e37171` |
| w098 | `alias-0f15ec2c666fb5c06fddb2eb` | GHSA-f5x2-vj4h-vg4c | adonisjs/bodyparser | NOT_AI | `436bb11c1f78` | `40e1c71f958c` |
| w099 | `alias-1d09a6be8414c705749e756d` | GHSA-gvq6-hvvp-h34h | adonisjs/bodyparser | NOT_AI | `81eacb00a7cb` | `143a16f35602` |
| w100 | `alias-3addaa4f5eaf80c7d9c16572` | GHSA-g5gc-h5hp-555f | adonisjs/lucid | NOT_AI | `3d36a661b32d` | `b007b12b40cc` |
| w101 | `alias-51c2ec0bcd297fb5978eb9a2` | GHSA-px2c-r924-mwcc | couchbase/couchbase-net-client | NOT_AI | `35aefa5dfddc` | `04d1679b2178` |
| w102 | `alias-6aede76126dee9ae1698b1e4` | GHSA-xx9g-fh25-4q64 | adonisjs/bodyparser | NOT_AI | `7bc00981abe8` | `7ad95e086b7c` |
| w103 | `alias-76e91e62a72e7ab6b20c3bb6` | GHSA-wqcr-7rf3-f64m | sylabs/singularity | NOT_AI | `48b4735d5a8d` | `c08791793e84` |
| w104 | `alias-d7f3f7d73868c4a64f96e583` | GHSA-qcm7-3vpr-hj5h | adonisjs/bodyparser | NOT_AI | `40e1c71f958c` | `aa96908f7b3f` |
| w105 | `alias-9fbecd95509734a3f91249c2` | GHSA-5xhp-2v8r-m7wh | goodrain/rainbond | NOT_AI | `b9981602508f` | `25fb0c7a29d9` |
| w106 | `alias-ae5c3562b35e97fbafcd63ba` | GHSA-5q5g-57mw-wmq6 | yuzutech/kroki | NOT_AI | `741e6c088bc4` | `f31093cd8a0a` |
| w107 | `alias-11b0dcf80f0882a555b887b6` | GHSA-q5q7-8x6x-hcg2 | arkmq-org/activemq-artemis-operator | NOT_AI | `36aeb84b3c43` | `d3482fab6d00` |
| w108 | `alias-98da36b466ef14d40c66a60c` | GHSA-q66h-m87m-j2q6 | chaintope/bitcoinrb | NOT_AI | `3a777e737b0e` | `070327133a2a` |
| w109 | `alias-0408e626e12f5a6fc21adab1` | GHSA-fvc5-h4x4-cfv4 | wpdevelopers/essential-addons-for-elementor-lite | NOT_AI | `3a2ff8f2c42b` | `d88e08257f66` |
| w110 | `alias-9d181eb10a28d5464a730a0e` | GHSA-mrww-7xh9-f6fh | wpdevelopers/essential-addons-for-elementor-lite | NOT_AI | `b31258ac7a92` | `4e43db06bcf1` |
| w111 | `alias-0412a4a35285dd21de0f0227` | GHSA-chfm-cm6h-q5x7 | concretecms/concretecms | NOT_AI | `e6a4e05418af` | `f22b9dff5945` |
| w112 | `alias-070fe58ed470532aedcac78d` | GHSA-g82f-9pw7-773w | concretecms/concretecms | NOT_AI | `6c4fb938c3b4` | `d088e93b1f42` |
| w113 | `alias-08e8fe4d350d1966937efe07` | GHSA-pv2v-6w2v-97x6 | concretecms/concretecms | NOT_AI | `ac4e7e16808a` | `f22b9dff5945` |
| w114 | `alias-0c8feb9a0f1e625b5a3e6062` | GHSA-f4vq-pj32-gr4q | concretecms/concretecms | NOT_AI | `10236caea734` | `2b7557793f04` |
| w115 | `alias-0d0aa97a4a7d3e00410cf0f1` | GHSA-v3pr-hxpr-mfm8 | apache/mina | NOT_AI | `—` | `409171daa076` |
| w116 | `alias-109b899f0cf05c4efa0695e6` | GHSA-h4f4-gv6h-x824 | magento/magento2 | NOT_AI | `1e26bd94f729` | `13cef1b7d1b4` |
| w117 | `alias-1a6e3850e1433264420875f5` | GHSA-x2fp-hj8c-mmxh | concretecms/concretecms | NOT_AI | `66f16af85c73` | `f22b9dff5945` |
| w118 | `alias-3e8b7b2e80fa2d1dfed87cf4` | GHSA-f2wh-grmh-r6jm | apache/mina | NOT_AI | `691a9df5a0af` | `8b1dadb55b1d` |
| w119 | `alias-409ea4c8fad7cb1ef5f4a9ff` | GHSA-8jmm-3xwx-w974 | alistgo/alist | NOT_AI | `c8f3e8ab4d2f` | `69629ca76a8f` |
| w120 | `alias-40b43adce242ab999c257ae8` | GHSA-3qpq-r242-jqj7 | phpseclib/phpseclib | NOT_AI | `e793461543d1` | `d53d2021bcb9` |
| w121 | `alias-47d2f1cf18c1cdb6371ca640` | GHSA-gw2x-mfwr-h46p | xuxueli/xxl-job | NOT_AI | `9293c61ca0a8` | `7a5239f3b427` |
| w122 | `alias-49cb8bc669519766e2354303` | GHSA-85jx-x9r4-45m2 | magento/magento2 | EVIDENCE_GAP | `1b8236afe67f` | `10fdaddfd21f` |
| w123 | `alias-587aafec5fb95f291cdc6961` | GHSA-xgfm-992v-h2hr | magento/magento2 | NOT_AI | `d551d1e3f70f` | `f83cc26ca1d1` |
| w124 | `alias-5c3e16ae9067c397a3d90c2f` | GHSA-995c-6rp3-4m4x | apache/mina | NOT_AI | `—` | `cca24d646c89` |
| w125 | `alias-66e81fedf4c23ff5c8ef4e1d` | GHSA-x4q4-7phh-42j9 | alistgo/alist | NOT_AI | `f275f83de02b` | `fd693936a13f` |
| w126 | `alias-73ab00fb6220757929a348a0` | GHSA-r355-75hw-r8jf | magento/magento2 | NOT_AI | `3d6bdb94951c` | `bf1f471de6c0` |
| w127 | `alias-7912978619fc13b2f8a82bec` | GHSA-wh92-6q6g-px7j | magento/magento2 | NOT_AI | `f281a0539385` | `8075ae194288` |
| w128 | `alias-7965222101dd977121f3bc20` | GHSA-qxpc-96fq-wwmg | apache/cassandra | NOT_AI | `f078c02cb58b` | `b584a435970e` |
| w129 | `alias-87a0d48b691557d3441892f7` | GHSA-7fxv-8wr2-mfc4 | rancher/local-path-provisioner | NOT_AI | `874088575ce3` | `28710fb09df4` |
| w130 | `alias-87d6c11a6071d0ecd9998a09` | GHSA-fhq3-2gf3-8f3j | misp/misp-modules | NOT_AI | `2be1d7a0cde7` | `52cda9caa003` |
| w131 | `alias-8a74ea5f1aeb262fcc467ef0` | GHSA-fh34-c629-p8xj | apache/cassandra | NOT_AI | `1bb2947dd581` | `b47179b7d4fc` |
| w132 | `alias-8c1738d6464de8f1a216bdfd` | GHSA-m557-wrgg-6rp4 | phpseclib/phpseclib | NOT_AI | `f5807e1d4e13` | `0987dd98832b` |
| w133 | `alias-9c1dc487cc303e12be49dd74` | GHSA-8297-v2rf-2p32 | apache/mina | NOT_AI | `691a9df5a0af` | `8b1dadb55b1d` |
| w134 | `alias-9c511674d1389c1bc95dc86d` | GHSA-94g3-g5v7-q4jg | phpseclib/phpseclib | NOT_AI | `c30f3b7e9a73` | `ccc21aef71eb` |
| w135 | `alias-9cfb31e894bfee65d0797496` | GHSA-jgj7-c8vj-w563 | ulisesbocchio/jasypt-spring-boot | NOT_AI | `0376d901df2b` | `—` |
| w136 | `alias-c7aad5ce4820970f195d932e` | GHSA-vf5j-865m-mq7c | apache/mina | NOT_AI | `—` | `cca24d646c89` |
| w137 | `alias-d20985c8d4cbc26053fa600f` | GHSA-r854-jrxh-36qx | phpseclib/phpseclib | NOT_AI | `df0fe2386a66` | `ffe48b6b1b1a` |
| w138 | `alias-f6e0454ecae71dba8cd3ca59` | GHSA-j4rh-7jcr-qm69 | misp/misp-modules | NOT_AI | `1457575dda5a` | `52cda9caa003` |
| w139 | `alias-ffbea6af31e554be88138163` | GHSA-g9w4-m5fx-x3wv | yoast-dist/duplicate-post | NOT_AI | `8011c3bac314` | `34df3b057ef4` |
| w140 | `alias-071a34986d0d561df529c482` | GHSA-77m7-4hpw-56g7 | tier4/nebula | NOT_AI | `a008a6f84706` | `—` |
| w141 | `alias-0b933428c283fd2ed2890a6f` | GHSA-9mf5-x83c-fg2x | gitlab.torproject.org/tpo/core/tor | NOT_AI | `336a24754d11` | `7477e8bf28df` |
| w142 | `alias-26a72e92880aa7f0af74af49` | GHSA-xh4p-6jqr-58x9 | cerebrate-project/cerebrate | NOT_AI | `5aefc3783746` | `c9bfa90abc85` |
| w143 | `alias-3d5214dba06f5732947a91bc` | GHSA-w92g-j683-fhvq | xpf0000/flyenv | NOT_AI | `d0259bcabf37` | `68fd6d7b2002` |
| w144 | `alias-3d746383031d1d61c897b5b5` | GHSA-cmg9-62q9-xmww | neomjs/neo | NOT_AI | `fae8a8755faf` | `498018638e1b` |
| w145 | `alias-53b9263e067e802a17583be7` | GHSA-r3c6-fj5w-6f75 | gitlab.torproject.org/tpo/core/tor | NOT_AI | `8b185b2ac3d8` | `60369467550f` |
| w146 | `alias-7fb0ce4610329e99804d3778` | GHSA-pq38-gw56-4w65 | gitlab.torproject.org/tpo/core/tor | NOT_AI | `89eb96c19a09` | `4efa20ae2615` |
| w147 | `alias-86adade8d778e33539faebdb` | GHSA-36cc-rhpv-jrxc | gitlab.torproject.org/tpo/core/tor | NOT_AI | `39b597c2fd8b` | `49565af98e44` |
| w148 | `alias-8bf8bbd5e482aa9745b674d8` | GHSA-j5c4-cwjr-6vv5 | gitlab.torproject.org/tpo/core/tor | NOT_AI | `336a24754d11` | `81e8aa45b2ba` |
| w149 | `alias-90e8c355043e95342bd135f3` | GHSA-37c4-9pw5-3r33 | phproxy/phproxy | NOT_AI | `74393b7dd065` | `—` |
| w150 | `alias-1cee710f9588230f35409237` | GHSA-9fjq-45qv-pcm7 | recmo/uint | NOT_AI | `efeee3d169df` | `bc3fad727853` |
| w151 | `alias-09ebd7252f1d98948899ccfb` | GHSA-6jjx-jh3j-cxqj | baserow/baserow | NOT_AI | `a41ab1ac8700` | `a870dc0d38c9` |
| w152 | `alias-29ed9ad1912c63854b7e92fe` | GHSA-6p87-gwpg-qp8w | zanllp/infinite-image-browsing | NOT_AI | `5f98c26b86f7` | `4057a624c7a2` |
| w153 | `alias-87e79c815e09df87b7c34404` | GHSA-cw66-pfp5-82xp | zanllp/infinite-image-browsing | NOT_AI | `5f98c26b86f7` | `4057a624c7a2` |
| w154 | `alias-c96e3afd61609b412069f7a1` | GHSA-ggx8-w5hw-4h29 | covesa/open1722 | NOT_AI | `67fd16fc27be` | `674437149460` |
| w155 | `alias-fa09a057be874ba9d2f4595c` | GHSA-r2g8-gx6q-pvxr | covesa/open1722 | NOT_AI | `67fd16fc27be` | `674437149460` |
| w156 | `alias-7d1336aa40623a56dfbc9349` | GHSA-cxfp-7pvr-95ff | containerd/containerd | NOT_AI | `a21b178f12b2` | `ec3567d6b369` |
| w157 | `alias-be76f5a34ff4d2eb6e293740` | GHSA-m6hq-p25p-ffr2 | containerd/containerd | NOT_AI | `45ee2e554a22` | `083b53cd6f19` |
| w158 | `alias-ced858c6233e9054f92cfb12` | GHSA-cm76-qm8v-3j95 | containerd/containerd | NOT_AI | `d8063c30dd05` | `ac00b8e6108c` |
| w159 | `alias-29e41df4e73615035cb4ede1` | GHSA-8248-cv95-x854 | labredescefetrj/wegia | NOT_AI | `15e731ab88c4` | `83738357b944` |
| w160 | `alias-4ae606f6e9539d1fe64bab90` | GHSA-56r8-9xc4-3g79 | labredescefetrj/wegia | NOT_AI | `c881b4e14637` | `d3b80fd90178` |
| w161 | `alias-9541a14c8a379770f6b9502d` | GHSA-xpm4-qfqg-g2wr | gitlab.freedesktop.org/networkmanager/networkmanager | NOT_AI | `e85cc46d0b36` | `a8e87381a3e7` |
| w162 | `alias-a39f0d5caa473fc8512962e4` | GHSA-8879-fh4f-q3qm | krayin/laravel-crm | NOT_AI | `f344238f734b` | `2a3724cb7e9e` |
| w163 | `alias-ba93eb313ecd1541903f6cc9` | GHSA-hjjv-j557-q7r3 | krayin/laravel-crm | NOT_AI | `f344238f734b` | `2a3724cb7e9e` |
| w164 | `alias-ca3f8b4c76fdbc59511621e9` | GHSA-j8gj-mw5g-642g | krayin/laravel-crm | NOT_AI | `64b90d623f8a` | `6e37f3919f42` |
| w165 | `alias-d05c668b4ff23b0fff488539` | GHSA-cqgm-j57m-cj34 | tainacan/tainacan | NOT_AI | `2dc5cf5c6f6e` | `579d28d7752b` |
| w166 | `alias-ed8fcd1b91b3cfdf27137bc9` | GHSA-2xjx-542r-phch | iomad/iomad | NOT_AI | `3f09d1b3d7f6` | `0c9f8d9ee05d` |
| w167 | `alias-049d9e990bc63abaa2897f2a` | GHSA-hv8m-jj95-wg3x | messagepack-csharp/messagepack-csharp | NOT_AI | `36104610053f` | `719e690abae8` |
| w168 | `alias-058d831b72758b99e08df17d` | GHSA-5vpg-rj7q-qpw2 | yiisoft/yii2 | NOT_AI | `269ce903bdfb` | `109878b491db` |
| w169 | `alias-0a2cc5322720d2111a6e0c03` | GHSA-ffj4-jq7m-9g6v | datadog/guarddog | NOT_AI | `cd08be9a2e3f` | `b2e10d2f5a0e` |
| w170 | `alias-0be1caf9b41978e4de8eb5bd` | GHSA-mf78-3rpf-r784 | julien040/anyquery | NOT_AI | `edfe9dcb68ff` | `27f84fc16831` |
| w171 | `alias-1e5c41e68d66853a0adca7b0` | GHSA-cj9g-3mj2-g8vv | messagepack-csharp/messagepack-csharp | NOT_AI | `2b56a7c106fe` | `a26f555ecfed` |
| w172 | `alias-1ef0eabe9ffcd2dbdfc37878` | GHSA-hwrq-8wxh-q4xv | julien040/anyquery | NOT_AI | `edfe9dcb68ff` | `27f84fc16831` |
| w173 | `alias-239587fb81e2be1bee0bcff9` | GHSA-hrj8-hjv8-mgwc | julien040/anyquery | NOT_AI | `d2ecb36e6375` | `33769e03bd4b` |
| w174 | `alias-23f33f211dc3503dd2175443` | GHSA-65fp-7g2v-658r | bagisto/bagisto | FALSE_POSITIVE | `—` | `—` |
| w175 | `alias-2457a298c8a5abb2c9510491` | GHSA-xg9w-vg3g-6m68 | datadog/guarddog | NOT_AI | `cd08be9a2e3f` | `9aa6a725b2c7` |
| w176 | `alias-268012bccddeda1aaf365bfe` | GHSA-w567-gjr2-hm5j | messagepack-csharp/messagepack-csharp | NOT_AI | `d8a42395ae66` | `0555f07cbf21` |
| w177 | `alias-40f1da5aec5a3423703d1343` | GHSA-382j-8mxh-c7x2 | messagepack-csharp/messagepack-csharp | NOT_AI | `35682022fa24` | `26d4e743ca2a` |
| w178 | `alias-41c66fdf3bfbc6dd2b335ecb` | GHSA-v75r-vx73-82pj | cyclonedx/cyclonedx-node-npm | NOT_AI | `7da79c148dae` | `9f646253f426` |
| w179 | `alias-5a21f357f433c1977460060b` | GHSA-xrcf-6jh3-ggvx | julien040/anyquery | NOT_AI | `90e7eaa8f3d7` | `27f84fc16831` |
| w180 | `alias-61165ef6b55810915b62b216` | GHSA-98wm-cxpw-847p | invoiceninja/invoiceninja | EVIDENCE_GAP | `—` | `b81a3fc30257` |
| w181 | `alias-63b664d85451309a6a17605f` | GHSA-vh6j-jc39-fggf | messagepack-csharp/messagepack-csharp | NOT_AI | `62700694def6` | `b9cb6050908f` |
| w182 | `alias-86108b6dcf06c918d8dace0a` | GHSA-x3f9-vcp2-hgcw | bagisto/bagisto | NOT_AI | `55b71e1e663c` | `90a962fe2044` |
| w183 | `alias-95879d037bbd7985705d50c1` | GHSA-x5rw-qvvp-5cgm | bagisto/bagisto | NOT_AI | `3e44549e6545` | `b2b1cf625772` |
| w184 | `alias-97ba1bb04896d21a51d86e41` | GHSA-587r-mc96-6f2p | datadog/guarddog | NOT_AI | `b198bdef92ab` | `5d15a38a0395` |
| w185 | `alias-a83e2f6a59be7805a5098d4e` | GHSA-r8xr-pgv5-gxw3 | kuadrant/authorino | NOT_AI | `f8895e464ed3` | `—` |
| w186 | `alias-b013e77a664e33890f7c75b9` | GHSA-mqhg-v22x-pqj8 | bagisto/bagisto | NOT_AI | `15043a249ba9` | `4144931da001` |
| w187 | `alias-b1699731c6e6c6f4b795128d` | GHSA-2mwc-h2mg-v6p8 | bagisto/bagisto | NOT_AI | `b1285fa2433f` | `0a9059d5a7dc` |
| w188 | `alias-c18618ce23ece28347b904c4` | GHSA-m5p4-gvpx-4mvr | datadog/guarddog | NOT_AI | `fab6f9642091` | `ec0705814fa3` |
| w189 | `alias-c19a6318057f9e3f0a63be9a` | GHSA-4xh5-jcj2-ch8q | controlplaneio-fluxcd/flux-operator | NOT_AI | `eba38678c032` | `084540424f6d` |
| w190 | `alias-c29c69e20b4ace9fc826779e` | GHSA-j9rx-rppg-6hh4 | julien040/anyquery | NOT_AI | `bff740c2a2ae` | `27f84fc16831` |
| w191 | `alias-ccf93a7cec91c86aaa4d56ef` | GHSA-4c44-r8rm-3p39 | novosga/novosga | NOT_AI | `b55a045d1f92` | `424957aeeaa3` |
| w192 | `alias-d3d4ec30daea2d9b395ab407` | GHSA-c96f-x56v-gq3h | delvedor/find-my-way | NOT_AI | `acf1283552c1` | `cfe3fd6168b5` |
| w193 | `alias-d7380c8820f083472a4e4c3a` | GHSA-9h5v-pfqq-x599 | faisalman/ua-parser-js | NOT_AI | `aed89f0b414f` | `90354d345849` |
| w194 | `alias-df693add9d8e1d6639f07692` | GHSA-xgr2-5837-hf48 | novosga/novosga | NOT_AI | `556dde92fb3e` | `—` |
| w195 | `alias-e64afc2954aa7554424ab33b` | GHSA-xv9w-7v6q-hpjh | fluent/fluent-plugin-s3 | NOT_AI | `de1ffbe1e6b9` | `e085aee001d1` |
| w196 | `alias-ec7e1d6ea3c9983abcb7450a` | GHSA-vqvv-2wj5-q34w | kuadrant/authorino | NOT_AI | `a85b10f23537` | `—` |
| w197 | `alias-a0a8576723a479096122938c` | GHSA-9j3x-w929-5ch3 | everest/everest-core | NOT_AI | `40b148b649ae` | `b8ab2777d927` |
| w198 | `alias-01cce0b6fc0d53af48fe3e7a` | GHSA-fv6j-9p8m-c3wr | mtrudel/bandit | NOT_AI | `6feadb31189d` | `f6914aad14bb` |
| w199 | `alias-5d31c88f3f7542cff392ace5` | GHSA-47p7-hmcr-q3rr | killergerbah/asbplayer | NOT_AI | `209fe85c993e` | `65f0cdce0579` |
| w200 | `alias-7150c422fc00ef3a528792ab` | GHSA-3rvx-fcj6-wr45 | opensearch-project/sql | NOT_AI | `486063eb4afc` | `25529e7ead3f` |
| w201 | `alias-73de0c8187b63c1e8039d6f2` | GHSA-3hm7-m5p9-2h77 | wp-statistics/wp-statistics | NOT_AI | `e83c5a764428` | `4a912c6e9080` |
| w202 | `alias-d31f146de1346c2cef8dfe17` | GHSA-9pp6-v7j8-j65j | lucasgelfond/zerobrew | NOT_AI | `5e9da9406db4` | `89a60b73c7ed` |
| w203 | `alias-e2ca9e9dcb1995266dd86326` | GHSA-23xx-x3px-xxpj | mtrudel/bandit | NOT_AI | `aa68cfc718dd` | `d38cf046c9a3` |
| w204 | `alias-810b8e6e8a7b57af6c81b51b` | GHSA-r3r8-w3g2-hq7h | rnpgp/rnp | NOT_AI | `020c61c4814d` | `1a2359d623e4` |
| w205 | `alias-b41bfb6d8d97ab855af0d56b` | GHSA-p63x-hq5f-7f58 | harry0703/moneyprinterturbo | NOT_AI | `00052b4c5037` | `18f5e478979b` |
| w206 | `alias-04ff4a2ae20f049dd85b8235` | GHSA-5gr5-vmmr-82g6 | erupts/erupt | NOT_AI | `1405b8b1fe76` | `58ed8631700f` |
| w207 | `alias-079ef85ce8e0fdd73dd256a9` | GHSA-rpg2-jvhp-h354 | redhatinsights/yggdrasil | NOT_AI | `68ec1b651433` | `196d0cbea42f` |
| w208 | `alias-8f8b4319ac4e99b5aba756ca` | GHSA-f5xg-cfpj-2mw6 | nervjs/taro | NOT_AI | `33cf18fabb67` | `c2e321a8b6fc` |
| w209 | `alias-a122f80ebfd92a7aa1d59582` | GHSA-mm3p-j368-7jcr | unjs/ipx | NOT_AI | `a60fb0d44b96` | `81693ddbfc06` |
| w210 | `alias-3264bc95406d406529a1f8fc` | GHSA-qv97-5qr8-2266 | input-output-hk/mithril | NOT_AI | `07b38289ad8e` | `0b411eab64e9` |
| w211 | `alias-04e2c4eadbef4c1efd1789ef` | GHSA-27p7-fq6v-hh4m | frrouting/frr | NOT_AI | `128ea8abbd38` | `4825b5ba5633` |
| w212 | `alias-08870751f4b5f8625066756b` | GHSA-cg97-7v4v-qg3v | op-tee/optee_os | NOT_AI | `ad194957b670` | `0aadfc23407f` |
| w213 | `alias-1b86e239a59590b22a9f8f79` | GHSA-wjc3-2qjv-c8fp | frrouting/frr | NOT_AI | `cf9b9f77f638` | `f098decf0298` |
| w214 | `alias-1fecf5414844884ea1886689` | GHSA-wrjr-rgfw-cm84 | fosowl/agenticseek | NOT_AI | `d1954ff32621` | `f1eb2cfc721f` |
| w215 | `alias-29fd22c81aad302f00cb7cff` | GHSA-rf2w-6p6m-3cqv | trinodb/trino | FALSE_POSITIVE | `—` | `—` |
| w216 | `alias-5addbf343b520d2a95313dce` | GHSA-p84g-83m7-53p6 | op-tee/optee_os | NOT_AI | `387b0ee39b1b` | `8794043c4065` |
| w217 | `alias-88987297646cef164c60b322` | GHSA-hpx7-jm9p-88gh | swe-agent/swe-agent | NOT_AI | `5b143857cb7a` | `—` |
| w218 | `alias-8999c2992850bc3e70d9def0` | GHSA-q7jj-qhhg-6m9g | frrouting/frr | NOT_AI | `47555ee921fa` | `0e6882bc72c0` |
| w219 | `alias-b2b14cc1f1ad84e6351a291a` | GHSA-4j2p-28q2-5m79 | huggingface/accelerate | NOT_AI | `6a74308ab4b2` | `—` |
| w220 | `alias-d01552a041ba3d98187cc992` | GHSA-6qpj-whq8-wr7j | trustwallet/wallet-core | NOT_AI | `d7290d43c14a` | `5668c67a5ca9` |
| w221 | `alias-da599766548655dcf57b756c` | GHSA-hg7c-pmh6-576f | op-tee/optee_os | NOT_AI | `f8907bbf8d02` | `7b8b494e0a32` |
| w222 | `alias-e1b1b425e92b3410110944fc` | GHSA-hmpg-chwg-jvg8 | frrouting/frr | NOT_AI | `d311a698deb8` | `693a2e02687c` |
| w223 | `alias-f47bd2b9d061222a7d643472` | GHSA-4ph9-3c4q-r2hh | frrouting/frr | NOT_AI | `65efcfce427e` | `7676cad65114` |
| w224 | `alias-033ccab37c7db0c611a0e1bb` | GHSA-hfqg-gq7v-xwpg | sparklemotion/nokogiri | NOT_AI | `131df0d6bf14` | `a8c526adf177` |
| w225 | `alias-0ac79d9e89f4e7a5f2fab95d` | GHSA-cgqh-cr58-mqgh | liftoff-sr/cipster | NOT_AI | `2d6b8f3eaafd` | `ea870a274bf6` |
| w226 | `alias-0bab0183add216a12024228f` | GHSA-qvp4-q2p5-22gg | mmaitre314/picklescan | NOT_AI | `c1d5abdcc740` | `7f994d62084f` |
| w227 | `alias-10f424b37aea92b018b86c24` | GHSA-7jm4-f7vj-6pcc | mmaitre314/picklescan | NOT_AI | `c1d5abdcc740` | `62e76cfdf9aa` |
| w228 | `alias-1ae5b298c391ad33926edb0f` | GHSA-2ph4-3vr8-f2m3 | sparklemotion/nokogiri | NOT_AI | `131df0d6bf14` | `6457fe639359` |
| w229 | `alias-2e589975108dd9d8709e9dab` | GHSA-vp8m-mf3r-82q9 | mmaitre314/picklescan | NOT_AI | `c1d5abdcc740` | `aecd11be9870` |
| w230 | `alias-5966b54d9e5177fac38be456` | GHSA-wp3c-7fhf-vm5h | liftoff-sr/cipster | NOT_AI | `90721b00e44e` | `e745d9d4a8ca` |
| w231 | `alias-5dbb91d5a9bd3caa90a37292` | GHSA-xxw5-vgjv-jc6g | liftoff-sr/cipster | NOT_AI | `90721b00e44e` | `3a0159ed4312` |
| w232 | `alias-720672c2359e9ab914f671d7` | GHSA-pvgm-mg5q-xc76 | fluentcms/fluentcms | NOT_AI | `0fdb790520a5` | `—` |
| w233 | `alias-81606d17927cc512cfd44cf6` | GHSA-v2c6-62qq-rjcr | pydio/cells | NOT_AI | `c5cb0b5a19bd` | `—` |
| w234 | `alias-9f9c2209e45ba0a5d8439785` | GHSA-j7c4-3mfp-j7v9 | libcsp/libcsp | NOT_AI | `e143ee74d326` | `a8649782b05f` |
| w235 | `alias-ba8bc7ea829c1e317fcd3cde` | GHSA-v82x-ghcg-c238 | fluentcms/fluentcms | NOT_AI | `79045878d9ba` | `—` |
| w236 | `alias-cb429e86f759d4d6ac86939b` | GHSA-w4qj-vxw3-g77r | liftoff-sr/cipster | NOT_AI | `186ffccd18ab` | `886a4d090e1c` |
| w237 | `alias-cf900bae1a812ad0069ce2fe` | GHSA-7m9c-h5vv-88gq | fluentcms/fluentcms | NOT_AI | `0fdb790520a5` | `—` |
| w238 | `alias-d9b463a522ac3009ac44e871` | GHSA-mmm3-jq63-7mw5 | libcsp/libcsp | NOT_AI | `307f4077288f` | `dd1ad4d2c5c5` |
| w239 | `alias-fcb34f18a96610af6219bd26` | GHSA-q8vh-mhmw-wmcq | liftoff-sr/cipster | NOT_AI | `d442e60357a8` | `e8e9dba09bf5` |
| w240 | `alias-0818185f8f22e9a62c6f26d4` | GHSA-m69x-pw9p-7j3q | spring-projects/spring-security | NOT_AI | `e9a44bc0ce98` | `9d4d9065b485` |
| w241 | `alias-112fc07547642be4ffc556a9` | GHSA-cq87-8r7h-962v | apple/swift-nio | NOT_AI | `976f4752dfff` | `dd16365724d5` |
| w242 | `alias-18f02f30b058229e19c793d9` | GHSA-rj37-6j9x-74q6 | apple/swift-nio | NOT_AI | `c154ceec1ef7` | `b24872d3aa4a` |
| w243 | `alias-207901cf15a22c66d8513fab` | GHSA-2hfh-9h53-qc24 | apache/ws-neethi | NOT_AI | `8baf24289b8a` | `7a38f2be139d` |
| w244 | `alias-251db8dc68c8acdab3dadaac` | GHSA-97r5-pg8x-p63p | pallets-eco/flask-security | NOT_AI | `51a024574473` | `8e69f3a94a46` |
| w245 | `alias-25ebef6e77ba9f2870eaf67f` | GHSA-hqwm-7x7x-8379 | devspace-sh/devspace | NOT_AI | `764fefcd27f7` | `6b5073d5c38c` |
| w246 | `alias-28ede3a298a2c59fb29633cd` | GHSA-6cmp-qv2f-x97x | velocidex/velociraptor | NOT_AI | `f20ab033e4a1` | `716559831911` |
| w247 | `alias-2da295bf3990fb8cdd4ee43c` | GHSA-qhp6-635j-x7r2 | static-web-server/static-web-server | NOT_AI | `abc76a8c1f19` | `7bf0fd425eb1` |
| w248 | `alias-3f6dd612f18e1e8d588b5ae1` | GHSA-prf8-cf2x-rhx7 | hyperledger/fabric | NOT_AI | `9282be96df6e` | `—` |
| w249 | `alias-4013ee81709d84438bd0b642` | GHSA-vxf7-qj7q-83fh | spring-projects/spring-security | NOT_AI | `c076f0f2e190` | `a317a3d86639` |
| w250 | `alias-47362631449f5c302b1ff663` | GHSA-9fj4-3849-rv9g | openkruise/kruise | NOT_AI | `5667ad394e5b` | `94364b76adf3` |
| w251 | `alias-475b0f28c24a3f4fd14d67ec` | GHSA-r3rc-9hpw-54v9 | apple/swift-nio | NOT_AI | `ba791a0ed51a` | `87f935b70c5e` |
| w252 | `alias-49048428f0124aca33b5d40a` | GHSA-2v93-vp82-cjv8 | velocidex/velociraptor | NOT_AI | `83448b40d12d` | `716559831911` |
| w253 | `alias-4d702d4e4e38f6916e3360b2` | GHSA-2q7c-5gjm-7q23 | spring-projects/spring-security | NOT_AI | `16fd24c0025f` | `97a49aa3bf23` |
| w254 | `alias-4e60996c21aefb6f57ef651d` | GHSA-ww38-37g9-m3q3 | spring-projects/spring-security | NOT_AI | `e9a44bc0ce98` | `e50c2a6a74d5` |
| w255 | `alias-50fcbd8ef1612c5a41eb907e` | GHSA-2jrg-rf5x-568g | spring-projects/spring-security | NOT_AI | `aba437d4698c` | `88118afb8f93` |
| w256 | `alias-58aebbf5614b43b414a9950a` | GHSA-r2jv-fwfr-4j8c | askbot/askbot-devel | NOT_AI | `929cba67ae17` | `3da3d75f3520` |
| w257 | `alias-5c08e1b57f6718120a20bd5f` | GHSA-gmwr-9j4p-96vm | processwire/processwire | FALSE_POSITIVE | `—` | `—` |
| w258 | `alias-6b1186e7e9e726230979e232` | GHSA-hv5g-26jg-pc45 | velocidex/velociraptor | NOT_AI | `416a2e9d7e07` | `1c6f3b700d67` |
| w259 | `alias-86a1fe9e952cb04d5e675f9a` | GHSA-287c-fxr7-3w6c | apache/ws-neethi | NOT_AI | `ee7f26a25bdb` | `196862e97da0` |
| w260 | `alias-9221e625b5affc842a462859` | GHSA-hm8f-75xx-w2vr | sigstore/sigstore-python | NOT_AI | `37fa700a95d6` | `5e77497fe8f0` |
| w261 | `alias-9f5a2214d7af46a6b11a403b` | GHSA-53wx-pr6q-m3j5 | apache/parquet-java | NOT_AI | `0e9240f5aa6f` | `2fef79bb53ea` |
| w262 | `alias-9facb10815652e7cc3caa664` | GHSA-g36m-9g3m-2vmp | apache/ws-neethi | NOT_AI | `ae621abb456e` | `9069bcf9d401` |
| w263 | `alias-b0086d62e1c6c328309e8f6c` | GHSA-f8q5-h5qh-33mh | xygeni/xygeni-action | NOT_AI | `4bf1d4e19ad8` | `13c6ed2797df` |
| w264 | `alias-b0c056603519a4df794707cc` | GHSA-v6c2-xwv6-8xf7 | borewit/music-metadata | NOT_AI | `aba797eded02` | `318e963e2173` |
| w265 | `alias-bcb0733c55b345f57ef969de` | GHSA-3c93-g9g6-p5j4 | velocidex/velociraptor | NOT_AI | `90208c6d9d29` | `3c84e6413e69` |
| w266 | `alias-dcd30bce1e5bb1dbce0594f7` | GHSA-w5hq-g745-h8pq | uuidjs/uuid | NOT_AI | `37a5efa8b8a7` | `3d2c5b0342f0` |
| w267 | `alias-4074738cbdb652f884babf05` | GHSA-pwhc-rpq9-4c8w | containerd/containerd | NOT_AI | `a0a5cc778760` | `7c59e8e9e970` |
| w268 | `alias-073938ef4ff64e3cf957d867` | GHSA-x4cc-vgcc-h5h4 | gitlab.gnome.org/gnome/libsoup | NOT_AI | `732fcd4bb689` | `5c1a2e9c06a8` |
| w269 | `alias-0971fb28eef94bfa9b3a7c93` | GHSA-hg24-p7xv-jhq8 | gitlab.gnome.org/gnome/libsoup | NOT_AI | `264eb7480e3a` | `739bf7cb509c` |
| w270 | `alias-124b66791665a333f94bb54c` | GHSA-wpfw-5xvc-wq9w | gitlab.gnome.org/gnome/libsoup | NOT_AI | `a89a4910bc35` | `e9b681a5b23f` |
| w271 | `alias-154dfb6a8008d88303151b03` | GHSA-wmpg-2mpv-2hmm | gitlab.gnome.org/gnome/libsoup | NOT_AI | `7aee2eeb1ca5` | `e82c13ba03de` |
| w272 | `alias-15d9fe6659d18b6779ed7cc5` | GHSA-6p72-283f-crv2 | gitlab.gnome.org/gnome/libsoup | NOT_AI | `207f87a86eaf` | `—` |
| w273 | `alias-256b1c88d6c106fa37af1c5e` | GHSA-rpc6-j92g-4x56 | indilib/indi | NOT_AI | `4d63b7497c17` | `96bbd7f564bb` |
| w274 | `alias-3f3939baeb5f47aea511994e` | GHSA-f3q7-jj9x-2wjr | fujitsuresearch/onecompression | NOT_AI | `bc9f97c215b0` | `70e89052a6b2` |
| w275 | `alias-4e2f7550673eac0b45258c88` | GHSA-rfq2-gv2r-vgjg | riot-os/riot | NOT_AI | `52aec3ad32fb` | `ddff869df57b` |
| w276 | `alias-6550607fe4f4ead3b6c71d7b` | GHSA-742g-xjv2-hvh9 | formalms/formalms | NOT_AI | `48ffe2139a82` | `—` |
| w277 | `alias-6ecb3d605d4fcf0548d89172` | GHSA-93xg-c6hj-rp82 | idurar/idurar-erp-crm | NOT_AI | `e968bc95b8a1` | `—` |
| w278 | `alias-763adaa33b4ac5a3a77ce2bc` | GHSA-6fmw-7w5g-3pf9 | gitlab.com/samba-team/samba | NOT_AI | `042df7f0b78d` | `79caa6ef08b9` |
| w279 | `alias-8315569d2b3a5c61cd42c7be` | GHSA-79v2-fj3p-7x4f | antvis/layout | NOT_AI | `b9fde76f4c45` | `—` |
| w280 | `alias-860bbc837a56cd8348805125` | GHSA-49v6-p72m-p687 | yacy/yacy_search_server | NOT_AI | `4b77733e59dd` | `008b8c3b499e` |
| w281 | `alias-8bb1b4e7ea326c70e2b1d859` | GHSA-rcpp-qhfh-r47v | quickjs-ng/quickjs | NOT_AI | `878647e21dec` | `c5d80831e51e` |
| w282 | `alias-8cbd27f3ae08b43f59886b3f` | GHSA-44p3-ph5c-h5h3 | getmaxun/maxun | NOT_AI | `7e2258299716` | `11db0257531f` |
| w283 | `alias-8ec36ba82448495a669833a8` | GHSA-67vh-536w-6pc4 | quickjs-ng/quickjs | NOT_AI | `878647e21dec` | `53eefbcd6951` |
| w284 | `alias-9faecf77268e2403081d4563` | GHSA-xjvw-vc5c-qgj5 | riot-os/riot | NOT_AI | `1a146f7934d0` | `6e06b384233d` |
| w285 | `alias-ab9acbb7c6030c57f8155aa5` | GHSA-gr63-2w3v-w2gp | quickjs-ng/quickjs | NOT_AI | `ef8dc076e018` | `daab4ad4bae4` |
| w286 | `alias-adb7a0b5f04189f71c9aa3e2` | GHSA-5m3h-w8g2-q63h | quickjs-ng/quickjs | NOT_AI | `c27cdfc43d5e` | `397310610529` |
| w287 | `alias-b4ec3138287d9cd939470cea` | GHSA-2gmr-vqp5-r9qg | quickjs-ng/quickjs | NOT_AI | `878647e21dec` | `ea3e9d77454e` |
| w288 | `alias-c9df92813e9608dcdc6e0e43` | GHSA-9cx2-fwcj-qq73 | xorbitsai/inference | NOT_AI | `224f81247ca5` | `77511b444b09` |
| w289 | `alias-f5fb798bcd081371c625de96` | GHSA-w4x2-2pcx-2cpc | fishcodetech/muteki | EVIDENCE_GAP | `013ab6bf5fde` | `—` |
| w290 | `alias-38cfc55a9eb78b42318e66ea` | GHSA-wg5p-8h9p-3mr7 | naranor/agent-coderag | NOT_AI | `b6bb9d7f25dc` | `1d917513cd95` |
| w291 | `alias-48fc20ef32757cb47993d255` | GHSA-8rw6-p7m8-63jp | surrealdb/surrealdb | NOT_AI | `c4386f1549ba` | `8f89b260bb96` |
| w292 | `alias-061db5e605f24329a6bbff0b` | GHSA-5c4f-pxmx-xcm4 | apache/cassandra | NOT_AI | `0b83682b40d3` | `066c489d764d` |
| w293 | `alias-1e6f631fa96725e6e80a6258` | GHSA-h3qp-hwvr-9xcq | octo-sts/app | NOT_AI | `e6d0bdf23044` | `b3976e39bd8c` |
| w294 | `alias-4f18d6b89e282fac75ef5628` | GHSA-jr3w-9vfr-c746 | rancher/local-path-provisioner | NOT_AI | `af85381fd304` | `1ed6b546b8db` |
| w295 | `alias-67d47274d2d864426a971733` | GHSA-qgp8-v765-qxx9 | cloudflare/workers-oauth-provider | AI_ROOT_CAUSE | `b1079e7beb5f` | `09a2adb2f197` |
| w296 | `alias-89fc55956ba0b4bc2bf0c0f5` | GHSA-565h-44m8-4c2v | xuxueli/xxl-job | NOT_AI | `0a3542dcac7b` | `cb1bd548a6d9` |
| w297 | `alias-94e43bc58f8dba40785f7dca` | GHSA-4pc9-x2fx-p7vj | cloudflare/workers-oauth-provider | AI_ROOT_CAUSE | `3b2ae809e925` | `4393dd4f9615` |
| w298 | `alias-a7a4991b958fcea21bbb8e9c` | GHSA-f8vw-8vgh-22r9 | xuxueli/xxl-job | NOT_AI | `a1755156e2da` | `c741d8361ee9` |
| w299 | `alias-a957f60880b91689c9fa6ed4` | GHSA-6m8w-jc87-6cr7 | open-policy-agent/opa | NOT_AI | `d3f5102aa4d6` | `ad2063247a14` |
| w300 | `alias-dcab1727eca653bdc9f6b9b9` | GHSA-gjx6-h8hm-c9rq | xuxueli/xxl-job | NOT_AI | `d66bdc88113e` | `b683e65168d1` |
| w301 | `alias-e93298eb5474e1b245b669bc` | GHSA-6rq7-m52p-8pqg | xuxueli/xxl-job | NOT_AI | `8a8d7a5caf0a` | `d71e69a69c5a` |
| w302 | `alias-d1f0d769b4506edb09060e34` | GHSA-h8w6-x833-p4x4 | sahlberg/libsmb2 | NOT_AI | `189e5edab3ae` | `5e75eebf922b` |
| w303 | `alias-00c08a4d36548a08c12cdee7` | GHSA-7p8h-8h8j-472c | vladimir-tokarev-cyera/llama-cpp-security-patches | NOT_AI | `662aaea8c9c6` | `—` |
| w304 | `alias-059d49cd14078f8455c9f065` | GHSA-vv96-h3xf-q33j | horilla-opensource/horilla-crm | NOT_AI | `14ca79728363` | `fc5c8e55988e` |
| w305 | `alias-13cab56e58910a5206e6928e` | GHSA-h26w-wq3x-9p76 | akaunting/akaunting | NOT_AI | `ddd18c7ea6f8` | `80ef6d3b154a` |
| w306 | `alias-1538e5138ecc7af29635c310` | GHSA-r4j6-x8h7-4f8w | alseambusher/crontab-ui | NOT_AI | `b207df5332b9` | `—` |
| w307 | `alias-1560a140e8811bf17daaa441` | GHSA-3777-v3gr-3jr3 | akaunting/akaunting | NOT_AI | `d9c076457215` | `80ef6d3b154a` |
| w308 | `alias-210d3ac30996ad1cd0bb5d8a` | GHSA-6m8g-7xrr-8q5f | webmin/webmin | NOT_AI | `f6788682b34b` | `cf432879a145` |
| w309 | `alias-2826ec37bcd89c3d3b60ce5b` | GHSA-c2p7-hcxm-xqhj | vas3k/taxhacker | NOT_AI | `d8711b714285` | `—` |
| w310 | `alias-31fd62e8e6aaa9072c014bc3` | GHSA-cqj6-j4f4-mcpp | horilla-opensource/horilla-crm | NOT_AI | `61c54bbb22a3` | `730b5a44ff06` |
| w311 | `alias-4f401d448319feb66dd70aa2` | GHSA-9848-6qgw-2748 | webmin/webmin | NOT_AI | `b30868ce165f` | `da18a16c84ae` |
| w312 | `alias-59701fdd6d717f8118b77521` | GHSA-jfqq-rfm8-8frm | hashcat/hashcat | EVIDENCE_GAP | `ef52453de952` | `6f374c4ff7d5` |
| w313 | `alias-62829739710228997e8c4372` | GHSA-g2r8-97m7-62w9 | duckdb/duckdb-aws | NOT_AI | `07991443a780` | `7d04119ee8d3` |
| w314 | `alias-6d9b7e7f3b75552edf8715ff` | GHSA-25qx-69jj-jfcj | alseambusher/crontab-ui | NOT_AI | `0c6cc5512adf` | `—` |
| w315 | `alias-84436ad872bfed39828d8257` | GHSA-6gxr-4p8w-gxc9 | vladimir-tokarev-cyera/llama-cpp-security-patches | NOT_AI | `addae65fd44d` | `—` |
| w316 | `alias-8a6b84048b61cdf9987e9d06` | GHSA-c9g5-5438-6vvf | akaunting/akaunting | NOT_AI | `d9c076457215` | `—` |
| w317 | `alias-8b2c1d0e732a44cd0613d5ff` | GHSA-3f2h-96vw-c84x | vladimir-tokarev-cyera/llama-cpp-security-patches | NOT_AI | `e6ab62c4a1af` | `—` |
| w318 | `alias-905c97025d1e12c3e2cdb067` | GHSA-h3jq-rqqh-3gvh | civicrm/civicrm-core | NOT_AI | `a04756886989` | `—` |
| w319 | `alias-999c3b211116b11b52c3fbfc` | GHSA-v47h-4p48-9r9r | akaunting/akaunting | NOT_AI | `6d50fa844252` | `96c38008cf6f` |
| w320 | `alias-9c73f039e2cef1de1621ca70` | GHSA-wvf4-v63v-mwm5 | vladimir-tokarev-cyera/llama-cpp-security-patches | NOT_AI | `9697338d2d48` | `e1efd0991d85` |
| w321 | `alias-a3667c05295a72b132d0d9bd` | GHSA-hrrq-qh5p-23c2 | vas3k/taxhacker | NOT_AI | `b41fb0bba679` | `—` |
| w322 | `alias-b5d3a758daf589da5f00d70f` | GHSA-xpvh-gv3p-w5qx | webmin/webmin | NOT_AI | `fc1c1b243f79` | `—` |
| w323 | `alias-b8321412522485592f282a5f` | GHSA-2rpj-3356-c2rw | webmin/webmin | NOT_AI | `27d3d6cb9738` | `cf432879a145` |
| w324 | `alias-d9cde0ce3770f581346632b0` | GHSA-9x3x-hjpw-2q3f | ericlbuehler/mistral.rs | NOT_AI | `ec4ccb9ac31e` | `cd5297e2ea5c` |
| w325 | `alias-df57e3cd613998b205c70e6c` | GHSA-8hjx-7pv7-rr27 | squidex/squidex | NOT_AI | `beb2a508bddf` | `—` |
| w326 | `alias-df6deb3c385573a2438386f1` | GHSA-8qr5-q795-mv79 | code100x/cms | NOT_AI | `a60ba45f26cb` | `—` |
| w327 | `alias-e1d9ee55bc16f2fa71708a73` | GHSA-23xj-gfh3-wf2h | webmin/webmin | NOT_AI | `b3b5fff0dc48` | `efae1cf754e4` |
| w328 | `alias-e51091acb8bb63a76751426a` | GHSA-vgv2-whp7-2895 | hashcat/hashcat | NOT_AI | `97c9e86d155d` | `93b55d37d3b2` |
| w329 | `alias-e6afbab1e30ebd77e4bf14a9` | GHSA-6hc7-9rph-cm99 | vladimir-tokarev-cyera/llama-cpp-security-patches | NOT_AI | `e6ab62c4a1af` | `—` |
| w330 | `alias-f86acb29ba3858a142e7a0e4` | GHSA-5qq7-x27p-hfq4 | hashcat/hashcat | NOT_AI | `5065474b4e5e` | `fcae69f2438f` |
| w331 | `alias-fc0a3e93b181101f3bc20b79` | GHSA-cm34-rh84-36rf | hashcat/hashcat | NOT_AI | `a460ab01b684` | `68f56a2d8712` |
| w332 | `alias-fc85fd946d751ae78b2030ff` | GHSA-rqfr-jhc5-r4q9 | akaunting/akaunting | NOT_AI | `515bdaf5cd43` | `80ef6d3b154a` |
| w333 | `alias-dc201851f836b74a75a740ae` | GHSA-3h96-34p3-xm76 | rmosolgo/graphql-ruby | NOT_AI | `c634445febcc` | `88d6c1ca5192` |
| w334 | `alias-17c3175d7cad1b687072e156` | GHSA-fgmm-c43r-4vvc | the-events-calendar/the-events-calendar | NOT_AI | `d26394e9c59c` | `03b53c73eb17` |
| w335 | `alias-cb6e1a954a6d6437f3c31009` | GHSA-c6q3-c35r-7vcf | tainacan/tainacan | NOT_AI | `8234540ec866` | `8ea7ecf14e5b` |
| w336 | `alias-ea74e4f064c4de916175da2d` | GHSA-37g4-vx3r-j5q5 | tainacan/tainacan | NOT_AI | `8a01249afd46` | `8468fb4ec76c` |
| w337 | `alias-00e8aaffc90c0ba6a7d3098d` | GHSA-42cj-m3vj-89wv | traefik/traefik | NOT_AI | `982f10368ffe` | `67501cbe7bc7` |
| w338 | `alias-0164997606796566d1970ee1` | GHSA-62fc-8686-hfmq | traefik/traefik | NOT_AI | `36a565a59998` | `65ebf4b47fbd` |
| w339 | `alias-028626b3c0926bca7768d9b6` | GHSA-6pvw-g552-53c5 | git-lfs/git-lfs | NOT_AI | `e445b45c1c9c` | `8b4aede153ff` |
| w340 | `alias-0389f68c5dc855b285c98b38` | GHSA-9pgc-3ccv-5297 | python-zeroconf/python-zeroconf | NOT_AI | `0a36cc6815a7` | `f9e23592137f` |
| w341 | `alias-046ee9496f25dedf22036f47` | GHSA-6c37-7w4p-jg9v | nationalsecurityagency/emissary | NOT_AI | `c702bb7d6975` | `5b909b5b8ae9` |
| w342 | `alias-04bb99df869250f012854922` | GHSA-46g3-37rh-v698 | step-security/harden-runner | NOT_AI | `c793555005be` | `fa2e9d605c4e` |
| w343 | `alias-05664ab63a43dfe6d17a9839` | GHSA-v853-w46p-fv2h | apache/activemq | NOT_AI | `ef53b5b7b7ba` | `cf0006041d2c` |
| w344 | `alias-05dc6059d886a1ab2824a431` | GHSA-w8hm-jrh2-57j3 | renovatebot/renovate | NOT_AI | `0144105c1d49` | `6c9c4ac14ef4` |
| w345 | `alias-061f511415b41757ba410e10` | GHSA-3g6g-gq4r-xjm9 | nationalsecurityagency/emissary | NOT_AI | `1bea2e57d612` | `d1d39fc025fc` |
| w346 | `alias-061f945bb5500d9e15321a52` | GHSA-g699-3x6g-wm3g | step-security/harden-runner | NOT_AI | `c793555005be` | `fa2e9d605c4e` |
| w347 | `alias-06b2ef7b16018ac9a7216b91` | GHSA-wc96-39fc-566f | netty/netty | NOT_AI | `6d1b5b0908d3` | `5b68c61f37aa` |
| w348 | `alias-06d6d55842cbfd997f678dea` | GHSA-3g6v-2r68-prfc | traefik/traefik | NOT_AI | `8c7634bcde59` | `8447bfc71e97` |
| w349 | `alias-077abd95bb91831299565a00` | GHSA-hf52-78x8-6w3w | apache/activemq | NOT_AI | `3953b9aaefae` | `b6f9a14e1a6a` |
| w350 | `alias-077cc4b3147cc625c47b1f29` | GHSA-5rvc-5cwx-g5x8 | free5gc/free5gc | EVIDENCE_GAP | `058e9e86db17` | `88de9fa74a1b` |
| w351 | `alias-0784ec5526213f338f2a4d58` | GHSA-qh43-xrjm-4ggp | kimai/kimai | NOT_AI | `d807cdeae944` | `999d820d4ca1` |
| w352 | `alias-0b9a1025278f32f7203f668a` | GHSA-84wq-86v6-x5j6 | phpoffice/phpspreadsheet | NOT_AI | `509f27e5c601` | `9019a9c9da1d` |
| w353 | `alias-0d40a6a1747b260fc33a44d2` | GHSA-rfg2-pjw2-56x2 | python-zeroconf/python-zeroconf | NOT_AI | `c3a39f874a5c` | `0ad3f37b5b85` |
| w354 | `alias-0d52629e388fec1055cdcaca` | GHSA-xhjw-95fp-8vgq | traefik/traefik | NOT_AI | `75e0baf2f4a7` | `df00d82fc7f1` |
| w355 | `alias-0da24584af05eef9b01b84db` | GHSA-2c5c-chwr-9hqw | netty/netty | NOT_AI | `abe017c47b0e` | `541ca7c645b8` |
| w356 | `alias-0db7126fc97d0f3ef9635812` | GHSA-xh5m-36r6-47m3 | phpoffice/phpspreadsheet | NOT_AI | `509f27e5c601` | `85f2556b0bf5` |
| w357 | `alias-0f811df52155c33b9d047be5` | GHSA-fw45-f5q2-2p4x | traefik/traefik | NOT_AI | `77a21f6286ef` | `4595c7a9201a` |
| w358 | `alias-10665a2705bcd9df88bd7057` | GHSA-p5f7-rjhp-pxvc | spring-projects/spring-amqp | NOT_AI | `0a11c54328bf` | `ca163ae82281` |
| w359 | `alias-12854677e89b09dccb101c3e` | GHSA-w573-9ffj-6ff9 | netty/netty | NOT_AI | `3030b4afe30f` | `652663cb50c3` |
| w360 | `alias-13292b77cd124ec887bcc685` | GHSA-mr6m-xj7v-3cv3 | apache/activemq | NOT_AI | `07d4e8c63de6` | `95eeb906d74f` |
| w361 | `alias-1547fada0020eec6cdfeced3` | GHSA-pgcc-vfmc-7cw5 | kimai/kimai | NOT_AI | `8a4e340e77f4` | `31a8f887a5cd` |
| w362 | `alias-15cffb35a4c6e322cc2635d0` | GHSA-9c54-x2g4-v92j | sigstore/timestamp-authority | NOT_AI | `880365399bca` | `506ec57b6ac2` |
| w363 | `alias-1647f2ffd0d8f6ed9f7a4713` | GHSA-7gmj-h9xc-mcxc | nodemailer/mailparser | NOT_AI | `7cba5bcfc259` | `921a67df4cfb` |
| w364 | `alias-1681ed2c64ca89b8f0c075fb` | GHSA-p688-r7jv-fm6f | rust-lang/cargo | NOT_AI | `412b63391472` | `03cb632e2473` |
| w365 | `alias-16b0b8ed4fb637e6bd6548ff` | GHSA-h2qv-fj59-j46j | netty/netty | NOT_AI | `1f0d47dee797` | `bd6214fe1c3b` |
| w366 | `alias-17f10907f108e2dd5a472b52` | GHSA-vxvf-xvm3-p8j5 | openstack/horizon | NOT_AI | `3e2ff4e063fb` | `78d0d05c606c` |
| w367 | `alias-180b6c8d98391dd544e87802` | GHSA-c2gf-v879-257j | netty/netty | NOT_AI | `9d804c54ce96` | `3d45a1e4e8eb` |
| w368 | `alias-181b2142fff0d629f339182d` | GHSA-99qx-5qqr-4j95 | apache/activemq | NOT_AI | `e366917efc28` | `052369f00a43` |
| w369 | `alias-194345c4236b2c394f23d97b` | GHSA-34rh-wp3j-6cxc | pion/stun | NOT_AI | `2d0e6be7ebff` | `fa9f074a33a8` |
| w370 | `alias-196edd21eec6097f3320d4ff` | GHSA-hg6c-8mvr-jqc9 | apache/activemq | NOT_AI | `9ba8d2681f0c` | `1f2a2571524c` |
| w371 | `alias-1a12d6d10032e459926d4fff` | GHSA-rf88-776r-rcq9 | saloonphp/saloon | NOT_AI | `85c55f967bab` | `d418356b6257` |
| w372 | `alias-1c02b5b83fe341620704e62d` | GHSA-mmj4-63m4-r6h5 | codeigniter4/codeigniter4 | NOT_AI | `2bd4f8f5053d` | `b6e9a4fa1dca` |
| w373 | `alias-200ff0d776891de9e55c4307` | GHSA-5x9f-6vg5-qg4m | siderolabs/omni | NOT_AI | `dfcbaae7d0b7` | `ced79da6c032` |
| w374 | `alias-210325cfaf243be1047bae5e` | GHSA-64mm-vxmg-q3vj | chimurai/http-proxy-middleware | NOT_AI | `575f64a1f41d` | `1f15982670ce` |
| w375 | `alias-2223a603c11a5e805e43d608` | GHSA-qjq3-wqj5-g37q | jenkinsci/pipeline-groovy-lib-plugin | NOT_AI | `62281a938287` | `5cc688825312` |
| w376 | `alias-2325d1f709323193b337bc0c` | GHSA-pj97-4p9w-gx3q | zarf-dev/zarf | NOT_AI | `de21ea8975ae` | `abd00afc217e` |
| w377 | `alias-23aa1eff20a6d2ef5b646538` | GHSA-vfx2-hv2g-xj5f | angular/angular-cli | NOT_AI | `4dac5f251061` | `4d564f66f694` |
| w378 | `alias-24131b767a6b39eb756f4700` | GHSA-cmpj-2x3g-m7g3 | free5gc/free5gc | NOT_AI | `84a33e9458e9` | `6e27bc78a469` |
| w379 | `alias-24eccf84e3fa3b413cbc9a86` | GHSA-p2rf-wpxj-mx2g | jenkinsci/credentials-binding-plugin | NOT_AI | `83f3ca6dbf7f` | `3f6decef43ea` |
| w380 | `alias-25ae2f7da15baf48545a92bb` | GHSA-wrwh-rpq4-87hf | free5gc/free5gc | NOT_AI | `fc6e50f8530f` | `86686276a7e2` |
| w381 | `alias-25d5e168479a99535e1c80af` | w381 | mattiasw/exifreader | NOT_AI | `51ea66e9bfe7` | `00878ca9df0e` |
| w382 | `alias-25dce8bb662a0a5a40419e11` | GHSA-g4w6-vmgf-xqvx | cedar-policy/authorization-for-expressjs | NOT_AI | `a8cd22f862f6` | `3d23c4a23d55` |
| w383 | `alias-27e768038167f92853d79d92` | w383 | anephenix/hub | NOT_AI | `f5d03cac30ba` | `67260d2a1407` |
| w384 | `alias-2903320f52c25b2573632839` | GHSA-rxrq-fv76-26pr | free5gc/free5gc | NOT_AI | `a39681cbb8e9` | `f110517b1189` |
| w385 | `alias-29efd4ddf3f9c9aad7a4ced9` | GHSA-44hj-4m45-frj3 | fluent/fluentd | NOT_AI | `1f53273438db` | `45c87a81f3ac` |
| w386 | `alias-2b597281aa9ba1487032f722` | GHSA-499r-g7pc-vmp9 | composer/composer | NOT_AI | `e03983697a9e` | `502c6c4f6998` |
| w387 | `alias-2e82e9a39a9711b1e16ae7fd` | GHSA-px92-q6rc-6mwv | spring-projects/spring-graphql | NOT_AI | `577014f4f123` | `e01cd34dd7b2` |
| w388 | `alias-2ef0212b1ce6c0378e230880` | w388 | sveltejs/devalue | NOT_AI | `819f1ac7475a` | `40f1db13afdd` |
| w389 | `alias-2f0f2aa54871ecdd82bccae5` | GHSA-wg36-wvj6-r67p | composer/composer | NOT_AI | `36dd7dfea5b7` | `4f02616e6fba` |
| w390 | `alias-30842547202bb7b00688a14b` | GHSA-jv4p-mhmp-69vw | 3em0/cve_repo | NOT_AI | `4507c7078486` | `—` |
| w391 | `alias-313df99aad9c3dbf3f72d299` | GHSA-hcm4-6hpj-vghm | zarf-dev/zarf | NOT_AI | `92b743d02930` | `93f9c33a9d47` |
| w392 | `alias-32e785e30659db177e40706e` | GHSA-3p28-73q7-45xp | free5gc/free5gc | NOT_AI | `3ae828b1315f` | `c38a82fd0170` |
| w393 | `alias-32e930b5ec70ab3155cf4fb5` | GHSA-jv9x-w4gm-hwcm | kimai/kimai | NOT_AI | `82cd0c5ed2d2` | `cbdf91f316ba` |
| w394 | `alias-34709288e949e49d4b83921d` | GHSA-j9cw-hwqf-85w7 | fluent/fluentd | NOT_AI | `335d3b2b709a` | `f5f2b7cddf8a` |
| w395 | `alias-34948015081a21a97e196a75` | GHSA-pfrv-63w8-q7rq | byaidu/pdfmathtranslate | NOT_AI | `500bcca42f40` | `—` |
| w396 | `alias-35690d5deb754cef2ec0427a` | GHSA-3j3q-wp9x-585p | kcp-dev/kcp | NOT_AI | `44b4682b63e6` | `416922b09843` |
| w397 | `alias-3598903927f77b31ad026eed` | GHSA-v33r-r6h2-8wr7 | kimai/kimai | NOT_AI | `0714fc6ac657` | `a0601c8cb28f` |
| w398 | `alias-36cf156a616c2d7c972ba960` | GHSA-rhr9-hgcm-x289 | gravitl/netmaker | NOT_AI | `57f19cdc8f6a` | `db2f005ea034` |
| w399 | `alias-36e5cce518d278333ee982f4` | GHSA-3xc2-h5r3-wv3r | kimai/kimai | NOT_AI | `9a85b737b35f` | `16703081cdbd` |
| w400 | `alias-37396502750453cfc6b53ee7` | GHSA-6g43-577r-wf4x | free5gc/chf | NOT_AI | `50083ee6a9fb` | `55af766f321a` |
| w401 | `alias-3b9e155f64be80aaf4614670` | GHSA-9663-mqmp-p9mm | python-zeroconf/python-zeroconf | NOT_AI | `3b8d906177bc` | `b22c8ff19c66` |
| w402 | `alias-3bd1bfd8f3f862b713c3d7fd` | GHSA-ch3w-9456-38v3 | gravitl/netmaker | NOT_AI | `78da9fa9010b` | `0d938931c0fd` |
| w403 | `alias-3c87b58ed4aaea9816a9d95f` | GHSA-wmvv-fhm6-w34x | 3em0/cve_repo | NOT_AI | `6699379d6673` | `—` |
| w404 | `alias-3e405801c9c8f6d53b958920` | GHSA-6wrm-x65g-hr4p | openstack/horizon | NOT_AI | `a68d35e52f44` | `c7863093c67a` |
| w405 | `alias-4019fd990f77003e051f7f3f` | GHSA-gcvm-c75m-h4p4 | apache/openmeetings | NOT_AI | `—` | `e758715c801d` |
| w406 | `alias-44470e3609dbc575f10925ae` | GHSA-qpv2-rwc8-c993 | gravitl/netmaker | NOT_AI | `0bacbd9f6c0b` | `5309aa70d464` |
| w407 | `alias-452f15479141a045e87f98c1` | GHSA-c83f-3xp6-hfcp | saloonphp/saloon | NOT_AI | `bef86d8bdec2` | `1307b1d72cac` |
| w408 | `alias-462d565c5e49c27af6e7fea7` | GHSA-x9c7-5h6g-hq8q | spring-cloud/spring-cloud-function | NOT_AI | `4d9cdb9750ce` | `6bcd55803c5a` |
| w409 | `alias-46f366c60c35ab53ade3713a` | GHSA-72f5-rr8c-r6gr | fluent/fluentd | NOT_AI | `832c0c22427b` | `c6a01ea2e0ea` |
| w410 | `alias-49eec800e0cf6a69422f404d` | GHSA-gg9x-qcx2-xmrh | authlib/joserfc | NOT_AI | `29c5a59f4a1b` | `86d00910b2b2` |
| w411 | `alias-4e8f21ae446bbfd766cfcc2c` | GHSA-m4h2-mjfm-mp55 | mercurius-js/mercurius | NOT_AI | `aa4bc978e8d1` | `5b56f60f4b0d` |
| w412 | `alias-4fcbc61bb0c50fc602bdc6e5` | GHSA-f6ww-3ggp-fr8h | xmldom/xmldom | NOT_AI | `64cd7b6e5ef8` | `372008f9ae0e` |
| w413 | `alias-5130c7e029f64ad71c1c7504` | GHSA-253q-9q78-63x4 | jmlepisto/clatter | NOT_AI | `6453c23382cb` | `b65ae6e9b801` |
| w414 | `alias-516513eed680733543944c00` | GHSA-phxq-526m-79px | spring-projects/spring-graphql | NOT_AI | `a1165051eb53` | `63a89ed1379b` |
| w415 | `alias-53086d69ef6d1b9c6f30bf6e` | GHSA-h9q6-hc68-35rp | shamaton/msgpack | NOT_AI | `8c8c814cd610` | `269f54e9483a` |
| w416 | `alias-56fd2b54c66f104a9bad64b8` | GHSA-rr89-w3h9-m66j | mattiasw/exifreader | NOT_AI | `88e93582f71a` | `5f116128adc1` |
| w417 | `alias-5a15473e9aae8d5f94242b5b` | GHSA-5rmx-256w-8mj9 | h44z/wg-portal | NOT_AI | `94f0b26304e0` | `fe4485037a25` |
| w418 | `alias-5d19fad05e02b87183c6bf07` | GHSA-x288-3778-4hhx | angular/angular-cli | NOT_AI | `3c9697a8c34a` | `6cf621c905de` |
| w419 | `alias-5d999522924c1b5dd36c7ad5` | GHSA-53h4-8rc4-f539 | slimphp/slim | NOT_AI | `4f84a8cee4eb` | `e12cb05ca2a1` |
| w420 | `alias-5ec06c86235aa6e00d461fb8` | GHSA-f7xc-5852-fj99 | saloonphp/saloon | NOT_AI | `4fbbd5f5f6ff` | `d418356b6257` |
| w421 | `alias-5f52522c6f016b598fd4dd0b` | GHSA-hrmw-qprp-wgmc | phpoffice/phpspreadsheet | NOT_AI | `edc003ad1645` | `f1eb4e6980d5` |
| w422 | `alias-5fd878b2fa29730f576105a5` | GHSA-5846-7qm3-r52j | hackingrepo/dssrf-js | NOT_AI | `6885ccae01fb` | `668c21792cd1` |
| w423 | `alias-6201a37efcc390bc5e77cd78` | GHSA-77vg-94rm-hx3p | sveltejs/devalue | NOT_AI | `819f1ac7475a` | `206ca6712fbc` |
| w424 | `alias-654f8af5e27af03626a25f8d` | GHSA-4g5x-hcwm-82jw | zhenorzz/goploy | NOT_AI | `16f6e848b8cb` | `d51aa15ebc0a` |
| w425 | `alias-661ba9c25d5b81cb58258a1b` | GHSA-x8qp-wqqm-57ph | intlify/vue-i18n | NOT_AI | `69489802dea2` | `49f982443ab8` |
| w426 | `alias-683b0a2c791c7e09e4a85ba6` | GHSA-qc2x-6f54-m6h9 | python-zeroconf/python-zeroconf | NOT_AI | `e814dd1e6848` | `544449596e64` |
| w427 | `alias-696849a1ba7b0ba3ba2fb199` | GHSA-j759-j44w-7fr8 | xmldom/xmldom | NOT_AI | `5fb8fb92b2cb` | `fda7cc313de3` |
| w428 | `alias-69a56edd2872b02919a7aa96` | GHSA-4rm2-28vj-fj39 | dedoc/scramble | NOT_AI | `f8cc090269b4` | `b54b0c43bdeb` |
| w429 | `alias-6e57d2e25dc479260d4bbd85` | GHSA-2v35-w6hq-6mfw | xmldom/xmldom | NOT_AI | `5fb8fb92b2cb` | `4845ef109221` |
| w430 | `alias-6f028c4d4eb820cd4bc422bf` | GHSA-m39w-hqxx-3r48 | spring-projects/spring-graphql | NOT_AI | `b10d5f7df7f2` | `169bfc94c160` |
| w431 | `alias-71ed34a89b276f47ba2df810` | GHSA-gqw4-4w2p-838q | composer/composer | NOT_AI | `dd1fd0e306db` | `4fcc13d428f2` |
| w432 | `alias-721ca2e5bf5c6f8c896e54a7` | GHSA-2gr4-ppc7-7mhx | codeigniter4/codeigniter4 | NOT_AI | `2bd4f8f5053d` | `29299349e7d2` |
| w433 | `alias-764e1cb0cc9cbb2a37321577` | GHSA-c66c-vq6w-fvh5 | siderolabs/omni | NOT_AI | `7486bb8d20d4` | `13c3f2897898` |
| w434 | `alias-76a1f9bfe1bf09fc91f70eaa` | GHSA-hmqr-wjmj-376c | gravitl/netmaker | NOT_AI | `34cac9ced04f` | `0c4d431df2b5` |
| w435 | `alias-76b6bdf9567124529666db74` | GHSA-w5r5-m38g-f9f9 | authlib/joserfc | NOT_AI | `86d25febaca0` | `696a9611ab98` |
| w436 | `alias-77cf5118e417cfdb350fea15` | GHSA-4hgg-c4rr-6h7f | gravitl/netmaker | NOT_AI | `cb940ac68466` | `5617d97ce616` |
| w437 | `alias-79b8158cf102410bb7a1c941` | GHSA-65mp-fq8v-56jr | jugmac00/flask-reuploaded | NOT_AI | `45b77b494769` | `d64c6b2f71cb` |
| w438 | `alias-7b2a06cfdc0ea75844a0a7a4` | GHSA-hhmc-q9hp-r662 | codeigniter4/codeigniter4 | NOT_AI | `eb5bc0669202` | `20ebcf4694d9` |
| w439 | `alias-7e21407cc08de7646d210ce7` | GHSA-87m4-826x-3crx | phpoffice/phpspreadsheet | NOT_AI | `93c94eb31d59` | `1433b34843af` |
| w440 | `alias-8350e4ca675bf95a0ab51c1e` | GHSA-5mq8-78gm-pjmq | kepano/defuddle | FALSE_POSITIVE | `7b9c01b8dc97` | `7cd4a27447b4` |
| w441 | `alias-8390ae3f5e804bd13d8971db` | GHSA-rrjr-v56m-ww88 | g-research/parquetsharp | NOT_AI | `c4564c2eaf2a` | `d87081931cde` |
| w442 | `alias-86f9902c6c6a756100d51582` | GHSA-26rh-24rg-j3vv | zhenorzz/goploy | NOT_AI | `fdd819900c59` | `b49eabe903c7` |
| w443 | `alias-87309aca08e97e031f07444b` | GHSA-c9w5-rwh3-7pm9 | codeigniter4/codeigniter4 | NOT_AI | `ec2dc8b43e78` | `f5e463b9a3e9` |
| w444 | `alias-887158b2240e3e92704a6c59` | GHSA-fxxf-w25w-mcx2 | jenkinsci/credentials-binding-plugin | NOT_AI | `3f6decef43ea` | `e52b2328afde` |
| w445 | `alias-8d6078ff40410b86338dad03` | GHSA-86vw-mfpg-wwv9 | jsonata-js/jsonata | NOT_AI | `06f323d7c7a7` | `d6ffc17cb16a` |
| w446 | `alias-8ff3e3491ba1099c624cc12e` | GHSA-999r-qq7v-r334 | aws/aws-cdk | NOT_AI | `6a16cf26e727` | `a92105c64c4f` |
| w447 | `alias-906b1ddfad74662995a82a58` | GHSA-vcrf-j523-4mrf | aws/aws-cdk | NOT_AI | `1a25fc6d9971` | `baa9e1dff469` |
| w448 | `alias-99269a04002d2569a57a9292` | GHSA-jp3q-wwp3-pwv9 | solspace/craft-freeform | NOT_AI | `7dd80f030aa6` | `b9adad6cdf1e` |
| w449 | `alias-9a5b372063a8402451409def` | GHSA-p8qj-fj6r-w7q9 | spring-projects/spring-amqp | NOT_AI | `3b605cddbfd5` | `0373cde52a99` |
| w450 | `alias-9d5a14a2fb4939a00ef8f4fc` | GHSA-cphf-4846-3xx9 | eclipse-vertx/vert.x | NOT_AI | `d5f646b10137` | `d007e7b41854` |
| w451 | `alias-a106b4c6af8b3fafb3e3f5e9` | GHSA-vw5p-8cq8-m7mv | sveltejs/devalue | NOT_AI | `24f4466144ce` | `e46afa64dd2b` |
| w452 | `alias-a23290c2b2cbee12e9caeb01` | GHSA-9j26-99jh-v26q | wwbn/avideo-encoder | NOT_AI | `036052b948a6` | `78178d11541d` |
| w453 | `alias-a3061e770b4acff99bbc9620` | GHSA-cpmj-h4f6-r6pq | step-security/harden-runner | NOT_AI | `c793555005be` | `5ef0c079ce82` |
| w454 | `alias-a479695e53e43897a6f054ac` | GHSA-78cg-fc6c-w44w | apache/openmeetings | EVIDENCE_GAP | `—` | `7944f872a5e9` |
| w455 | `alias-a4adef64bffbfff031ff7150` | GHSA-3p24-9x7v-7789 | nationalsecurityagency/emissary | NOT_AI | `c702bb7d6975` | `1faf33f2494c` |
| w456 | `alias-a4c9ba4141b5698fc43b8bcc` | GHSA-6hq5-7373-42rg | phpoffice/phpspreadsheet | NOT_AI | `84747121a190` | `7ef7b25e8548` |
| w457 | `alias-aa781692286415d4b9811365` | GHSA-gjfg-22fp-rrxx | composer/composer | NOT_AI | `aa94918d509c` | `502c6c4f6998` |
| w458 | `alias-ae00e4e7e6f79b5307f208bd` | GHSA-hx53-77qj-8663 | hashicorp/nomad | NOT_AI | `566dfb2f399d` | `cd7240c4099a` |
| w459 | `alias-b1eb0e4cc547b8a4c33d7ca4` | GHSA-jq42-7mfv-hm57 | rust-lang/cargo | NOT_AI | `9fba127e4fea` | `312d5575ac92` |
| w460 | `alias-b2d082989eb9b35cff8a16a8` | GHSA-69xr-m8h6-h664 | angular/angular-cli | NOT_AI | `f086eccc36d1` | `5adc92541433` |
| w461 | `alias-b31939ea3cee4255a8a39e16` | GHSA-428g-f7cq-pgp5 | marshmallow-code/marshmallow | NOT_AI | `8a6ad548df6b` | `d24a0c9df061` |
| w462 | `alias-b357e7947151ec34d5a566ec` | GHSA-f9f8-rm49-7jv2 | composer/composer | NOT_AI | `0b94fd209aee` | `3f5e7f9fbfa5` |
| w463 | `alias-b414e635ca1236122779eb57` | GHSA-x6wf-f3px-wcqx | xmldom/xmldom | NOT_AI | `5fb8fb92b2cb` | `7207a4b0e0bc` |
| w464 | `alias-b6d507cdcd65a2b033fcb04a` | GHSA-gcq2-9pq2-cxqm | chimurai/http-proxy-middleware | NOT_AI | `a12a59df4250` | `a1ac3158541d` |
| w465 | `alias-b9036092203163b6beed15b6` | GHSA-29rf-f4vv-pvq6 | authorizerdev/authorizer | NOT_AI | `4e48320cf19e` | `2a9d22f3ab45` |
| w466 | `alias-b9c9ee85a11154b51e58be76` | GHSA-xm5m-wgh2-rrg3 | sigstore/timestamp-authority | NOT_AI | `b7c9c9f82ee8` | `9583b6186084` |
| w467 | `alias-c0bba41923717755adb233b5` | GHSA-x746-7m8f-x49c | kludex/starlette | NOT_AI | `dd11c69b5b11` | `e3f972225adb` |
| w468 | `alias-c34d7ded879e9355f989173d` | GHSA-xh43-g2fq-wjrj | angular/angular-cli | NOT_AI | `8db316149ed6` | `f086eccc36d1` |
| w469 | `alias-c6077d002a33ddb2bda06b75` | GHSA-8p33-q827-ghj5 | hackingrepo/dssrf-js | NOT_AI | `6885ccae01fb` | `3b1236e9f5ab` |
| w470 | `alias-c7fc1af06fb91d8488eb1750` | GHSA-hxf2-gm22-7vcm | nationalsecurityagency/emissary | NOT_AI | `91a632b5fc86` | `33d260d2cfbc` |
| w471 | `alias-c80c47cfc3e8d2e3a731011e` | GHSA-m39p-34qh-rh3w | keichi/binary-parser | NOT_AI | `93759332a744` | `7811fab5d061` |
| w472 | `alias-c8a68256c3907ccf3fe3b733` | GHSA-wqxq-w68r-wg85 | apache/openmeetings | NOT_AI | `ff7f413bba28` | `c407437744ec` |
| w473 | `alias-c917fe8f2f6bde8cc20ff533` | GHSA-937x-gpqr-72gg | jugmac00/flask-reuploaded | NOT_AI | `d64c6b2f71cb` | `5ded76092429` |
| w474 | `alias-c94f43a01ee83c9cd57f67bc` | GHSA-c3gj-q88f-7hqj | studio-42/elfinder | NOT_AI | `357fc6f64505` | `d03a9c7ad84c` |
| w475 | `alias-cbc0b29ff84b0551b441f93f` | GHSA-g2pg-6438-jwpf | sveltejs/devalue | NOT_AI | `bbf86c2df544` | `11755849fa06` |
| w476 | `alias-d2944118fa50c384b0683973` | GHSA-cpm7-cfpx-3hvp | nationalsecurityagency/emissary | NOT_AI | `a43333496010` | `e2078417464b` |
| w477 | `alias-d5ecdc77a5c3b71016055ad4` | GHSA-6xvm-j4wr-6v98 | quinn-rs/quinn | NOT_AI | `0837b5b51ea1` | `c8eefa07e087` |
| w478 | `alias-d7d398aa233342f0464b2144` | GHSA-pr7j-96cj-549h | fluent/fluentd | NOT_AI | `fe73c272eed3` | `990921518971` |
| w479 | `alias-d85e65477aebdcdf95288e74` | GHSA-phvx-9mgw-67r5 | python-zeroconf/python-zeroconf | NOT_AI | `061a2aa3c6e8` | `95561e28b249` |
| w480 | `alias-ddec734b1bb1dfab2ff3968f` | GHSA-3g76-f9xq-8vp6 | eclipse-vertx/vert.x | NOT_AI | `58238be403a9` | `c64a707b6de8` |
| w481 | `alias-de19269741ef7437dd9ec8ed` | GHSA-rpc5-pm7q-hjmp | naver/billboard.js | NOT_AI | `1ae188f09b86` | `49e079cdd466` |
| w482 | `alias-e22205d9a7fc391fa1a1fa10` | GHSA-q23m-vm9r-5745 | stefanprodan/podinfo | NOT_AI | `153f4dce4547` | `cbebb20fd485` |
| w483 | `alias-e65ab0afd50c091aa8290563` | GHSA-v74m-68w4-83qm | seopanel/seo-panel | NOT_AI | `b8092087fd04` | `440a00b68741` |
| w484 | `alias-e7045e68192add7278e098de` | GHSA-wh4c-j3r5-mjhp | xmldom/xmldom | NOT_AI | `5fb8fb92b2cb` | `2b852e836ab8` |
| w485 | `alias-e76fe79d8bbaf8eee43a4eaf` | GHSA-cg4g-m8jx-vjv2 | hackingrepo/dssrf-js | NOT_AI | `6885ccae01fb` | `9211f91bf532` |
| w486 | `alias-e96c7ae2a46a8034301278fd` | GHSA-82w8-qh3p-5jfq | kludex/starlette | NOT_AI | `65a0abd755b4` | `dba1c4babc4f` |
| w487 | `alias-e975ab13155cb0d091885e97` | GHSA-h64w-w9pr-82m4 | mattiasw/exifreader | NOT_AI | `f31553373ee1` | `c9d88b67e127` |
| w488 | `alias-ec9be0f27c0fb8db4666bc3f` | GHSA-3934-423W-4JQ3 | hashicorp/nomad | NOT_AI | `dd220bfb36a0` | `2a09fd62c238` |
| w489 | `alias-edd8a49ba5a19d4f4e8471a6` | GHSA-wv8c-6mx2-xf4j | siderolabs/omni | NOT_AI | `f8de9a6d9645` | `25fa9e141ee0` |
| w490 | `alias-f3e12c76b5adc30e16d2715b` | GHSA-gqgw-jghv-mxwx | jazzband/tablib | NOT_AI | `22c4d185e122` | `b0ff39fb9b2f` |
| w491 | `alias-f7db1cc48653609acdaf6492` | GHSA-8q4h-8crm-5cvc | studio-42/elfinder | NOT_AI | `7a44e40df641` | `5e463d138497` |
| w492 | `alias-fe018c127a88d4f1324fb7f4` | GHSA-x229-w2j4-h748 | 3em0/cve_repo | NOT_AI | `4507c7078486` | `—` |
| w493 | `alias-ff8ff56caa4b32b54e6a346a` | GHSA-wphv-vfrh-23q5 | authlib/joserfc | NOT_AI | `05ccff5d3c78` | `4d4ea2e787ed` |
| w494 | `alias-ffe85254265cfb2e7ab831c4` | GHSA-7wmf-pw8j-mc78 | codeigniter4/codeigniter4 | NOT_AI | `d0c35d680a38` | `ecbf044666be` |
| w495 | `alias-02eaef7d14238358fc68d45b` | GHSA-xv9c-v5pw-jxvf | misp/misp-modules | NOT_AI | `52cda9caa003` | `3bae4108a3ba` |
| w496 | `alias-189431d12ccb0895410f151d` | GHSA-7jmx-9c9v-p8w8 | peergos/peergos | NOT_AI | `a0714b5a5174` | `8a90a180b466` |
| w497 | `alias-3d4b43326a4da331198820e6` | GHSA-pwc8-43hr-jg4j | absmach/magistrala | NOT_AI | `bb39e842de28` | `2726a2978492` |
| w498 | `alias-6c4e7f2b0f7f275b96c3a230` | GHSA-4887-2gc3-6j9r | cisagov/malcolm | NOT_AI | `eb4e64da6da1` | `82b5fc5271fe` |
| w499 | `alias-6e1af5a5e935507ed1982c45` | GHSA-8xqr-cc5h-9wvp | friendica/friendica | NOT_AI | `f8f3689a0d7f` | `—` |
