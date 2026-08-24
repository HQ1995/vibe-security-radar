# Next-pool map versus canonical85

## Verdict first

Inventory only. This packet does not claim PASS and does not claim a case count.
Authoritative counted HOLD snapshot is canonical85 (85 first-party GHSA identities).
Source conservation remains 211 fp211 hypotheses and 212 source GHSA cases.
Publication, integration, and causal admission stay closed.

PASS/KEEP identities seen in herdr-260814-* and orchestrator-260814-* worker packets: 20.
Already among the 85 counted IDs: 12.
A independent KEEP not integrated: 0.
B worker proposal needing hostile review: 1.
C NARROW/UNKNOWN: 3.
D REJECT/duplicate: 4.
ID conservation (pool = already_counted + A + B + C + D): True.

## Method

Labels are not inherited. Each recorded verdict is copied from its source path and sha256.
Dedupe is exact first-party GHSA identity or matching mechanism_key / mechanism_fingerprint.
Shared SHA alone is not duplication.
Canonical HOLD snapshots are the counted set, not proposal sources.
snapshot/work/pages/clone trees were not scanned.

## A independent KEEP not integrated

Empty.

## B worker proposal needing hostile review

- GHSA-FRVJ-C5QP-XJ4W repo=open-webui/open-webui cand=03547759179672d216d2e1376dd1ae4fdad76a94 fix=05098d25a58d03738e01c4e85e8852c3b4ad849c release=PASS hostile_review=absent src=autoresearch/herdr-260814-fresh-strict-grok46-xhigh/cases.jsonl sha256=6a13b08e9b569dfab705385985d5ea49f561c26e8ac28831e620c3e4dce1a742

## C NARROW/UNKNOWN

- GHSA-33RQ-M5X2-FVGF reason=NARROW repo=openclaw/openclaw src=autoresearch/herdr-260814-ghsa200-batch5-two-redteam-grok46-xhigh/cases.jsonl sha256=ef902eb150d5cf4f5c8c7090e4b2911d9208d7e8fa070b96bd8f5f00c25d5e21
- GHSA-6R28-9PPF-4HJ5 reason=NARROW repo=gopacket/gopacket src=autoresearch/herdr-260814-ghsa200-batch9-three-redteam-grok46-xhigh/cases.jsonl sha256=15de6f28690ba33dbba72df7a32212cc2fbd4873cdb6ec6a3ca28f72c7a1cf14
- GHSA-F229-3862-4942 reason=NARROW repo=agentfront/enclave src=autoresearch/herdr-260814-ghsa200-batch5-two-redteam-grok46-xhigh/cases.jsonl sha256=ef902eb150d5cf4f5c8c7090e4b2911d9208d7e8fa070b96bd8f5f00c25d5e21

## D REJECT/duplicate

- GHSA-2MHJ-FHVG-V428 reason=NEGATIVE_CONTROL_REJECT dup_target=None src=autoresearch/herdr-260814-ghsa200-pimcore-2mhj-recovery-redteam-grok46-xhigh/cases.jsonl sha256=f24104862ae27d35e6efda8f6940641aebf3a0d538a46eaba8248d8e49f41fc0
- GHSA-CHFM-XGC4-47RJ reason=REJECT dup_target=None src=autoresearch/herdr-260814-ghsa200-chfm-jxx9-hostile-redteam-grok46-high/cases.jsonl sha256=6760e03bfd63fff4cd9373b15574d8297d6e1245a8c40f90f9d1184a0bd0e6aa
- GHSA-HHJV-JQ77-CMVX reason=NEGATIVE_CONTROL_REJECT dup_target=None src=autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/cases.jsonl sha256=f1aa5870c6acbc0128d1c6971a95a0f3a4e609fc5bea6cbc4541fd870a2a35b0
- GHSA-JXX9-PX88-PJ69 reason=REJECT dup_target=None src=autoresearch/herdr-260814-ghsa200-chfm-jxx9-hostile-redteam-grok46-high/cases.jsonl sha256=6760e03bfd63fff4cd9373b15574d8297d6e1245a8c40f90f9d1184a0bd0e6aa

## Excluded already counted

12 PASS/KEEP identities are already canonical85 counted IDs and are listed in excluded.jsonl.

## Stop

Inventory complete. No ledger, site, or code edits. No clone or advisory fetch.
