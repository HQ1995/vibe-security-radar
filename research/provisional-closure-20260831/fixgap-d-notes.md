# Direct-fix closure: GHSA-WV46-V6XC-2QHF and GHSA-46Q5-G3J9-WX5C

Scope: recover the already-identified direct fixes and publish the smallest production hunks that explain how each fix closes its vulnerable path. No ledger mutation, export, publication, or commit was performed here.

## GHSA-WV46-V6XC-2QHF

- Canonical row: `alias-06ca275f5a582dacb68ec70b`, expected revision 2.
- Repository/object: `.ai-slop/state/repos/openclaw_openclaw`; candidate `9a3800d8e6e69bc0a125dca5760d47515e746454`; direct fix `7ade3553b74ee3f461c4acd216653d5ba411f455`; fix parent `55ad5d7bd769da9e1138ff5f36226e0a30ce8d24`.
- Primary sources: [first-party advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-wv46-v6xc-2qhf), [candidate commit](https://github.com/openclaw/openclaw/commit/9a3800d8e6e69bc0a125dca5760d47515e746454), [direct fix](https://github.com/openclaw/openclaw/commit/7ade3553b74ee3f461c4acd216653d5ba411f455).
- Closure: the candidate resolves the outbound recipient from mutable nickname/username data. The fix defaults `dangerouslyAllowNameMatching` to false and returns the webhook's stable `payload.user_id` before the lookup unless an operator explicitly opts into the dangerous compatibility behavior.
- Exact selected-file hashes: candidate patch `8ca5d13c7d7b19b3e1286b26dab9e247b994500d4dfb1ae25dfdd79fccae32ae`; fix patch `1aee95f59e7836d23fa1e330385cf7298777f6e99c2c1cc916f9ee484ba8d895`.

## GHSA-46Q5-G3J9-WX5C

- Canonical row: `alias-48acec3eadce8bee986a75d3`, expected revision 2.
- Repository/object: `.ai-slop/state/repos/qhkm_zeptoclaw`; candidate `2c9deefbf744089c3041885717b92c6f2fc0bf8c`; direct fix `bf004a20d3687a0c1a9e052ec79536e30d6de134`; fix parent `ec2743309478a52339d627a21849637a5836bb3f`.
- Primary sources: [first-party advisory](https://github.com/qhkm/zeptoclaw/security/advisories/GHSA-46q5-g3j9-wx5c), [candidate commit](https://github.com/qhkm/zeptoclaw/commit/2c9deefbf744089c3041885717b92c6f2fc0bf8c), [direct fix](https://github.com/qhkm/zeptoclaw/commit/bf004a20d3687a0c1a9e052ec79536e30d6de134).
- Closure: the candidate uses client JSON `sender` for the allowlist and client JSON `chat_id` for routing while `auth_token` defaults to `None`. The fix makes both identities server-controlled by default, propagates them into the live channel, resolves authorization/routing from those values, and refuses startup without `sender_id` unless legacy payload trust is explicitly enabled.
- The fix commit covers four advisories; only `src/config/types.rs`, `src/channels/factory.rs`, and `src/channels/webhook.rs` identity hunks belong to this case. HMAC support is adjacent defense-in-depth; filesystem, WhatsApp, Telegram, and email changes are excluded.
- Exact selected-file hashes: candidate patch `7cc16ed6a0430108a27c0d24eea9707a5cdcf6129a9219f22f04e378c9704b12`; fix patch `25ec9a5760de1e1629c8a346021e5fa9f66afcafa6442eb1b01bce5a1d4fb28d`.

## Replay

```sh
git -C .ai-slop/state/repos/openclaw_openclaw cat-file -t 7ade3553b74ee3f461c4acd216653d5ba411f455
git -C .ai-slop/state/repos/openclaw_openclaw show --format= --patch 7ade3553b74ee3f461c4acd216653d5ba411f455 -- extensions/synology-chat/src/accounts.ts extensions/synology-chat/src/webhook-handler.ts
git -C .ai-slop/state/repos/qhkm_zeptoclaw cat-file -t bf004a20d3687a0c1a9e052ec79536e30d6de134
git -C .ai-slop/state/repos/qhkm_zeptoclaw show --format= --patch bf004a20d3687a0c1a9e052ec79536e30d6de134 -- src/config/types.rs src/channels/factory.rs src/channels/webhook.rs
```

