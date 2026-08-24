# Adjudication report — unr-adj3-slice-8 (25 rows)

Verdict: **0 countable**. 25 REJECT. Every candidate AI commit is in a code area disjoint from the mechanism named by its advisory; none authors the vulnerable hunk.

Method: read each first-party advisory JSON from the local advisory-database clone (all 25 present), fetched/verified each candidate AI commit diff in the sweep pool via git smart-HTTP (--filter=blob:none, no GitHub API, no blame/SZZ), then compared changed files (git diff-tree) and message against the advisory mechanism. Closest calls (systemd nspawn config-escape, OpenPLC hardware-layer RCE, LightLLM shared-memory, Vibe-Trading enforcement/memory) were diff-checked and remain disjoint.

Cross-cutting: all 25 advisories are unreviewed (github_reviewed:false) with empty affected[]; unlike the adj2 slice there are no cross-repo mappings here (identity_gate PASS on every row).

### GHSA-7P49-G593-X646 — halo-dev/halo → REJECT

- aliases: CVE-2025-70886; CWE CWE-400
- mechanism: An issue in halo v.2.22.4 and before allows a remote attacker to cause a denial of service via a crafted payload to the public comment submission endpoint
- candidates: c6aa79eda250, 14659b9e89af, b1745b94f8b1, 0a7099eb0ca7, 76759377465a, 3b2738cbd346, ac449924e2ba
- candidate files: application/src/main/java/run/halo/app/security/DefaultSuperAdminInitializer.java; dashboard upvotes widget; FormKit color components; tag creation color; avatar attachment settings
- AI marker: co_author_trailer + author_identity_pair (Copilot/Claude)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (halo public comment submission endpoint DoS (CWE-400)): application/src/main/java/run/halo/app/security/DefaultSuperAdminInitializer.java; dashboard upvotes widget; FormKit color components; tag creation color; avatar attachment settings

### GHSA-396H-M3PM-FPM5 — systemd/systemd → REJECT

- aliases: CVE-2026-40225; CWE CWE-669
- mechanism: In udev in systemd before 260, local root execution can occur via malicious hardware devices and unsanitized kernel output.
- candidates: 7d5ec30862b3, e799263ff416, af5126568af6, 9ed12a81b251, f753f898ed06
- candidate files: src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq
- AI marker: co_author_trailer / explicit_attribution_line (Claude Opus 4.6)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (systemd udev local root via unsanitized kernel output (CWE-669)): src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq

### GHSA-52RM-R39V-FWV9 — systemd/systemd → REJECT

- aliases: CVE-2026-40223; CWE CWE-696
- mechanism: In systemd 258 before 260, a local unprivileged user can trigger an assert when a Delegate=yes and User=<unset> unit exists and is running.
- candidates: 7d5ec30862b3, e799263ff416, af5126568af6, 9ed12a81b251, f753f898ed06
- candidate files: src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq
- AI marker: co_author_trailer / explicit_attribution_line (Claude Opus 4.6)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (systemd assert on Delegate=yes + User=<unset> unit (CWE-696)): src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq

### GHSA-HC7R-6254-88W5 — systemd/systemd → REJECT

- aliases: CVE-2026-40226; CWE CWE-348
- mechanism: In nspawn in systemd 233 through 259 before 260, an escape-to-host action can occur via a crafted optional config file.
- candidates: 7d5ec30862b3, e799263ff416, af5126568af6, 9ed12a81b251, f753f898ed06
- candidate files: src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq
- AI marker: co_author_trailer / explicit_attribution_line (Claude Opus 4.6)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (systemd nspawn escape-to-host via crafted optional config file (CWE-348)): src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq

### GHSA-JF3X-2PF6-C45W — systemd/systemd → REJECT

- aliases: CVE-2026-40224; CWE CWE-863
- mechanism: In systemd 259 before 260, there is local privilege escalation in systemd-machined because varlink can be used to reach the root namespace.
- candidates: 7d5ec30862b3, e799263ff416, af5126568af6, 9ed12a81b251, f753f898ed06
- candidate files: src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq
- AI marker: co_author_trailer / explicit_attribution_line (Claude Opus 4.6)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (systemd-machined varlink root-namespace privilege escalation (CWE-863)): src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq

### GHSA-X53V-PXF5-CHX6 — systemd/systemd → REJECT

- aliases: CVE-2026-40227; CWE CWE-1025
- mechanism: In systemd 260 before 261, a local unprivileged user can trigger an assert via an IPC API call with an array or map that has a null element.
- candidates: 7d5ec30862b3, e799263ff416, af5126568af6, 9ed12a81b251, f753f898ed06
- candidate files: src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq
- AI marker: co_author_trailer / explicit_attribution_line (Claude Opus 4.6)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (systemd IPC API null-element assert (CWE-1025)): src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq

### GHSA-G77C-P776-CWHW — Intina47/context-sync → REJECT

- aliases: CVE-2026-7062; CWE CWE-77
- mechanism: A security vulnerability has been detected in Intina47 context-sync up to 2.0.0. This affects an unknown part of the file src/git-integration.ts of the component Git Integration. Such manipulation leads to os command injection. The attack can be executed remotely. The exploit has been disclosed publicly and may be used.
- candidates: f88c80690267, a7cb34435c9d, 91f0f2c0f75d, f5bc0d9d765d, 2ce8f90c5884, 918fdc2d00fe
- candidate files: docker/Dockerfile*, docker/mcp.json, docker/build.sh, docker-compose.yml, README/.dockerignore (Docker MCP toolkit)
- AI marker: author_identity_pair
- reasoning: candidate AI commit(s) do not introduce the named mechanism (context-sync src/git-integration.ts OS command injection (CWE-77)): docker/Dockerfile*, docker/mcp.json, docker/build.sh, docker-compose.yml, README/.dockerignore (Docker MCP toolkit)

### GHSA-HC32-C5XW-9F2M — frappe/erpnext → REJECT

- aliases: CVE-2026-42839; CWE CWE-79
- mechanism: An authenticated ERPNext user with Item record edit permissions can persist arbitrary HTML/JavaScript in the item_name, description, or image fields of an Item and trigger unescaped rendering in the Point of Sale (POS) cart interface for every operator who adds that item to a transaction.This issue affects ERPNext: 16.16.0.
- candidates: c6efc403cdae, 41bcf96601c7, 2a70203cabc6, f5481dc7d563, 66dac9b7a5ff
- candidate files: erpnext/regional/italy/* + patches (rename duplicate Customer fields); regional switzerland VAT; sales forecast report pandas->python; workflow dispatch
- AI marker: co_author_trailer / author_identity_pair
- reasoning: candidate AI commit(s) do not introduce the named mechanism (ERPNext Item XSS in POS cart (item_name/description/image) (CWE-79)): erpnext/regional/italy/* + patches (rename duplicate Customer fields); regional switzerland VAT; sales forecast report pandas->python; workflow dispatch

### GHSA-W2PQ-XVQR-7FQW — frappe/erpnext → REJECT

- aliases: CVE-2026-42840; CWE CWE-79
- mechanism: An authenticated user can persist arbitrary HTML/JavaScript in the email_id or mobile_no fields of a Customer record and trigger unescaped rendering in the Point of Sale (POS) interface for every operator who selects that customer.
This issue affects ERPNext: 16.16.0.
- candidates: c6efc403cdae, 41bcf96601c7, 2a70203cabc6, f5481dc7d563, 66dac9b7a5ff
- candidate files: erpnext/regional/italy/* + patches (rename duplicate Customer fields); regional switzerland VAT; sales forecast report pandas->python; workflow dispatch
- AI marker: co_author_trailer / author_identity_pair
- reasoning: candidate AI commit(s) do not introduce the named mechanism (ERPNext Customer email_id/mobile_no XSS in POS (CWE-79)): erpnext/regional/italy/* + patches (rename duplicate Customer fields); regional switzerland VAT; sales forecast report pandas->python; workflow dispatch

### GHSA-H639-9H3V-CF49 — systemd/systemd → REJECT

- aliases: CVE-2026-16552; CWE CWE-59
- mechanism: A flaw was found in systemd-tmpfiles. When processing a tmpfiles.d configuration entry that writes to a file, systemd-tmpfiles can follow a symbolic link placed by an unprivileged local user, and an existing safety check does not detect this specific case because it always treats transitions away from the root user as safe. On systems where a tmpfiles.d configuration targets a path an unprivileged user can influence, this could allow that user to redirect a privileged systemd-tmpfiles write to a file of their choosing, though the content written remains determined by the existing configuration rather than by the unprivileged user. The highest threat from this vulnerability is to integrity.
- candidates: 7d5ec30862b3, e799263ff416, af5126568af6, 9ed12a81b251, f753f898ed06
- candidate files: src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq
- AI marker: co_author_trailer / explicit_attribution_line (Claude Opus 4.6)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (systemd-tmpfiles symlink follow (CWE-59)): src/nspawn/nspawn.c (boot_id/kmsg bind-mount backing files); src/network/* unmanaged-interface checks; src/resolve/resolved-dns-dnssd*; test-network dnsmasq

### GHSA-3W7G-Q5X7-JG2R — apache/zeppelin → REJECT

- aliases: CVE-2026-44613; CWE CWE-352
- mechanism: Cross-Site Request Forgery (CSRF) vulnerability in Apache Zeppelin. The default CORS configuration allowed cross-origin state-changing requests and accepted text/plain request bodies, allowing an attacker who lures an authenticated user to a                   malicious site to perform actions on the user's behalf through REST and WebSocket endpoints. This issue affects Apache Zeppelin versions 0.6.0 through 0.12.0. Users are recommended to upgrade to version 0.12.1, which fixes this issue.
- candidates: be08114af55c, 6218c483bc77, c0987411b63f, 1050622a0eab, 03a602a3e5ff, a3f6c6730b37, f68719f2ae6f, 86aac6645129
- candidate files: zeppelin-interpreter/* (ZEPPELIN-6400 interpreter lifecycle); zeppelin-web webpack LESS loader; TypeScript config
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Zeppelin CSRF via default CORS config (CWE-352)): zeppelin-interpreter/* (ZEPPELIN-6400 interpreter lifecycle); zeppelin-web webpack LESS loader; TypeScript config

### GHSA-853R-VXG2-55R2 — apache/zeppelin → REJECT

- aliases: CVE-2026-44617; CWE CWE-90
- mechanism: LDAP filter injection vulnerability in Apache Zeppelin. LdapRealm used RFC 4514 distinguished-name escaping when constructing LDAP search filters instead of RFC 4515 filter escaping, leaving special filter characters insufficiently escaped.                   This is an incomplete fix of CVE-2024-31867. This issue affects Apache Zeppelin versions 0.11.1, 0.11.2, and 0.12.0. Users are recommended to upgrade to version 0.12.1, which fixes this issue.
- candidates: be08114af55c, 6218c483bc77, c0987411b63f, 1050622a0eab, 03a602a3e5ff, a3f6c6730b37, f68719f2ae6f, 86aac6645129
- candidate files: zeppelin-interpreter/* (ZEPPELIN-6400 interpreter lifecycle); zeppelin-web webpack LESS loader; TypeScript config
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Zeppelin LdapRealm LDAP filter injection (CWE-90)): zeppelin-interpreter/* (ZEPPELIN-6400 interpreter lifecycle); zeppelin-web webpack LESS loader; TypeScript config

### GHSA-8CJF-MHHJ-2C5P — apache/zeppelin → REJECT

- aliases: CVE-2026-44616; CWE CWE-90
- mechanism: LDAP injection vulnerability in Apache Zeppelin. ActiveDirectoryGroupRealm constructed LDAP search filters without escaping user-controlled input, allowing an authenticated attacker to inject LDAP filter syntax through the user-search endpoint                   and potentially expose directory information. The role-lookup path was also affected after successful LDAP authentication. This issue affects Apache Zeppelin versions 0.6.0 through 0.12.0. Users are recommended to upgrade to version 0.12.1, which                   fixes this issue.
- candidates: be08114af55c, 6218c483bc77, c0987411b63f, 1050622a0eab, 03a602a3e5ff, a3f6c6730b37, f68719f2ae6f, 86aac6645129
- candidate files: zeppelin-interpreter/* (ZEPPELIN-6400 interpreter lifecycle); zeppelin-web webpack LESS loader; TypeScript config
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Zeppelin ActiveDirectoryGroupRealm LDAP injection (CWE-90)): zeppelin-interpreter/* (ZEPPELIN-6400 interpreter lifecycle); zeppelin-web webpack LESS loader; TypeScript config

### GHSA-5J5V-R5QF-P5C4 — apache/zeppelin → REJECT

- aliases: CVE-2026-44615; CWE CWE-22
- mechanism: Path traversal vulnerability in Apache Zeppelin. When FileSystemNotebookRepo is configured, an authenticated attacker with permission to rename a note, or access to folder operations, could supply traversal segments in note or folder paths.                   Zeppelin composed these values into filesystem paths using the server's filesystem or Hadoop identity without ensuring that the result remained under the configured notebook directory. This could allow notebook files or directories to be moved,                   written, or deleted outside the notebook root. This issue affects Apache Zeppelin versions 0.9.0 through 0.12.0. Users are recommended to upgrade to version 0.12.1, which fixes this issue.
- candidates: be08114af55c, 6218c483bc77, c0987411b63f, 1050622a0eab, 03a602a3e5ff, a3f6c6730b37, f68719f2ae6f, 86aac6645129
- candidate files: zeppelin-interpreter/* (ZEPPELIN-6400 interpreter lifecycle); zeppelin-web webpack LESS loader; TypeScript config
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Zeppelin FileSystemNotebookRepo path traversal (CWE-22)): zeppelin-interpreter/* (ZEPPELIN-6400 interpreter lifecycle); zeppelin-web webpack LESS loader; TypeScript config

### GHSA-GRVF-XRW5-JXHC — thiagoralves/OpenPLC_v3 → REJECT

- aliases: CVE-2021-47770; CWE CWE-94
- mechanism: OpenPLC v3 contains an authenticated remote code execution vulnerability that allows attackers with valid credentials to inject malicious code through the hardware configuration interface. Attackers can upload a custom hardware layer with embedded reverse shell code that establishes a network connection to a specified IP and port, enabling remote command execution.
- candidates: 746b16bbff4c, 995fa8cdbd57, 7ea8d717c593, a67be6960bdf, b3a1e6511966, f01c1c05ba88, e52d48c5cf88, 51183f5df355
- candidate files: webserver/core/hardware_layers/simulink.cpp; webserver/webserver.py (SSL/HTTPS); X-OpenPLC-Runtime-Version header
- AI marker: author_identity_pair (Devin AI) / co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (OpenPLC hardware configuration interface authenticated RCE (CWE-94)): webserver/core/hardware_layers/simulink.cpp; webserver/webserver.py (SSL/HTTPS); X-OpenPLC-Runtime-Version header

### GHSA-XXV9-73GC-96FM — ModelTC/LightLLM → REJECT

- aliases: CVE-2026-26220; CWE CWE-502
- mechanism: LightLLM version 1.1.0 and prior contain an unauthenticated remote code execution vulnerability in PD (prefill-decode) disaggregation mode. The PD master node exposes WebSocket endpoints that receive binary frames and pass the data directly to pickle.loads() without authentication or validation. A remote attacker who can reach the PD master can send a crafted payload to achieve arbitrary code execution.
- candidates: 4311248b6059, f0a0a272e026, 3548be135f76, 519754d01b4a, 6ba897abecff
- candidate files: lightllm/server/core/objs/shm_*.py + rpc_shm.py; router/*; utils/shm_utils.py (shared-memory startup); chat template
- AI marker: co_author_trailer / author_identity_pair
- reasoning: candidate AI commit(s) do not introduce the named mechanism (LightLLM PD disaggregation pickle.loads RCE (CWE-502)): lightllm/server/core/objs/shm_*.py + rpc_shm.py; router/*; utils/shm_utils.py (shared-memory startup); chat template

### GHSA-CH4H-8W5C-3G8G — timeplus-io/proton → REJECT

- aliases: CVE-2026-4746; CWE CWE-787
- mechanism: Out-of-bounds Write vulnerability in timeplus-io proton (base/poco/Foundation/src‎ modules). This vulnerability is associated with program files inflate.C.

This issue affects proton: before 1.6.16.
- candidates: 3bcb0b00e388, bfb1ded16676, 9a3959b0d224, 7d41c4c131cc, b4a800e2581e, 88286ab3e2f4
- candidate files: src/Storages/ExternalStream/NATSJetstream/*; session watermark; Pulsar client v4; rand distribution; CI actions
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (proton poco Foundation inflate.C out-of-bounds write (CWE-787)): src/Storages/ExternalStream/NATSJetstream/*; session watermark; Pulsar client v4; rand distribution; CI actions

### GHSA-3XV9-7R7G-8Q6F — radareorg/radare2 → REJECT

- aliases: CVE-2026-40517; CWE CWE-78
- mechanism: radare2 prior to 6.1.4 contains a command injection vulnerability in the PDB parser's print_gvars() function that allows attackers to execute arbitrary commands by crafting a malicious PDB file with newline characters in symbol names. Attackers can inject arbitrary radare2 commands through unsanitized symbol name interpolation in the flag rename command, which are then executed when a user runs the idp command against the malicious PDB file, enabling arbitrary OS command execution through radare2's shell execution operator.
- candidates: 4c849b2aaeda, cdf0662a2c1f, ff54b190187a, 3449cecf29ae
- candidate files: libr/anal/p/anal_tp.c; sys/wasi-browser.sh; linux-wasi-browser CI
- AI marker: co_author_trailer / author_identity_pair
- reasoning: candidate AI commit(s) do not introduce the named mechanism (radare2 PDB parser print_gvars command injection (CWE-78)): libr/anal/p/anal_tp.c; sys/wasi-browser.sh; linux-wasi-browser CI

### GHSA-X2X5-GJ4J-P6QW — radareorg/radare2 → REJECT

- aliases: CVE-2026-6940; CWE CWE-22
- mechanism: radare2 prior to 6.1.4 contains a path traversal vulnerability in project deletion that allows local attackers to recursively delete arbitrary directories by supplying absolute paths that escape the configured dir.projects root directory. Attackers can craft absolute paths to project marker files outside the project storage boundary to cause recursive deletion of attacker-chosen directories with permissions of the radare2 process, resulting in integrity and availability loss.
- candidates: 4c849b2aaeda, cdf0662a2c1f, ff54b190187a, 3449cecf29ae
- candidate files: libr/anal/p/anal_tp.c; sys/wasi-browser.sh; linux-wasi-browser CI
- AI marker: co_author_trailer / author_identity_pair
- reasoning: candidate AI commit(s) do not introduce the named mechanism (radare2 project deletion path traversal (CWE-22)): libr/anal/p/anal_tp.c; sys/wasi-browser.sh; linux-wasi-browser CI

### GHSA-93WG-JRMM-CX46 — Dolibarr/dolibarr → REJECT

- aliases: CVE-2026-37713; CWE CWE-94
- mechanism: An issue in Dolibarr ERP/CRM v.22.0.0 through v.22.0.4 and v.24.0.0-alpha allows a remote attacker to execute arbitrary code via the htdocs/core/class/commonobject.class.php.
- candidates: 5675986268fa, 25ee7f6fddf5, 98e93f850fed, 24a6061047b7
- candidate files: htdocs/projet/class/api_tasks.class.php; message templates reload; numero_compte; ticket email; workflow dispatch
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Dolibarr commonobject.class.php RCE (CWE-94)): htdocs/projet/class/api_tasks.class.php; message templates reload; numero_compte; ticket email; workflow dispatch

### GHSA-WWCX-37RF-X4FR — Dolibarr/dolibarr → REJECT

- aliases: CVE-2026-37711; CWE CWE-94
- mechanism: An issue in Dolibarr ERP/CRM v.22.0.0 through v.22.0.4 and v.24.0.0-alpha allows a remote attacker to execute arbitrary code via the htdocs/core/actions_addupdatedelete.inc.php
- candidates: 5675986268fa, 25ee7f6fddf5, 98e93f850fed, 24a6061047b7
- candidate files: htdocs/projet/class/api_tasks.class.php; message templates reload; numero_compte; ticket email; workflow dispatch
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Dolibarr actions_addupdatedelete.inc.php RCE (CWE-94)): htdocs/projet/class/api_tasks.class.php; message templates reload; numero_compte; ticket email; workflow dispatch

### GHSA-QVHX-Q8VJ-H6R5 — Dolibarr/dolibarr → REJECT

- aliases: CVE-2026-37712; CWE CWE-94
- mechanism: An issue in Dolibarr ERP/CRM v.22.0.0 through v.22.0.4 and v.24.0.0-alpha allows a remote attacker to execute arbitrary code via the htdocs/cron/class/cronjob.class.php, call_user_func_array() in function job type
- candidates: 5675986268fa, 25ee7f6fddf5, 98e93f850fed, 24a6061047b7
- candidate files: htdocs/projet/class/api_tasks.class.php; message templates reload; numero_compte; ticket email; workflow dispatch
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Dolibarr cronjob.class.php call_user_func_array RCE (CWE-94)): htdocs/projet/class/api_tasks.class.php; message templates reload; numero_compte; ticket email; workflow dispatch

### GHSA-9QQM-G68P-FHHP — VoltAgent/voltagent → REJECT

- aliases: CVE-2026-13511; CWE CWE-266
- mechanism: A vulnerability was determined in VoltAgent up to 2.1.17. Affected by this issue is the function handleGetMemoryConversation of the file packages/server-core/src/handlers/memory.handlers.ts of the component Memory REST API. Executing a manipulation of the argument conversationId can lead to improper authorization. The attack may be performed from remote. This attack is characterized by high complexity. The exploitation is known to be difficult. The exploit has been publicly disclosed and may be utilized. The pull request to fix this issue awaits acceptance.
- candidates: 42f4cc7b1684, bb6e9b1e3d81, 19c4fcfc10ba, f3942fa58713, e209e3aa35a5, f035d094f3b3, 0dd31c0ba4e9
- candidate files: packages/ag-ui/src/voltagent-agent.ts; styles; examples; CLAUDE.md symlink
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (VoltAgent handleGetMemoryConversation memory-handler vuln (CWE-266)): packages/ag-ui/src/voltagent-agent.ts; styles; examples; CLAUDE.md symlink

### GHSA-Q796-5G5H-CQCC — HKUDS/Vibe-Trading → REJECT

- aliases: CVE-2026-58169; CWE CWE-346
- mechanism: Vibe-Trading before 0.1.10 contains a DNS rebinding authentication bypass vulnerability that allows remote attackers to bypass bearer-token authentication by exploiting the server's trust of TCP peer addresses for loopback clients combined with missing Host header validation while binding to 0.0.0.0 with credentialed CORS. Attackers can craft a malicious DNS rebinding page to issue authenticated requests to the local API server, reach the shell execution endpoint with a bash-enabled preset, and achieve remote code execution as the API process user while also overwriting LLM and data-source settings to exfiltrate credentials.
- candidates: b986d0c2d8a2, d01eb3810215, 732537ecac14, 321f37b7369c, eb0d90409756, 8c6fe10ba1cb, a2dba07ddb4b, 9b6e3228c5c4
- candidate files: agent/src/live/{advisory,enforcement,order_guard}.py; agent/src/memory/persistent.py; docker ollama base URLs; SSE idle timeout
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Vibe-Trading DNS rebinding bearer-token auth bypass (CWE-346)): agent/src/live/{advisory,enforcement,order_guard}.py; agent/src/memory/persistent.py; docker ollama base URLs; SSE idle timeout

### GHSA-3J25-MJX3-PWG4 — HKUDS/Vibe-Trading → REJECT

- aliases: CVE-2026-58173; CWE CWE-22
- mechanism: Vibe-Trading before 0.1.10 contains a path traversal vulnerability that allows attackers to write files outside the intended memory root directory by supplying a malicious memory_type value containing path traversal sequences through the remember tool. Attackers can manipulate the memory_type parameter in the persistent memory store to cause the application to write arbitrary Markdown files to unintended locations on the filesystem.
- candidates: b986d0c2d8a2, d01eb3810215, 732537ecac14, 321f37b7369c, eb0d90409756, 8c6fe10ba1cb, a2dba07ddb4b, 9b6e3228c5c4
- candidate files: agent/src/live/{advisory,enforcement,order_guard}.py; agent/src/memory/persistent.py; docker ollama base URLs; SSE idle timeout
- AI marker: co_author_trailer
- reasoning: candidate AI commit(s) do not introduce the named mechanism (Vibe-Trading remember tool memory_type path traversal (CWE-22)): agent/src/live/{advisory,enforcement,order_guard}.py; agent/src/memory/persistent.py; docker ollama base URLs; SSE idle timeout
