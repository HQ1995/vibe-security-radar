# GHSA-HQJG-PWW4-PCGQ

repo: google/clasp

summary: @google/clasp vulnerable to unsafe path traversal cloning or pulling a malicious script

aliases: ['CVE-2026-4092']

severity: HIGH

evidence: blame blamed_lines=5 files=['src/core/files.ts']

intro: 9c141469c5be3310d335dd33b1872bcbbeb24df1

intro_subject: chore: Improve internal docs (#1067)

intro_date: 2025-06-06T13:05:05-06:00

fix: ba6bd666fe74de54950122b5d92ecf1dcc02a9d3

affected: [
  {
    "package": {
      "ecosystem": "npm",
      "name": "@google/clasp"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "3.2.0"
          }
        ]
      }
    ]
  }
]

DETAILS:
### Impact
Allows an attacker to perform a "Path Traversal" attack to modify files outside the projects directory, potentially allowing for running attacker code on the developer's machine.

### Patches
Fixed in version 3.2.0

### Workarounds
* Only clone or pull scripts from trusted sources
* Review the output of the `pull` and `clone` commands to verify only expected project files are modified

REFS:
- WEB https://github.com/google/clasp/security/advisories/GHSA-hqjg-pww4-pcgq
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-4092
- WEB https://github.com/google/clasp/pull/1109
- WEB https://github.com/google/clasp/commit/ba6bd666fe74de54950122b5d92ecf1dcc02a9d3
- PACKAGE https://github.com/google/clasp
- WEB https://github.com/google/clasp/releases/tag/v3.2.0

INTRO_LOG:
9c141469c5be3310d335dd33b1872bcbbeb24df1
Steve Bazyl <sqrrrl@gmail.com>
2025-06-06T13:05:05-06:00
chore: Improve internal docs (#1067)

* Jules was unable to complete the task in time. Please review the work done so far and provide feedback for Jules to continue.

* docs: Improve internal documentation for src and test files

This commit adds comprehensive internal documentation to .ts files
across your `src` and `test` directories.

The following improvements were made:
- Added file-level comments explaining the purpose of each file.
- Added JSDoc comments to classes, explaining their responsibilities.
- Added JSDoc comments to public methods in classes, detailing their
  purpose, parameters, and return values.
- Added JSDoc comments to other exported functions and interfaces,
  explaining their usage and properties/parameters.
- Added inline comments to complex or non-obvious logic blocks within
  functions and methods to improve code readability and maintainability.
- Reviewed and added clarifying comments to test suites (`describe`
  blocks) and test cases (`it` blocks) where needed.

All changes were linted and tested to ensure no regressions or style issues were introduced.

---------

Co-authored-by: google-labs-jules[bot] <161369871+google-labs-jules[bot]@users.noreply.github.com>


INTRO_STAT:
 package-lock.json                     | 115 +++++++++++++++++++-
 package.json                          |   2 +-
 src/auth/auth.ts                      |  68 ++++++++++--
 src/auth/auth_code_flow.ts            |  43 ++++++++
 src/auth/credential_store.ts          |  42 ++++++++
 src/auth/file_credential_store.ts     |  59 +++++++++--
 src/auth/localhost_auth_code_flow.ts  |  40 ++++++-
 src/auth/serverless_auth_code_flow.ts |  26 +++++
 src/commands/clone-script.ts          |  21 +++-
 src/commands/create-deployment.ts     |   3 +
 src/commands/create-script.ts         |  30 ++++--
 src/commands/create-version.ts        |   3 +
 src/commands/delete-deployment.ts     |   3 +
 src/commands/disable-api.ts           |   2 +
 src/commands/enable-api.ts            |   2 +
 src/commands/list-apis.ts             |   2 +
 src/commands/list-deployments.ts      |   3 +
 src/commands/list-scripts.ts          |   3 +
 src/commands/list-versions.ts         |   3 +
 src/commands/login.ts                 |   2 +
 src/commands/logout.ts                |   2 +
 src/commands/open-apis.ts             |   2 +
 src/commands/open-container.ts        |   2 +
 src/commands/open-credentials.ts      |   2 +
 src/commands/open-logs.ts             |   2 +
 src/commands/open-script.ts           |   2 +
 src/commands/open-webapp.ts           |   2 +
 src/commands/program.ts               |  39 +++++--
 src/commands/pull.ts                  |  30 ++++--
 src/commands/push.ts                  |  25 ++++-
 s

INTRO_DIFF_OVERLAP:
diff --git a/src/core/files.ts b/src/core/files.ts
index 05b06c8..175ecf1 100644
--- a/src/core/files.ts
+++ b/src/core/files.ts
@@ -12,6 +12,10 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+// This file manages the synchronization of files between the local filesystem
+// and the Google Apps Script project. It handles pulling, pushing, collecting
+// local files, watching for changes, and resolving file types and conflicts.
+
 import path from 'path';
 import chalk from 'chalk';
 import chokidar, {Matcher} from 'chokidar';
@@ -28,6 +32,13 @@ import {ClaspOptions, assertAuthenticated, assertScriptConfigured, handleApiErro
 
 const debug = Debug('clasp:core');
 
+/**
+ * Represents a file within an Apps Script project, either locally or remotely.
+ * @property {string} localPath - The path of the file on the local filesystem, relative to the current working directory.
+ * @property {string} [remotePath] - The name of the file as it appears in the Apps Script project (often without extension, or 'appsscript' for the manifest).
+ * @property {string} [source] - The source content of the file.
+ * @property {string} [type] - The type of the file as defined by Apps Script (e.g., "SERVER_JS", "HTML", "JSON").
+ */
 export interface ProjectFile {
   readonly localPath: string; // Local filesystem path, relative to cwd
   readonly remotePath?: string; // Name of file in apps script project
@@ -50,11 +61,12 @@ async function getLocalFiles(rootDir: string, ignorePatterns: string[], recursiv
   let fdirBuilder = new fdir().withBasePath().withRelativePaths();
   if (!recursive) {
     debug('Not recursive, limiting depth to current directory');
-    fdirBuilder = fdirBuilder.withMaxDepth(0);
+    fdirBuilder = fdirBuilder.withMaxDepth(0); // Limit crawling to the current directory if not recursive
   }
   const files = await fdirBuilder.crawl(rootDir).withPromise();
   let filteredFiles: string[];
   if (ignorePatterns && ignorePatterns.length) {
+    // Filter out files that are explicitly ignored by the .claspignore file or default ignore patterns.
     filteredFiles = micromatch.not(files, ignorePatterns, {dot: true});
     debug('Filtered %d files from ignore rules', files.length - filteredFiles.length);
   } else {
@@ -77,12 +89,15 @@ function createFilenameConflictChecker() {
   const files = new Set<string>();
   return (file: ProjectFile) => {
     if (file.type !== 'SERVER_JS') {
-      return file;
+      return file; // Conflict check only applies to SERVER_JS files
     }
     const parsedPath = path.parse(file.localPath);
+    // Create a key based on directory and name (without extension) to detect conflicts
+    // e.g. `src/Code.js` and `src/Code.gs` would conflict.
     const key = path.format({dir: parsedPath.dir, name: parsedPath.name});
     if (files.has(key)) {
       throw new Error('Conflicting files found', {
+        // TODO: Better error message, show conflicting files
         cause: {
           code: 'FILE_CONFLICT',
           value: key,
@@ -111,19 +126,21 @@ function getFileType(fileName: string, fileExtensions: Record<string, string[]>)
 function getFileExtension(type: string | null | undefined, fileExtensions: Record<string, string[]>) {
   // TODO - Include project setting override
   const extensionFor = (type: string, defaultValue: string) => {
+    // Prioritize the first extension defined for a type in .clasp.json if available.
     if (fileExtensions[type] && fileExtensions[type][0]) {
       return fileExtensions[type][0];
     }
-    return defaultValue;
+    return defaultValue; // Fallback to default if no specific extension is configured.
   };
   switch (type) {
     case 'SERVER_JS':
-      return extensionFor('SERVER_JS', '.js');
+      return extensionFor('SERVER_JS', '.js'); // Default to .js for server-side JavaScript
     case 'JSON':
-      return extensionFor('JSON', '.json');
+      return extensionFor('JSON', '.json'

FIX_LOG:
ba6bd666fe74de54950122b5d92ecf1dcc02a9d3
ⳕⲛτⲉⲅⲥⲉⳏτⲟⲅ 🕵🏻 <192411347+g0w6y@users.noreply.github.com>
2026-01-31T15:20:27+00:00
fix: prevent path traversal in remote file synchronization (#1109)

* Implement security check for resolved file paths

Added security check to prevent file path traversal.

* Refactor fetchRemote method for clarity and security

* Refactor fetchRemote method documentation and logic

* Add isInside function and refactor fetchRemote

* Fix typescript error

---------

Co-authored-by: Steve Bazyl <sqrrrl@gmail.com>


FIX_STAT:
 src/core/files.ts | 54 +++++++++++++++++++++++++++++++++++++++++++-----------
 1 file changed, 43 insertions(+), 11 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/src/core/files.ts b/src/core/files.ts
index 175ecf1..43934ed 100644
--- a/src/core/files.ts
+++ b/src/core/files.ts
@@ -55,6 +55,23 @@ function parentDirs(file: string) {
   }
   return parentDirs;
 }
+function isInside(parentPath: string, childPath: string): boolean {
+
+  const relative = path.relative(parentPath, childPath);
+
+  return (
+
+    relative !== '' &&
+
+    !relative.startsWith('..') &&
+
+    !path.isAbsolute(relative)
+
+  );
+
+}
+
+
 
 async function getLocalFiles(rootDir: string, ignorePatterns: string[], recursive: boolean) {
   debug('Collecting files in %s', rootDir);
@@ -190,12 +207,8 @@ export class Files {
     this.options = options;
   }
 
-  /**
+/**
    * Fetches the content of a script project from Google Drive.
-   * @param {number} [versionNumber] - Optional version number to fetch.
-   * If not specified, the latest version (HEAD) is fetched.
-   * @returns {Promise<ProjectFile[]>} A promise that resolves to an array of project files.
-   * @throws {Error} If there's an API error or authentication/configuration issues.
    */
   async fetchRemote(versionNumber?: number): Promise<ProjectFile[]> {
     debug('Fetching remote files, version %s', versionNumber ?? 'HEAD');
@@ -207,29 +220,47 @@ export class Files {
     const scriptId = this.options.project.scriptId;
     const script = google.script({version: 'v1', auth: credentials});
     const fileExtensionMap = this.options.files.fileExtensions;
+
     try {
       const requestOptions = {scriptId, versionNumber};
       debug('Fetching script content, request %o', requestOptions);
+
       const response = await script.projects.getContent(requestOptions);
       const files = response.data.files ?? [];
+
+      // 1. Establish the security boundary (the "jail")
+      const absoluteContentDir = path.resolve(contentDir);
+
       return files.map(f => {
         const ext = getFileExtension(f.type, fileExtensionMap);
-        const localPath = path.relative(process.cwd(), path.resolve(contentDir, `${f.name}${ext}`));
 
-        const file = {
-          localPath: localPath,
+        // 2. Resolve the absolute path for the remote file
+        const resolvedPath = path.resolve(contentDir, `${f.name}${ext}`);
+
+        // 3. SECURITY CHECK: Ensure path is strictly inside contentDir
+        // This prevents traversal (../../) and prefix attacks (/foo/bar vs /foo/bar1)
+        if (!isInside(absoluteContentDir, resolvedPath)) {
+          throw new Error(
+            `Security Error: Remote file name "${f.name}" attempts to write outside the project directory.`
+          );
+        }
+
+        const localPath = path.relative(process.cwd(), resolvedPath);
+
+        const file: ProjectFile = {
+          localPath,
           remotePath: f.name ?? undefined,
           source: f.source ?? undefined,
           type: f.type ?? undefined,
         };
+
         debug('Fetched file %O', file);
         return file;
       });
-    } catch (error) {
-      handleApiError(error);
+    } catch (err) {
+      throw handleApiError(err as GaxiosError);
     }
   }
-
   /**
    * Collects all local files in the project's content directory, respecting ignore patterns.
    * It reads the content of each file and determines its type.
@@ -570,3 +601,4 @@ function extractSyntaxError(error: GaxiosError, files: ProjectFile[]) {
   snippet = preLines + '\n' + errLine + '\n' + postLines;
   return {message, snippet}; // Return the formatted message and snippet.
 }
+


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []