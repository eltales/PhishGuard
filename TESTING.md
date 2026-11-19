# Testing PhishGuard

Run the analyzer tests from the project directory:

```powershell
node tools/selftest.js
```

For manual checks, configure `alex.morgan@example.com` as the company email, `security@example.com` as the administrator, and `trusted-service.test` as a trusted domain. Import the [sample messages](test-emails/README.md) into a local folder, then open them from that folder.

| Check | Expected behavior |
| --- | --- |
| Open the lookalike fixture | A critical warning appears above the message. Details include the similar sender domain. |
| Open the medium-risk fixture | A warning appears. With link warnings enabled, opening any link shows its destination and offers a Cancel button. Use Cancel for this test. |
| Open the trusted-domain fixture | The routine message shows no warning. Strong signals on other messages can still trigger a warning. |
| Open the attachments fixture | Details show the double extension and MIME mismatch. The warning does not offer **Trust sender locally**. |
| Trust a sender on a message with weak content signals | **Trust sender locally** adds the individual email address to **Trusted sender email addresses** in options. Trust persists when the message is reopened. Remove the address and save to revoke it. |
| Open a newsletter with many links to a trusted domain | The link count does not add points. Subdomains such as `id.atlassian.com` and `track.atlassian.com` belong to the configured `atlassian.com` domain. |
| Try to add `exarnple.test` to trusted domains | PhishGuard rejects the entry. |
| Report a selected message | **Report phishing** in the main Mail toolbar, or **Report to administrator** in the warning, prepares a message to `security@example.com`. The subject starts with `PhishGuard: ` and the original is an `.eml` attachment. Leave the report unsent. |
| Change **Language** | English is the default. Choose **Polski** and save. Options, message warnings, and reports use the new language. |
| Leave the company domain unset | The report popup offers to open settings. |
| Leave the administrator address unset | Preparing a report displays a configuration error. |
| Switch between several messages | PhishGuard warning styles appear where expected. The Error Console should show no duplicate `addSheet` errors from PhishGuard. |

Open Thunderbird's Error Console with **Ctrl+Shift+J** on Windows. Filter by `PhishGuard` for analysis messages, or by `addSheet` to check stylesheet injection.
