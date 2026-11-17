# Sample messages

These `.eml` files are local test fixtures. The attachments contain plain text. The embedded link hosts are reserved example domains or a documentation IP address.

## Setup

In PhishGuard settings, enter `alex.morgan@example.com` as the company email and `security@example.com` as the administrator. Add `trusted-service.test` to the trusted domains. Drag the `.eml` files into a Thunderbird local folder and open them there.

| Fixture | What it exercises | Expected risk |
| --- | --- | --- |
| `test-phishing-lookalike.eml` | Lookalike sender domain, Reply-To mismatch, misleading link, and macro-document filename | Critical |
| `test-medium-risk.eml` | Reply-To mismatch, urgency, and a regular link | Medium |
| `test-trusted-domain.eml` | Routine message from a trusted domain | Low |
| `test-auth-fail.eml` | Reported SPF, DKIM, and DMARC failures | High |
| `test-display-name-spoof.eml` | Company impersonation in the display name | Critical |
| `test-display-name-email.eml` | Display name impersonates an email address | Critical |
| `test-url-tricks.eml` | URL user info, many subdomains, and an IP address link | Critical |
| `test-attachments.eml` | Double extension and MIME mismatch | Medium |
| `test-image-only.eml` | Minimal text, Reply-To mismatch, and an IP address link | High |
| `test-cyrillic.eml` | Cyrillic sample text from a `.com` sender | Medium |

The Cyrillic fixture has English headers and link text. Its short Cyrillic paragraph is the input for the writing-system check.

See [manual verification](../TESTING.md) for steps and expected behavior.
