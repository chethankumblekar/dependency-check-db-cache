# Identity provider testing

GitHub and Microsoft Entra sign-in are unit-tested against local fakes
(`tests/test_sso.py`). This page is the test against real providers. Run it
on a test deployment, with test accounts, before the first production
deployment and after any change to `src/checkstead/sso.py`. It needs a person:
the provider's login page takes a password and, often, a second factor.

Status on 20 October 2026: **not run.** The automated preflight passed
against a local server with placeholder client ids. No real test tenant or
OAuth app was used.

## Set up

| Provider | Create | Callback URL |
| --- | --- | --- |
| GitHub | An OAuth App in a test organization (Settings, Developer settings, OAuth Apps) | `https://<test-host>/api/sso/github/callback` |
| Entra | An app registration in a test directory, single tenant, with a client secret, and API permissions `openid`, `profile`, `email` | `https://<test-host>/api/sso/entra/callback` (platform: Web) |

Test accounts: in GitHub, one member and one non-member of the organization
named in `CHECKSTEAD_GITHUB_ORG`. In Entra, one user in the test directory and
one user in a second directory (any other tenant you control).

Server settings: `CHECKSTEAD_PUBLIC_BASE=https://<test-host>`,
`CHECKSTEAD_LOCAL=0`, `CHECKSTEAD_COOKIE_SECURE=1`, the four client id and
secret variables, `CHECKSTEAD_GITHUB_ORG=<test org>`, and
`CHECKSTEAD_ENTRA_TENANT=<test directory id>`.

## Automated preflight

```bash
python3 scripts/idp-preflight.py --base https://<test-host>
```

Exit 0 means each enabled provider redirects with the right client id, the
exact callback URL, the minimal scope, and a state that matches an HttpOnly,
SameSite=Lax, Secure cookie; a forged state is refused; and the provider's
page answers. It does not sign anyone in.

## Manual cases

Record the date, the build digest, and pass or fail for each row.

| # | Case | Expected |
| --- | --- | --- |
| 1 | First person signs in with GitHub (org member) | Signed in as administrator. `accounts.sqlite` holds no GitHub token. |
| 2 | Administrator adds a second GitHub login; that person signs in | Signed in as user. Administration is refused (403). |
| 3 | A GitHub account that is not in `CHECKSTEAD_GITHUB_ORG` signs in | "is not a member of" message. No session cookie. |
| 4 | A GitHub login that was never added signs in | "An administrator has to add this login" (403). |
| 5 | Administrator adds an Entra login from the test directory; that person signs in | Signed in. |
| 6 | The same login, but a user from the second directory | "This Microsoft Entra directory is not allowed" (401). |
| 7 | Sign-in started, then the callback replayed from browser history | "Sign-in could not be confirmed" (400): the state cookie was cleared. |
| 8 | Callback URL opened in a second browser without the state cookie | 400. |
| 9 | Sign out, then reuse the old session cookie (curl) | `/api/session` returns 401. |
| 10 | Request with `Host: evil.example` through the proxy | 421. |
| 11 | Rename the GitHub test account, sign in again | Same account (matched by numeric id), login updated. |
| 12 | Rotate the OAuth client secret at the provider and in `.env`, restart | Sign-in still works; the old secret no longer does. |

## When a case fails

Do not deploy. Open an issue with the case number, the provider's error page
or the server response, and the server log line. Do not paste client
secrets, codes, or tokens into the issue.
