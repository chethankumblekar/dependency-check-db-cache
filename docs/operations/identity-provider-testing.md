# Identity provider testing

GitHub and Microsoft Entra sign-in are unit-tested against local fakes
(`tests/test_sso.py`). This page is the test against real providers. Run it
on a test deployment, with test accounts, before the first production
deployment and after any change to `src/checkstead/sso.py`. It needs a person:
the provider's login page takes a password and, often, a second factor.

Status on 21 October 2026: **partly run against real providers.** Azure DevOps
sign-in failed on `main` and passes with pull request 32. Cases 1,
4 (with Entra), 5, 7, 8, 9 and 10 passed, with one deviation in case 7. Cases 2, 3, 6,
11 and 12 need a second account or directory and were not run. See
[Results, 21 October 2026](#results-21-october-2026).

## Set up

| Provider | Create | Callback URL |
| --- | --- | --- |
| GitHub | An OAuth App in a test organization (Settings, Developer settings, OAuth Apps) | `https://<test-host>/api/sso/github/callback` |
| Entra | An app registration in a test directory, single tenant, with a client secret, and API permissions `openid`, `profile`, `email`, and Microsoft Graph `User.Read` (profile photo) | `https://<test-host>/api/sso/entra/callback` (platform: Web) |

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

## Results, 21 October 2026

Build: `main` at `446a848`, run from source (`python3 -m checkstead ui`) on
`http://localhost:8769` with `CHECKSTEAD_LOCAL=0`. Plain HTTP on localhost, so
`CHECKSTEAD_COOKIE_SECURE` was not set. Providers: a GitHub OAuth App on the
personal account `chethankumblekar` (no `CHECKSTEAD_GITHUB_ORG`), and a
single-tenant Entra app registration in directory `4c789ab3-…`, signed in by a
guest (Microsoft account) user. Both apps were deleted after the run.

`idp-preflight.py` with the real client ids: PASS for GitHub and Entra.

| # | Result | Evidence |
| --- | --- | --- |
| 1 | PASS | First GitHub sign-in became `admin`, keyed by numeric id. `accounts.sqlite` has `users` and `sessions` (`token_hash`) only; no GitHub token in the dump. |
| 2 | Not run (one GitHub account). The same check passed with Entra: a `user` session gets 403 from `/api/admin/users`. | |
| 3 | Not run (no test organization) | |
| 4 | PASS, with Entra | Entra sign-in before the login was added: "An administrator has to add this login before it can sign in." |
| 5 | PASS | Administrator added `entra` with the guest's email address with `POST /api/admin/users` (201). Sign-in then succeeded as `user`; display name taken from userinfo. |
| 6 | Not run (no second directory). A user from another directory is stopped by Microsoft first, because the app is single tenant. | |
| 7 | PASS after success; **deviation after failure** | After a successful callback the state cookie is cleared, so a replay gets 400. After a failed callback (refused login, rejected code) the state cookie is not cleared: reloading the real refused Entra callback reached Microsoft again and got "Microsoft Entra rejected this sign-in." (401) instead of 400. Nobody was signed in, because the provider codes are single use. |
| 8 | PASS | Callback without the state cookie: 400 for GitHub and Entra. |
| 9 | PASS | `DELETE /api/session` 200, then `/api/session` 401; the session row was removed from `sessions`. |
| 10 | PASS | `Host: evil.example`: 421. |
| 11 | Not run | |
| 12 | Not run | |

Findings:

- Low: `_sso_callback` in `src/checkstead/ui.py` clears `checkstead_sso` only
  on success. Clearing it on every callback response would make case 7 hold
  in both paths.
- Note: Graph `oidc/userinfo` returns no `oid`, so Entra accounts are keyed by
  `sub`, which is pairwise per application. Replacing the app registration
  (new client id) gives every Entra user a new `sub`; the existing rows keep
  the old one. Check how `sign_in` matches a known login with a new subject
  before rotating to a new registration.

Azure DevOps sign-in (PAT and organization), against a real organization
with a PAT scoped to User Profile (read) and expiring the next day:

- **Fail on `main`.** `identify_azure` calls
  `connectionData?api-version=7.1`; Azure DevOps answers 400 ("The requested
  version \"7.1\" of the resource is under preview. The -preview flag must be
  supplied"), and the user sees "The identity provider rejected this token."
  `7.1-preview.1` returns 200. Fixed in pull request 32.
- **Pass with that fix.** Administrator-added login, then `POST /api/session`
  with the PAT: 200, `role` user, bound to the Azure DevOps user id. The
  accounts database holds only 64-character session hashes, no PAT.
- **Gap: the web sign-in page has no Azure DevOps option.**
  `static/js/views/signin.js` shows only the GitHub, Microsoft and localhost
  buttons, while the Access page lets an administrator add Azure DevOps
  logins. Those people can sign in only by calling the API.

## When a case fails

Do not deploy. Open an issue with the case number, the provider's error page
or the server response, and the server log line. Do not paste client
secrets, codes, or tokens into the issue.
