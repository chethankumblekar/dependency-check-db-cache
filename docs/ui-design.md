# Web UI design

The timeline server's UI for people who decide whether a dependency change is safe to ship. They are security engineers, release owners, and the developers whose pull request a scan blocked. They need to answer three questions quickly and trust the answer:

1. What needs me right now?
2. Can I trust this scan? Was the vulnerability data current, signed, and intact?
3. What changed, and what do I do about it?

## Principles

- **Evidence before verdicts.** Every claim on screen comes from a field in a report. When a report does not record something, the UI says "Not recorded". It never infers a value or treats a missing value as good.
- **One loud element.** The evidence chain is the signature element. Everything around it stays quiet: one rule weight, one radius, no shadows, no gradients.
- **Words carry meaning, colour reinforces it.** Severity, freshness, and signature states are always written out ("Critical 9.1", "Aging, 5 days", "Not verified"). Colour is never the only signal.
- **Teal means verified, and nothing else.** The accent colour is reserved for verified evidence, so it never shows up as decoration.
- **No sample data.** The app ships no fixtures. An empty server shows an empty state that says how to produce the first scan.

## Design tokens

All tokens are CSS custom properties in [app.css](../src/checkstead/static/app.css). The dark theme redefines the same names.

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `--paper` | `#f4f6f5` | `#0f1513` | Page background: cool slate-green, not cream |
| `--surface` | `#ffffff` | `#151d1a` | Tables, panels |
| `--ink` | `#14201b` | `#e3eae6` | Body text |
| `--muted` | `#57645e` | `#93a29b` | Secondary text |
| `--verified` | `#0e6b5a` | `#45b89c` | Verified evidence only |
| `--warn` | `#8c5a0b` | `#e0a64a` | Aging data, new findings |
| `--fail` | `#a1252c` | `#f07a7f` | Stale data, unsigned, exploited |
| `--sev-critical` / `-high` / `-medium` / `-low` / `-none` | `#a1252c` `#a84a16` `#7d630b` `#4c6a5f` `#5d6964` | `#f07a7f` `#f0975f` `#d8b84d` `#8fb3a5` `#8a9892` | CVSS bands |

Contrast was computed with the WCAG 2.x formula. Every text token is at least 4.5:1 against `--paper`, `--surface`, and `--surface-sunk` in both themes. The lowest is a severity colour on `--surface-sunk` in the light theme, at 4.93:1. axe-core's contrast rule needs layout, which jsdom lacks, so the tests turn it off and these ratios are the check.

**Type.** Atkinson Hyperlegible Next for the interface: it was designed for low-vision readers and keeps 0/O and 1/l/I distinct. JetBrains Mono for identifiers only: CVE and GHSA ids, package coordinates, digests, revisions. Both are vendored as Latin `woff2` subsets under the SIL Open Font License, with SHA-256 sums in `static/fonts/SHA256SUMS`. CI fails if they differ from the pinned npm packages. The scale runs 13, 14, 15, 18, 21.6, and 26 px, and line length stays under 80 characters.

**Space.** 4, 8, 12, 16, 24, 32, and 48 px. Radius is 4 or 6 px. The content column is at most 1240 px wide.

**Theme.** Auto follows `prefers-color-scheme`. Light and Dark set `data-theme` on the root element, and the choice is kept in `localStorage`. If storage is blocked, the choice lasts for the page only.

## Information architecture

```
Sign in (gate)                      shown until a session exists; Azure DevOps form once an Azure DevOps login exists
└─ Shell: rail navigation + main
   ├─ Overview            #/                       evidence chain, needs attention, counts, newest scan per project
   ├─ Scans               #/scans                  opens the newest scan
   │  └─ Scan             #/scans/<id>[/<tab>]     findings | changes | dependencies | evidence
   ├─ Evidence            #/evidence               the evidence chain for every newest scan
   ├─ CI runs             #/builds                 GitHub App workflow runs, rerun
   └─ Access              #/access                 administrators only: people and roles
```

Routes are hash routes, so every view and tab has a link that survives a reload, and the server needs no route of its own. The server-rendered GitHub App pages under `/github` are unchanged.

## Journeys

**A release owner checks the morning's state.** They open Overview. The evidence chain says whether the newest scan's data can be trusted. Needs attention lists exploited findings first, then critical findings, then new findings, stale data, and unsigned snapshots. Each item links to the tab that explains it.

**A developer's pull request was blocked.** They follow the link to the scan and open Changes, which shows what the pull request introduced, most severe first. Selecting a finding shows its description, CVSS vectors, whether it is on the CISA KEV list, a link to the advisory, and what to do. For a transitive finding, it says to upgrade the direct dependency that brings it in.

**An auditor verifies a scan.** The Evidence tab shows the snapshot time and freshness, the full zip digest, the signature key, the engine version, and the policy the scan applied. It also gives the two commands that rerun the scan client's own checks.

**An administrator adds a colleague.** Access has a form with the account type, login, and role. Removing a person takes a second press. The server refuses to remove or demote the last administrator, and the UI shows that refusal.

## States

Every load is idle, loading, ready, or error. Views render each state explicitly.

| State | What the person sees |
| --- | --- |
| Loading | Skeleton lines in the shape of the content |
| Empty | What is missing and how to produce it, for example "No scans yet" with the ways scans reach the server |
| Error | The server's own message and **Try again** |
| Offline | A banner saying the shown data was loaded earlier and will not update. The request error names the connection |
| Timeout | After 20 seconds: "The server is taking too long" with **Try again** |
| Session expired | Any 401 returns to the sign-in gate |
| Permission denied | 403, or a member opening Access: "Only administrators manage access", with no form |
| Stale data | Freshness turns Aging after 1 day and Stale after 7, the same rule the scan client uses. Stale scans are listed in Needs attention |
| Unsigned or unrecorded | Shown in the chain as "Not verified" or "Not recorded" |

## Accessibility

- Landmarks: a skip link, a `nav` rail with `aria-current`, one `main`, and one `h1` per view with no skipped heading levels.
- On navigation, focus moves to the new page's heading. Arrowing between tabs keeps focus on the tabs.
- Tables have captions and `scope` attributes. Sortable headers are buttons with `aria-sort`. Selectable rows are focusable and respond to Enter and Space.
- Tabs follow the ARIA tabs pattern with arrow keys. Filters are labelled segmented buttons with `aria-pressed`.
- Focus rings are visible in both themes, and `prefers-reduced-motion` turns off transitions.
- axe-core runs against every view in the tests and must report no violations.

## Security

- Content-Security-Policy on the app is `default-src 'none'; script-src 'self'; style-src 'self'`, with no `'unsafe-inline'`. The legacy `/github` pages keep their own policy.
- The DOM is built with a small `h()` helper that sets text and attributes only. A test fails if any module assigns `innerHTML` or `outerHTML`, or calls `insertAdjacentHTML` or `document.write`.
- External links are checked to be `http` or `https` and open with `rel="noopener noreferrer"`.
- Static files are an allowlist read at startup. Any other path, including traversal attempts, is a 404. Files are served with a strong ETag and `Cache-Control: no-cache`, so an upgrade never leaves an old script running against a new API.
- No third-party requests: fonts and icons are local.

## Code

| Path | What |
| --- | --- |
| `src/checkstead/static/js/api.js` | Typed API contract (JSDoc), `request()` with a timeout and typed `ApiError` |
| `src/checkstead/static/js/model.js` | Everything derived from reports: latest scans, counts, evidence chain, attention |
| `src/checkstead/static/js/format.js` | Freshness, severity bands, time and digest formatting |
| `src/checkstead/static/js/components.js` | Severity mark, evidence chain, tables, tabs, states |
| `src/checkstead/static/js/app.js` | State, loading, the shell, routing, focus, theme |
| `src/checkstead/static/js/views/` | One module per page |
| `web/` | Development tooling only: TypeScript, jsdom, axe-core, and the font packages, all at exact versions |

## Known gaps

- Contrast is computed from tokens, not measured in a browser with axe. A browser-based axe run (Playwright) would cover it, but it is not set up.
- The Overview loads every scan's summary at once. That is fine for hundreds of scans. Thousands would need server-side paging.
- Dependency tables are capped at 500 rows per group, with the total shown. There is no paging or export yet.
- There is no in-app way to suppress a finding. The "What to do" text points to the suppression file.
- The `/github` setup pages are still server-rendered and use the older styles.
