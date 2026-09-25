# Site Scanning Alerts

Monitor federal websites for status changes and configuration issues using [GSA Site Scanning](https://digital.gov/site-scanning/) data. Automatically creates GitHub issues when your monitored websites experience problems.

This repo monitors the sites listed in `watchlist.txt` and checks for changes or problems daily.

---

**⚠️ Using this as a template?** → Jump to [Setup (Template Instructions)](#setup-template-instructions)

---

## Quickstart

1. Add domains to monitor in `watchlist.txt`:
   ```
   blog.gsa.gov
   www.gsa.gov
   base:gsa.gov
   ```

2. Enable the workflow in `.github/workflows/site-scanning-alerts.yml`:
   ```yaml
   name: Site Scanning Alerts
   
   on:
     schedule:
       - cron: '30 15 * * *'
     workflow_dispatch:
   
   permissions:
     issues: write
     contents: read

   concurrency:
     group: site-scanning-alerts-${{ github.repository }}
     cancel-in-progress: false
   
   jobs:
     check-alerts:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: GSA/site-scanning-alert-template@v1
           with:
             watchlist: watchlist.txt
   ```

3. Go to Actions tab → "Site Scanning Alerts" → Enable workflow

4. Wait for the first run (daily at 15:30 UTC) or trigger manually via workflow_dispatch

## What You'll Get

When a monitored site has a problem, an issue like this is created automatically:

```markdown
❗ Site Scanning results have changed for websites that you are monitoring:

- **blog.acme.gov**
  - `live`: TRUE → FALSE
  - `status_code`: 200 → 503
- **calendar.acme.gov**
  - `primary_scan_status`: completed → timeout
- **docs.acme.gov**
  - Newly in snapshot

Please investigate as appropriate.
```

Findings are grouped by site, so a site with several problems reads as one entry
rather than several unrelated ones. The grouping is a nested list rather than
per-site headings: an issue body starts below the issue title, so headings added
here would land at the wrong level in the page's heading outline.

The action uses **fingerprinted filing** (no rolling comments, no auto-close - MVP tradeoff, see [Known Limitations](#known-limitations)):
- **First detection** → files a new issue
- **Re-runs with identical findings while that issue is still open** → no-op (no duplicate issues)
- **Different findings** (a new domain fails, or the set of failures changes) → files another issue, since the fingerprint no longer matches
- **Condition clears** → reported in the step summary only; no issue is touched. Close the issue yourself once you've confirmed it's resolved.

## Configuring Your Watchlist

Edit `watchlist.txt` to add the websites you want to monitor. Two syntaxes are supported:

### Model 1: Exact Domain Match

Monitor specific domains by listing them one per line:

```
blog.acme.gov
calendar.acme.gov
www.acme.gov
```

This watches only those exact `initial_domain` values in the Site Scanning data.

### Model 2: All Subdomains Under a Base Domain

Monitor all websites under a base domain using the `base:` prefix:

```
base:cpsc.gov
```

This watches every record where `initial_base_domain` equals `cpsc.gov`, including `www.cpsc.gov`, `access.cpsc.gov`, etc.

### Comments and Blank Lines

Lines starting with `#` are treated as comments and ignored. Blank lines are also ignored.

## Configuration Reference

The action is configured via inputs in `.github/workflows/site-scanning-alerts.yml`. All inputs are optional with sensible defaults.

| Input | Default | Description |
|-------|---------|-------------|
| `watchlist` | `watchlist.txt` | Path to the file containing domains to monitor (one per line, supports base:domain.gov syntax for all subdomains) |
| `mode` | `both` | Alert mode: `change` (detect changes between latest and previous snapshots), `state` (alert on bad current values), or `both`. `change` alone cannot confirm recovery from a sustained outage - use `state` or `both` for availability monitoring. Any other value is a hard configuration error |
| `fields` | `live,status_code,primary_scan_status` | Comma-separated list of fields to monitor for changes (change mode only). Any column present in the Site Scanning snapshot is supported (e.g. live, status_code, primary_scan_status, https_enforced, hsts). Unrecognized field names are reported in the step summary and skipped |
| `alert_on_status_codes` | `500,502,503,504` | Comma-separated list of HTTP status codes to alert on (state mode). Example: 500,502,503,504 |
| `alert_on_scan_status` | *(empty)* | Comma-separated list of primary_scan_status values to alert on (state mode). Leave empty to disable. Example: connection_refused,invalid_ssl_cert |
| `alert_on_not_live` | `true` | Alert when monitored sites have live=false (state mode). Defaults on - a fully unreachable site has a blank status_code and a primary_scan_status outside the empty-by-default alert_on_scan_status set, so without this a hard-down site produces no state findings at all. Costs one finding per non-live site on every run it stays down |
| `ignore_blank_transitions` | `false` | Suppress alerts for value -> blank and blank -> value transitions. When false, renders blanks as "(no data)" |
| `ignore_transitions` | *(see below)* | Comma-separated list of specific transitions to suppress, format: field:old_value->new_value. Default suppresses transient status flapping |
| `max_changes` | `25` | Maximum number of changes to enumerate in an issue. When exceeded, issue shows summary counts instead of individual lines. Must be a whole number ≥ 1 |
| `labels` | `site-scanning-alert` | Comma-separated list of labels to apply to created issues |
| `issue_title` | `Possible website issues` | Title for alert issues |
| `snapshot_url` | `https://api.gsa.gov/.../site-scanning-latest.csv` | URL of the latest Site Scanning snapshot CSV. Override for testing only |
| `previous_snapshot_url` | `https://api.gsa.gov/.../site-scanning-previous.csv` | URL of the previous Site Scanning snapshot CSV (for change detection). Override for testing only |
| `max_snapshot_age_days` | `3` | Maximum age of the latest snapshot before reporting staleness instead of changes. Must be a whole number ≥ 0 (`0` = under 24 hours old) |
| `token` | `${{ github.token }}` | GitHub token for creating issues. Defaults to github.token (requires permissions.issues: write) |
| `fail_on_alert` | `false` | Whether to fail the workflow when an alert is fired |
| `dry_run` | `false` | When true, render alert to step summary instead of creating an issue |

**Default `ignore_transitions`:** The action suppresses flapping between transient scan statuses by default:
```
primary_scan_status:timeout->execution_context_destroyed
primary_scan_status:timeout->connection_reset
primary_scan_status:timeout->empty_response
primary_scan_status:execution_context_destroyed->timeout
primary_scan_status:connection_reset->timeout
primary_scan_status:empty_response->timeout
primary_scan_status:aborted->timeout
primary_scan_status:http2_error->timeout
```

Transitions to/from `completed` are **not** suppressed — those are the highest-signal changes.

## Understanding Your Alerts

When you receive an alert, here's what each field means and what action to take:

| Field | Meaning | What It Usually Means | Reference |
|-------|---------|----------------------|-----------|
| `live: TRUE -> FALSE` | Site stopped returning a 2xx status code | Real outage or a new block on the scanner. Investigate immediately. | [Data Dictionary](https://github.com/GSA/site-scanning-documentation/blob/main/data/Site_Scanning_Data_Dictionary.csv) |
| `live: TRUE -> (no data)` | Scan couldn't complete at all | Check `primary_scan_status` on the same line for the reason (often `timeout` or `dns_resolution_error`) | |
| `status_code: 200 -> 403` | Now refusing the scanner | Often WAF/bot rules, not a real outage. 3,144 sites sit at 403 steady-state. Verify manually in a browser. | |
| `status_code: 200 -> 503` | Service unavailable | Real problem. Investigate with your hosting team. | |
| `primary_scan_status: completed -> timeout` | Loaded before, didn't finish now | Most common genuine signal (142 of 410 changes/day). Often indicates slow page load or redirect loop. | [Scan Statuses](https://github.com/GSA/site-scanning-documentation/blob/main/pages/scan_statuses.md) |
| `primary_scan_status: completed -> dns_resolution_error` | DNS stopped resolving | Domain expired, DNS misconfiguration, or site taken offline | [Scan Statuses](https://github.com/GSA/site-scanning-documentation/blob/main/pages/scan_statuses.md) |
| `primary_scan_status: completed -> invalid_ssl_cert` | Certificate problem | Check expiration and CN/SAN match | [Scan Statuses](https://github.com/GSA/site-scanning-documentation/blob/main/pages/scan_statuses.md) |
| `no longer in snapshot` | Dropped from the Federal Website Index | Not an outage — index maintenance. Site may have been marked non-public or moved to a non-federal domain | |
| `newly in snapshot` | Added to the Federal Website Index | Not a problem — the watchlist is expanding | |

For detailed remediation guidance on each scan status, see [GSA's Scan Statuses reference](https://github.com/GSA/site-scanning-documentation/blob/main/pages/scan_statuses.md).

## Tuning the Noise

Real-world data (2026-09-02 snapshot): **63% of `live` changes and 62% of `primary_scan_status` changes are artifacts** — value↔blank transitions or transient flapping (`completed`↔`timeout`). The action's defaults suppress the most common noise while preserving genuine signal.

These percentages count *change-detection* findings only, measured under the defaults in force at the time - they have not been recomputed since. `alert_on_not_live` now defaults to `true`, which adds a state-mode finding for every non-live site on every run; that stream isn't reflected in the numbers below.

### Noise by the Numbers

From a typical day's diff of 29,668 sites:

| Metric | Count | Notes |
|--------|-------|-------|
| Total changes (all fields) | 1,332 | Across 117 of 1,396 base domains |
| `live` changes | 457 | 195 →blank, 168 blank→, 94 real |
| `status_code` changes | 465 | 194 →blank, 165 blank→, 106 real |
| `primary_scan_status` changes | 410 | All real values, but 62% is round-trip flapping |
| Noisiest base domain | `sandia.gov` | 373 change-lines/day across 341 rows |
| Quietest (example) | `cpsc.gov` | 0 changes across 22 rows |

### Strategies

**For Model 1 (exact domains):** Default settings work well. Most watchlists see 0-5 change findings/day. One thing to know: because `alert_on_not_live` defaults to `true`, a site sitting at `live=false` produces one state finding on *every* run until it recovers - deliberate, so a hard-down site doesn't go quiet after its day-one change alert, but a chronically non-live domain becomes a permanent line in every findings set. Drop it from the watchlist, or set `alert_on_not_live: 'false'`, if that's noise you don't want.

**For Model 2 (`base:large-agency.gov`):** You'll hit noise. Options:

1. **Raise `max_changes`** (e.g. to `100`) — you'll get a summary instead of enumeration
2. **Enable `ignore_blank_transitions: 'true'`** — cuts volume by ~60% but hides some real outages
3. **Switch to Model 1** — monitor only the 10-20 most critical domains under that base

**Flapping you probably want to ignore:** The default `ignore_transitions` handles the worst offenders. If you see round-trips like `completed`→`timeout`→`completed` daily for the same site, add them:

```yaml
ignore_transitions: 'primary_scan_status:completed->timeout,primary_scan_status:timeout->completed'
```

**Blank transitions (`live: true -> (no data)`):** These often mean "the scanner couldn't reach the site that day" — a genuine signal. Suppressing them (`ignore_blank_transitions: true`) will hide real but intermittent problems.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Workflow ran, no issue, no alerts | Watchlist matches nothing | Check the workflow's step summary for unmatched entries. Verify domains exist in the [Site Scanning target list](https://github.com/GSA/federal-website-index/blob/main/data/site-scanning-target-url-list.csv) |
| "N watchlist entries matched nothing" warning | One or more (but not all) watchlist entries don't match the snapshot | The step summary lists exactly which entries didn't match, even when the rest of your watchlist is monitored fine. Check those entries for typos |
| "Snapshot has not rotated" message | Ran multiple times before 15:00 UTC rotation | Expected behavior. Change detection is skipped for that run, but state-mode checks (if enabled) still run against current data, so an active outage is never missed. The action is idempotent when snapshots haven't changed. |
| HTTP 403 from api.gsa.gov | Rate limit or network policy block | The action retries automatically. Check the workflow log for retry attempts. If persistent, contact GSA or check your org's firewall rules. |
| Issue created but label missing | Label didn't exist in the repo | The action creates the label automatically (requires `permissions: issues: write`). Check that the workflow has this permission. |
| Too many alerts (100+ changes) | Large `base:` watchlist + noisy domain | Raise `max_changes` to get a summary, or switch to exact-domain Model 1 for critical sites only |
| "Snapshot is stale" message | Upstream scanning engine hasn't run | The action reports staleness instead of flooding with change alerts, and files a "data is stale" issue. Check the [Site Scanning engine's workflows](https://github.com/GSA/site-scanning-engine/actions). Once fresh data returns, close the staleness issue manually - the action doesn't auto-comment or auto-close it. |
| Nothing since \<date\> but sites are fine | Snapshot rotation cadence | Snapshots rotate once daily at 15:00 UTC. The action runs at 15:30 UTC to catch the fresh data. |
| A state alert for every non-live site, every single run | `alert_on_not_live` defaults to `true` | Deliberate - a fully unreachable site produces no other finding, so with this off `mode: both` goes silent after the day-one change alert. The cost is a standing finding for as long as the site is down. Remove the domain from the watchlist if it's known-dead, or set `alert_on_not_live: 'false'` to go back to change-only detection for it |
| Empty watchlist warning | `watchlist.txt` has only comments/blanks | Add at least one domain (uncomment an example or add your own) |
| "No alerts this run" | No findings this run | Expected when everything's healthy. In `mode: change`, this can also mean "nothing changed since yesterday" - which is not the same as "recovered" for a sustained outage. Switch to `mode: state` or `mode: both` if you need the action to actively confirm current health rather than only detect transitions. |
| "Invalid `mode`" error, workflow fails | `mode` input misspelled or unsupported | `mode` must be exactly `change`, `state`, or `both`. Fix the typo in the workflow file. |
| "Empty `labels` input" warning | `labels` input overridden to `''` | The action falls back to `site-scanning-alert` and warns, rather than creating a duplicate issue on every run (an empty label list can never match an existing issue). Set `labels` explicitly if you want a different label. |

---

## Setup (Template Instructions)

**This section is for organizations using this repo as a template.** If you cloned or forked this repository to set up monitoring for your own organization, follow these steps:

### Initial Setup

1. **Use this template**
   - Click "Use this template" at the top of this repo
   - Create your repo in your organization's GitHub account
   - Clone it locally

2. **Enable the workflow**
   - Go to the Actions tab in your new repo
   - Click "I understand my workflows, go ahead and enable them"
   - Find "Site Scanning Alerts" in the list and enable it

3. **Configure what to monitor**
   - Edit `watchlist.txt` to list your domains (see [Configuring Your Watchlist](#configuring-your-watchlist))
   - Commit and push

4. **Test it**
   - Go to Actions → "Site Scanning Alerts" → "Run workflow"
   - Check "Dry run" and run it
   - Review the step summary to see what alerts would have been created

5. **Enable for real**
   - Uncheck "Dry run" and run again, or wait for the scheduled run (daily at 15:30 UTC)
   - Check your repo's Issues tab for the first alert

### Customization

Edit `.github/workflows/site-scanning-alerts.yml` to change:
- **Schedule:** The `cron:` line (default: daily at 15:30 UTC)
- **Noise settings:** `ignore_blank_transitions`, `max_changes`, `ignore_transitions`
- **What to watch:** `fields`, `alert_on_status_codes`, `alert_on_not_live`
- **Issue appearance:** `labels`, `issue_title`

See [Configuration Reference](#configuration-reference) for all available options.

### GitHub Token and Permissions

The action uses `${{ github.token }}` by default, which has `issues: write` when you set `permissions: issues: write` in the workflow file (already configured in the template).

**No secrets to create** — the built-in `GITHUB_TOKEN` works because the issue is filed in the same repo the action runs in.

### Delete This Section

Once you've completed setup and your alerts are working, you can delete this "Setup (Template Instructions)" section from your README — it's only useful during initial configuration.

---

## Development / Maintainers

This section is for GSA maintainers of the action itself (not consumers).

### Architecture

- **Language:** Python 3.14+, stdlib only (no pip dependencies)
- **Design:** Composite action (shell runner + Python scripts)
- **Testing:** stdlib `unittest` + CI on every push/PR
- **Docs enforcement:** `test_docs.py` validates input table ↔ `action.yml` parity
- **Lint/format:** `ruff` (pinned in `pyproject.toml`); CI-only, never a runtime dependency

### Running Tests Locally

```bash
cd site-scanning-alert-template
python3 -m unittest discover tests -v
```

### Linting and Formatting

`ruff` handles both lint and format. It is a development dependency only — the
action itself runs on stdlib Python with no install step.

```bash
python3 -m pip install --group dev   # requires pip >= 25.1
ruff check .                         # lint
ruff format --check --diff .         # formatting gate (what CI runs)
ruff check --fix . && ruff format .  # apply fixes
```

pyupgrade (`UP`) is deliberately not enabled: the code targets `typing.List`/
`Optional` rather than builtin generics or PEP 604 unions.

### Running Manually (Dry Run Against Live Data)

```bash
export INPUT_WATCHLIST=watchlist.txt
export INPUT_MODE=both
export INPUT_FIELDS=live,status_code,primary_scan_status
export INPUT_DRY_RUN=true
export INPUT_MAX_CHANGES=25
export GITHUB_STEP_SUMMARY=/tmp/summary.md

python3 scripts/site_scanning_alerts.py
cat /tmp/summary.md
```

### File Layout

```
├── action.yml                        # Composite action definition + input schema
├── pyproject.toml                    # Project metadata + ruff config (dependencies = [] on purpose)
├── watchlist.txt                     # Example watchlist (commented out by default)
├── AGENTS.md                         # Agent-facing constraints and gotchas
├── scripts/
│   ├── site_scanning_alerts.py       # Entrypoint
│   ├── snapshot.py                   # CSV download + filtering + freshness checks
│   ├── rules.py                      # Change-diff + state-check + rendering
│   └── issues.py                     # Fingerprinted issue filing (file-or-skip, no rolling comments)
├── tests/                            # stdlib unittest (83 tests)
│   ├── test_site_scanning_alerts.py  # End-to-end via INPUT_* env + SystemExit codes
│   ├── test_snapshot.py
│   ├── test_rules.py
│   ├── test_issues.py
│   ├── test_docs.py                  # CI enforcement of docs accuracy
│   └── fixtures/                     # Tiny CSVs for tests (dated 2026-09-02)
└── .github/workflows/
    ├── site-scanning-alerts.yml      # Consumer recipe
    └── test.yml                      # CI (tests + docs checks + ruff lint)
```

### Releasing

**First release only:** `.github/workflows/site-scanning-alerts.yml` and this README's quickstart both reference `GSA/site-scanning-alert-template@v1`. That tag does not exist until someone creates it — consumer workflows will fail to resolve the action until the initial `v1` tag is pushed.

1. Merge PR to `main`
2. Tag the release: `git tag v1.x.x && git push origin v1.x.x`
3. Move the `v1` tag: `git tag -f v1 && git push -f origin v1` (on the first release, this creates `v1`; on subsequent releases, it moves it)

Consumers reference `GSA/site-scanning-alert-template@v1` and get the latest v1.x automatically.

### Known Limitations

- **CSV-only:** No JSON snapshot support (JSON is 2.5× larger with zero benefit for diffing)
- **Single repo issues:** Can't file issues cross-repo (by design — simpler token model)
- **No auto-close, no rolling comments:** Each distinct set of findings files its own issue (deduped only against an already-open issue with the identical fingerprint); recovery is reported in the step summary, not on the issue. Triage and closing are manual. This is an intentional MVP tradeoff - a bit more issue-tab noise in exchange for a much simpler, harder-to-break filing path. Revisit if the noise becomes a real problem.
- **No historical trending:** Each alert is independent; no aggregation of "site X has been flapping for 7 days"
- **API unsupported:** Site Scanning's REST API can't filter by `status_code` or `primary_scan_status`, and DEMO_KEY rate-limits at ~6 requests. CSV diff is the only viable approach.

---

## Program Links

- [Site Scanning Program Website](https://digital.gov/site-scanning)
- [API Documentation](https://open.gsa.gov/api/site-scanning-api/)
- [Site Scanning Engine (scan execution)](https://github.com/GSA/site-scanning-engine)
- [Site Scanning Analysis (reporting)](https://github.com/GSA/site-scanning-analysis)
- [Federal Website Index (target list)](https://github.com/GSA/federal-website-index)
- [Central Project Repository](https://github.com/GSA/site-scanning)
- [Site Scanning Documentation](https://github.com/GSA/site-scanning-documentation)
- [Technical Details (all links)](https://digital.gov/guides/site-scanning/technical-details/)

## Feedback

To ask a question or leave feedback about the Site Scanning program, please [file an issue here](https://github.com/GSA/site-scanning/issues) or email site-scanning@gsa.gov.

To report an issue with this action specifically, [file an issue in this repo](https://github.com/GSA/site-scanning-alert-template/issues).
