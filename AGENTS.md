# AGENTS.md

GitHub composite action that diffs GSA Site Scanning CSV snapshots and files issues. `README.md` is the user-facing doc (consumer + template-setup + maintainer sections); this file is the agent-facing delta.

## Hard constraints

- **Python 3.14, stdlib only.** CI pins `python-version: '3.14'` (`.github/workflows/test.yml`) and `pyproject.toml` has `dependencies = []`. `action.yml` runs `python3 scripts/site_scanning_alerts.py` directly with **no install step**, so a third-party import would break every consumer at runtime. Local `python3` here is **older** (3.11) than CI (3.14), the opposite of what you'd assume — new-syntax features that CI accepts can be a local `SyntaxError`. Avoid `match`, `X | Y` unions, and builtin generics (`list[str]`); use `typing.List`/`Optional` as the existing code does. This also covers PEP 758 (parens now optional around multiple exception types, e.g. `except A, B:`) — `ruff format` will happily emit that for `target-version = "py314"`, but it doesn't parse below 3.14; the one spot where this came up is pinned with `# fmt: skip` in `scripts/snapshot.py`.
- **CI installing ruff does not relax the stdlib-only rule.** The `lint` job in `test.yml` is the only `pip install` in this repo; it runs in a throwaway runner and installs from `[dependency-groups]`, which consumers never see. The `test` job still runs on a bare interpreter *deliberately* — that's what catches an accidental third-party import in `scripts/`. Don't add a `pip install` to the `test` job or to `action.yml`.
- **Multi-line signatures and collection literals carry a trailing comma on purpose.** That's `ruff format`'s magic trailing comma — it's what keeps them exploded one-per-line. Delete the comma and the next format run collapses the construct onto one line.
- `scripts/` is a flat module dir, not a package. Imports are bare (`from rules import ...`) and both the entrypoint and the tests prepend `scripts/` to `sys.path`. Don't convert to relative imports or add `__init__.py`.
- `rules.py` intentionally re-declares `Row` instead of importing it from `snapshot.py` (keeps the pure-logic module free of `urllib`). Don't "dedupe" it — the reason is in the comment at `scripts/rules.py:12`.

## Commands

```bash
python3 -m unittest discover tests        # full suite, from repo root (83 tests, 1 skipped); pytest -q also works
python3 -m unittest tests.test_docs -v    # docs-parity gate CI runs separately
python3 -m unittest tests.test_rules.TestDedupeAlerts.test_change_wins_over_state_for_same_domain_field

ruff check .                              # lint (same as CI)
ruff format --check --diff .              # formatting gate (same as CI)
ruff check --fix . && ruff format .       # apply both

# No ruff locally? These need no venv and self-check the pin:
uvx ruff@0.16.8 check .
pipx run ruff==0.16.8 check .
```

**Lint and format with ruff** (pinned in `pyproject.toml` → `[dependency-groups].dev`; `[tool.ruff] required-version` rejects a mismatched local install). CI runs it as a separate `lint` job in `.github/workflows/test.yml`. Quotes are **uniformly double** — `ruff format` normalizes them, so don't hand-write single quotes. `UP` (pyupgrade) is **not** selected on purpose: it would rewrite the `typing.List`/`Optional` convention above. If you enable it you must ignore `UP006/UP007/UP035/UP037/UP045/UP046/UP047`. `E402` is per-file-ignored in the 5 files that `sys.path.insert` before importing. No typechecker — the code is fully annotated but the flat, non-package `scripts/` layout and untyped `Dict` GitHub API responses would push `mypy --strict` toward ~150 errors, most of them test-boilerplate; not worth it here.

Local end-to-end run against fixtures (no network, no GitHub):

```bash
printf 'test1.gov\nbase:test4.gov\n' > /tmp/wl.txt
INPUT_WATCHLIST=/tmp/wl.txt INPUT_DRY_RUN=true INPUT_MAX_SNAPSHOT_AGE_DAYS=3650 \
  INPUT_SNAPSHOT_URL="file://$PWD/tests/fixtures/latest.csv" \
  INPUT_PREVIOUS_SNAPSHOT_URL="file://$PWD/tests/fixtures/previous.csv" \
  GITHUB_STEP_SUMMARY=/tmp/summary.md python3 scripts/site_scanning_alerts.py
```

Fixtures are dated `2026-09-02`, so any run using them needs `INPUT_MAX_SNAPSHOT_AGE_DAYS` cranked up or the freshness check short-circuits the run. The repo's own `watchlist.txt` is comments-only on purpose — a plain dry run exits 0 with "Watchlist is empty".

## Docs and workflow files are test-enforced

`tests/test_docs.py` fails CI on documentation drift. Treat these as code:

- Every `action.yml` input must appear in the README "Configuration Reference" table as `` `input_name` ``, and vice versa. Adding one input means touching **five** places: `action.yml` `inputs:`, `action.yml` `env: INPUT_*`, `Config` in `scripts/site_scanning_alerts.py`, `read_config()`, and the README table.
- The README quickstart YAML block must stay indented **exactly 3 spaces** (the test strips a 3-space prefix) and must keep `permissions:` / `issues: write` / `contents: read` / `concurrency:` / `group: site-scanning-alerts-` / `cancel-in-progress: false` so the block is copy/paste-safe at column 1.
- Relative README links must resolve to real paths.
- `.github/workflows/site-scanning-alerts.yml` must keep a **top-level** `concurrency:` block with `cancel-in-progress: false`, positioned before `jobs:`. It exists because `find_open_issue` + `create_issue` is a non-atomic find-then-create; removing it fails `TestWorkflowConcurrency`.
- **Don't point a whitespace stripper or YAML formatter at `README.md`, `action.yml`, or `.github/workflows/*.yml`.** `test_docs.py` asserts on literal formatting: the quickstart block's exact 3-space indent, and `site-scanning-alerts.yml`'s top-level `concurrency:` ordering via `index('\njobs:')`. Ruff is Python-only and safe; generic pre-commit hooks like `trailing-whitespace`/`end-of-file-fixer` are not, which is why pre-commit isn't configured.

## Behavior that looks like a bug but isn't

- **No auto-close, no rolling comments.** `file_alert` files a new issue unless an open issue already carries the identical `<!-- site-scanning-alert: stream:fingerprint -->` marker. The fingerprint is a hash of the rendered body, so *any* wording change to `render_alerts` output re-files every currently-open condition as a new issue.
- `file_alert` raises `ValueError` on empty `labels` (an empty label list makes the dedupe lookup unable to ever match). The caller resolves a fallback via `_resolve_labels` before calling it.
- `mode` is validated before any network I/O and hard-fails on an unknown value rather than silently skipping both evaluators.
- A stalled snapshot rotation skips change detection but **still runs state checks** — regression-tested in `tests/test_site_scanning_alerts.py`. Don't short-circuit the whole run there.
- `run()` exits the process at every terminal point (`NoReturn`); `main()` wraps it for `SnapshotError`. Tests drive `main()` through the real `INPUT_*` env interface and assert on `SystemExit` codes plus `GITHUB_STEP_SUMMARY` contents, so new exit paths need a step-summary message.
- Defaults deliberately suppress transient `primary_scan_status` flapping (`ignore_transitions` in `action.yml`); separately, `report_recoveries: 'false'` suppresses good-direction transitions via `_is_recovery` in `scripts/rules.py`, consulted from `_should_ignore_change`. `ignore_transitions` itself never enumerates a transition into `completed` - the direction-aware predicate handles those instead, which is why `completed → timeout` still alerts while `timeout → completed` does not by default. Any field the action has no direction knowledge for (custom `fields` like `https_enforced`, `hsts`) is never a recovery and is always reported. A recovery, if reported, files its own new issue - it does not close the original.
- `alert_on_not_live` defaults to `true` on purpose: a fully unreachable site has `live=false`, a blank `status_code`, and a `primary_scan_status` outside the empty-by-default `alert_on_scan_status` set, so with it off `mode: both` produces zero state alerts and goes silent after the day-one change alert. `_env_flag` takes an explicit `default` argument for this reason - the Python-side default in `read_config()` must match `action.yml`'s, since the local dry-run recipe below invokes the script directly and bypasses `action.yml` entirely.
- Consequence of the above: on day 1 of an outage the rendered body carries the change alert (`live: true → false`); from day 2 it carries only the state alert (`live: false (current value)`) once `dedupe_alerts` no longer has a change alert to collapse it into. Different bodies fingerprint differently, so a sustained outage files two issues at onset and then stays stable - not a bug, see the no-auto-close bullet above.
- `IssueClient._request` decides retries by method: a GET retries 5xx, rate limits (429 / secondary-rate-limit 403), and network errors, but a POST retries **only** rate limits. A 5xx or `URLError`/`TimeoutError` on a POST may arrive after GitHub already applied the write, so a retried `POST /issues` would file a duplicate issue; rate limits are rejected before any work is done. The `f"... HTTP {e.code} - {body}"` message shape is load-bearing: `ensure_label` sniffs `"HTTP 404"` out of it.
