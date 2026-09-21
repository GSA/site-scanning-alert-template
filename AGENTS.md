# AGENTS.md

GitHub composite action that diffs GSA Site Scanning CSV snapshots and files issues. `README.md` is the user-facing doc (consumer + template-setup + maintainer sections); this file is the agent-facing delta.

## Hard constraints

- **Python 3.14, stdlib only.** CI pins `python-version: '3.14'` (`.github/workflows/test.yml`) and `pyproject.toml` has `dependencies = []`. `action.yml` runs `python3 scripts/site_scanning_alerts.py` directly with **no install step**, so a third-party import would break every consumer at runtime. Local `python3` here is newer (3.14) and will happily accept 3.10+ syntax that CI rejects — avoid `match`, `X | Y` unions, and builtin generics (`list[str]`); use `typing.List`/`Optional` as the existing code does.
- `scripts/` is a flat module dir, not a package. Imports are bare (`from rules import ...`) and both the entrypoint and the tests prepend `scripts/` to `sys.path`. Don't convert to relative imports or add `__init__.py`.
- `rules.py` intentionally re-declares `Row` instead of importing it from `snapshot.py` (keeps the pure-logic module free of `urllib`). Don't "dedupe" it — the reason is in the comment at `scripts/rules.py:12`.

## Commands

```bash
python3 -m unittest discover tests        # full suite, from repo root (83 tests, 1 skipped); pytest -q also works
python3 -m unittest tests.test_docs -v    # docs-parity gate CI runs separately
python3 -m unittest tests.test_rules.TestDedupeAlerts.test_change_wins_over_state_for_same_domain_field
```

No linter, formatter, or typechecker is configured (stray `.ruff_cache/` is local noise, not CI). Don't invent a `lint` step.

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

## Behavior that looks like a bug but isn't

- **No auto-close, no rolling comments.** `file_alert` files a new issue unless an open issue already carries the identical `<!-- site-scanning-alert: stream:fingerprint -->` marker. The fingerprint is a hash of the rendered body, so *any* wording change to `render_alerts` output re-files every currently-open condition as a new issue.
- `file_alert` raises `ValueError` on empty `labels` (an empty label list makes the dedupe lookup unable to ever match). The caller resolves a fallback via `_resolve_labels` before calling it.
- `mode` is validated before any network I/O and hard-fails on an unknown value rather than silently skipping both evaluators.
- A stalled snapshot rotation skips change detection but **still runs state checks** — regression-tested in `tests/test_site_scanning_alerts.py`. Don't short-circuit the whole run there.
- `run()` exits the process at every terminal point (`NoReturn`); `main()` wraps it for `SnapshotError`. Tests drive `main()` through the real `INPUT_*` env interface and assert on `SystemExit` codes plus `GITHUB_STEP_SUMMARY` contents, so new exit paths need a step-summary message.
- Defaults deliberately suppress transient `primary_scan_status` flapping (`ignore_transitions` in `action.yml`), but never transitions involving `completed`.
