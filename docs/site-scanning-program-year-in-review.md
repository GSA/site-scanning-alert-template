# Site Scanning Program: Historical Summary and Year in Review

*Prepared from a review of the public issue history at github.com/GSA/site-scanning
(bug-report issues excluded; both open and closed issues reviewed). Citations
are GitHub issue numbers on that repository, included so any claim below can
be independently checked.*

## Why the program exists

Site Scanning maintains the canonical inventory of federal (.gov/.mil) websites
and runs recurring automated scans producing compliance and quality metrics —
USWDS adoption, HTTPS/HSTS enforcement, IPv6 support, analytics (DAP) presence,
accessibility, and third-party service usage (#110–#115, #1082). It publishes
this as a public API and daily/weekly bulk CSV and JSON snapshots
(`api.gsa.gov/technology/site-scanning`), and it holds an Authority to Operate
as a production federal system, not a research prototype (#48, #700, #1505).

The program's mandate is externally driven, not self-assigned: it operationalizes
requirements under OMB memo M-22-09 (federal zero-trust strategy) and is
coordinated with CISA and search.gov as part of the government's shared
approach to managing the .gov web presence (#173). It is funded and renewed
on a recurring contract cycle, and it completed its most recent ATO renewal
this year (#1800, closed 2026-03-19).

## Who actually relies on the data — this is the core justification

The strongest evidence for the program's value isn't traffic numbers (those
aren't visible from the issue board) — it's the number of independent teams
that have built real dependencies on this data and notice, and complain, when
it breaks:

- **OMB/OFCIO** repeatedly directs the program's roadmap: a "Common Web Stack"
  requirements checklist, flagging DOD sites as public, tracking new .mil site
  additions, and a standing tracker of OMB/OFCIO asks (#1378, #1392, #1414,
  #1417). A 2026 OMB data call was populated directly from Site Scanning data
  (#1878).
- **CISA** cross-references its .gov domain registry against the Site Scanning
  inventory; discrepancies get reported by outside contributors as well as
  GSA staff, and a formal CISA–OMB–Site Scanning coordination cadence exists
  (#1379, #1380, #1532, #1565, #1860, #1883).
- **IT Collect / itdashboard.gov** consumes the API directly as "a component
  of our Federal Web Metrics service" powering itdashboard.gov's public
  Federal Website Metrics Report — and flagged an outage when
  `https_enforced`/`hsts` fields silently went null after an internal scan
  action broke (#1383). NSF OCIO independently monitors the same public
  dataset (#1419).
- **digital.gov's DAP team** uses Site Scanning to measure how quickly agencies
  upgrade their analytics tagging, found a detection gap, and proposed the fix
  the program shipped (#1323).
- **NOAA** has become the most active external partner in the last year (see
  below) — reconciling data discrepancies, requesting new fields, and
  proposing to build their own alerting on top of Site Scanning data.
- **Individual federal agencies** self-serve the data for compliance reporting
  (21st Century IDEA / DAP compliance checks filtered by agency, #435, #476)
  and site-owner onboarding requests (#62).

In short: this is infrastructure that OMB, CISA, and at least one other federal
agency's public reporting product are already load-bearing on. If Site Scanning
stopped, itdashboard.gov's public metrics report loses its data source, and
OMB/CISA lose their shared inventory reconciliation mechanism.

## Year in review (September 2025 – September 2026)

**Deepened federal partnership with NOAA.** Roughly 15 issues this year track
a growing NOAA collaboration: reconciling scan discrepancies (DAP detection
mismatches across 20+ noaa.gov subdomains, #1868; DNS/www questions, #1899),
processing NOAA's own "AEO" dataset against Site Scanning's index (8,233 NOAA
rows matched, 5,632 confirmed overlapping live sites, #1932), and a recurring
tracking issue for ongoing threads including office hours on AI-visibility
("aeo/geo") topics (#1846). NOAA is now proposing to build GitHub-Actions-based
alerting on Site Scanning data, explicitly modeling the approach on an existing
open-source template repository maintained by our team, with cross-reference to
NOAA's own internal tracker implementation (#1972). This is a concrete signal
that external agencies see Site Scanning not just as a compliance dashboard but
as infrastructure worth building automation on top of.

**Renewed the program's Authority to Operate** (#1800), keeping the system in
compliant production status.

**Built first-class reliability tooling.** The team stood up its own automated
anomaly detection — GitHub issues auto-filed for empty/null data columns and
row-count anomalies in daily snapshots (#1764, #1772) — and formalized this
into standing CI alerting across the index build, scan enqueueing, and
snapshot-creation pipelines (#1738, #1783), plus a separate developer-notification
mailing list so downstream API/CSV consumers get proactive notice of breaking
changes rather than discovering them the way IT Collect did earlier (#1796).

**Conducted a formal stakeholder needs review.** Published a "persistent support
offerings for stakeholders" reference document (#1716) and began a broader
review of every public-facing sub-property (documentation, analysis tooling,
website index, website inventory, technical-details page), including
identifying a legacy snapshot repository as a deprecation candidate (#1721).

**Advanced a new website inventory capability.** Built and piloted a separate
inventory-harvesting effort that cross-matches agency-published site lists
against .gov/OMB/OPM name registries and produces addition/removal
recommendation reports (#1561–#1646), reaching a "fully onboarded" milestone
(#1830) and engaging a GSA Lab study on rationalizing GSA's own website
inventory (#1853). This effort is now being re-scoped for a second round based
on round-one pilot feedback (#1997, #1995) — active, not abandoned.

**Opened R&D into AI-readiness scanning.** Began exploring how the program
should evolve as agencies adapt sites for AI-agent traffic and AI search
visibility: `agents.txt`/`llms.txt` detection (#1982), AI-element detection
(#1756), and evaluation of tools like Lighthouse's AI-friendliness scoring in
direct collaboration with NOAA (#1936). This positions the program ahead of an
emerging federal compliance need rather than reacting to one after the fact.

## Program health signals worth flagging to leadership

Two stakeholder-facing initiatives (new-field pitches for NOAA/AEO data,
#1948; a stakeholder dashboard update, #1935) were explicitly paused in July
2026 "given leadership changes." This is the one area where continued
executive sponsorship would visibly unblock work that external partners are
actively waiting on.

## Bottom line

The program operationalizes a real federal mandate (OMB M-22-09 zero trust),
is the data source behind at least one other agency's public metrics product
(itdashboard.gov), is actively coordinated with CISA and OMB/OFCIO on a
recurring basis, and has grown its footprint this year through a new,
self-initiated NOAA partnership that is now proposing to build its own
automation on top of our data. The clearest risk to continuity is not
technical — it's stalled stakeholder-facing work waiting on leadership
sponsorship to resume.

---

*Data gap, stated for transparency: no contract dollar figures, staffing
costs, or API/CSV traffic volumes are visible from the public issue board;
budget detail lives in linked internal documents not reviewed here. The case
above rests on named, cited dependencies rather than usage-volume metrics —
if leadership wants a dollar-denominated cost/value case, that would require
pulling the actual contract and hosting-cost figures separately.*
