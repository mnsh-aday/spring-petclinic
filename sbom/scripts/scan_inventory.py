#!/usr/bin/env python3
"""
scan_inventory.py -- nightly vulnerability sweep over a folder of SBOMs.

This is the "continuous" half of the CERT-In obligation, without a server.
Every product repository publishes its SBOM into one inventory repository;
this script runs there on a schedule, re-checks every stored SBOM against
freshly published advisories, and reports only what CHANGED.

Why only what changed: a first run over a real estate returns hundreds of
advisories. Mailing that same list every night trains everyone to ignore it.
State is kept in a JSON file committed alongside the SBOMs, so "new since
yesterday" is a fact rather than a guess.

No build runs here. Nothing is compiled. It reads files and queries OSV by
package identifier, so the whole estate is swept in minutes regardless of how
many languages it spans.

Usage:
  scan_inventory.py --inventory sboms/ --state scan-state.json \
      --out-report report.md --out-summary summary.md [--fail-on critical]

Exit codes:
  0  completed (findings may exist; see --fail-on to change this)
  1  --fail-on threshold met by a NEW finding
  2  could not run (no SBOMs found, state unreadable)
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
BATCH_SIZE = 500
HTTP_TIMEOUT = 60

SEV_ORDER = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}
SEV_LABEL = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "unknown"}


def log(msg: str) -> None:
    print("[scan] " + msg, file=sys.stderr)


def http_json(url: str, payload: Any = None) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"User-Agent": "certin-scan-inventory/1.0"}
    if data:
        headers["Content-Type"] = "application/json"
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:
            if attempt == 2:
                log("WARNING request failed after 3 tries: " + str(e))
                return None
            time.sleep(2 * (attempt + 1))
    return None


def parse_purl_version(purl: str) -> Any:
    """Version segment of a PURL, or None. No version means unscannable."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl.split("#")[0].split("?")[0]
    if "@" not in body:
        return None
    v = body.rsplit("@", 1)[1]
    return urllib.parse.unquote(v) or None


def load_inventory(folder: str) -> tuple:
    """-> (components_by_purl, project_meta, unscannable)

    components_by_purl maps a PURL to the set of projects containing it, so
    one query answers for every project at once.
    """
    by_purl: dict = defaultdict(set)
    names: dict = {}
    projects: dict = {}
    unscannable: dict = defaultdict(list)

    files = sorted(glob.glob(os.path.join(folder, "**", "*.json"), recursive=True))
    if not files:
        return {}, {}, {}, {}

    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                bom = json.load(fh)
        except Exception as e:
            log("WARNING skipping unreadable " + f + ": " + str(e))
            continue
        if bom.get("bomFormat") != "CycloneDX":
            log("WARNING skipping non-CycloneDX " + f)
            continue

        md = bom.get("metadata") or {}
        root = md.get("component") or {}
        project = root.get("name") or os.path.splitext(os.path.basename(f))[0]
        projects[project] = {
            "file": os.path.relpath(f, folder).replace(os.sep, "/"),
            "version": root.get("version"),
            "timestamp": md.get("timestamp"),
            "components": len(bom.get("components") or []),
        }

        for c in (bom.get("components") or []):
            purl = c.get("purl")
            label = ((str(c.get("group")) + "/") if c.get("group") else "") \
                + str(c.get("name")) + "@" + str(c.get("version"))
            if not purl or not parse_purl_version(purl):
                unscannable[project].append(label)
                continue
            key = purl.split("?")[0]
            by_purl[key].add(project)
            names.setdefault(key, label)

    return dict(by_purl), names, projects, dict(unscannable)


def query_osv(purls: list) -> dict:
    """-> {purl: [advisory ids]} for everything with a known advisory."""
    hits: dict = {}
    for i in range(0, len(purls), BATCH_SIZE):
        chunk = purls[i:i + BATCH_SIZE]
        res = http_json(OSV_BATCH,
                        {"queries": [{"package": {"purl": p}} for p in chunk]})
        if not res:
            continue
        for purl, entry in zip(chunk, res.get("results", [])):
            ids = [v.get("id") for v in (entry.get("vulns") or []) if v.get("id")]
            if ids:
                hits[purl] = ids
        log("queried " + str(min(i + BATCH_SIZE, len(purls))) + "/" + str(len(purls)))
        time.sleep(0.2)
    return hits


def advisory_detail(vid: str, cache: dict) -> dict:
    if vid in cache:
        return cache[vid]
    d = http_json(OSV_VULN + urllib.parse.quote(vid)) or {}
    sev = "unknown"
    db = d.get("database_specific") or {}
    if db.get("severity"):
        sev = str(db["severity"]).lower()
    fixed = set()
    for aff in (d.get("affected") or []):
        for rng in (aff.get("ranges") or []):
            for ev in (rng.get("events") or []):
                if ev.get("fixed"):
                    fixed.add(str(ev["fixed"]))
    # CVE aliases matter: CERT-In field 8 asks for CVE identifiers, and OSV
    # returns its own ids (GHSA-...) with the CVE as an alias.
    cves = [a for a in (d.get("aliases") or []) if str(a).startswith("CVE-")]
    out = {
        "id": vid,
        "summary": str(d.get("summary") or "")[:300],
        "severity": sev,
        "fixed": sorted(fixed),
        "cves": cves,
        "url": "https://osv.dev/vulnerability/" + vid,
    }
    cache[vid] = out
    return out


def load_state(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {"generated": None, "findings": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            s = json.load(f)
        if not isinstance(s.get("findings"), dict):
            raise ValueError("malformed")
        return s
    except Exception as e:
        log("WARNING state unreadable (" + str(e) + "); treating every finding as new")
        return {"generated": None, "findings": {}}


def main() -> int:
    ap = argparse.ArgumentParser(description="Nightly OSV sweep over stored SBOMs")
    ap.add_argument("--inventory", required=True, help="folder of CycloneDX SBOMs")
    ap.add_argument("--state", default="scan-state.json")
    ap.add_argument("--out-report", help="full report (markdown)")
    ap.add_argument("--out-summary", help="short summary for an issue/email body")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                    help="exit 1 if a NEW finding is at or above this severity")
    ap.add_argument("--no-state-write", action="store_true",
                    help="dry run: report but do not update the state file")
    args = ap.parse_args()

    by_purl, names, projects, unscannable = load_inventory(args.inventory)
    if not projects:
        log("ERROR no CycloneDX SBOMs found under " + args.inventory)
        return 2

    n_unscannable = sum(len(v) for v in unscannable.values())
    log(str(len(projects)) + " project(s), " + str(len(by_purl))
        + " unique packages"
        + ((", " + str(n_unscannable) + " unscannable (no version)")
           if n_unscannable else ""))

    hits = query_osv(sorted(by_purl))
    cache: dict = {}

    # current findings, keyed project|purl|advisory so a diff is exact
    current: dict = {}
    for purl, ids in hits.items():
        for vid in ids:
            det = advisory_detail(vid, cache)
            for project in sorted(by_purl[purl]):
                current[project + "|" + purl + "|" + vid] = {
                    "project": project,
                    "package": names.get(purl, purl),
                    "purl": purl,
                    "id": vid,
                    "cves": det["cves"],
                    "severity": det["severity"],
                    "fixed": det["fixed"],
                    "summary": det["summary"],
                    "url": det["url"],
                }

    prev = load_state(args.state)
    prev_keys = set(prev.get("findings") or {})
    new_keys = sorted(set(current) - prev_keys)
    gone_keys = sorted(prev_keys - set(current))
    first_run = prev.get("generated") is None

    log(("first run - " if first_run else "")
        + str(len(current)) + " finding(s) total, "
        + str(len(new_keys)) + " new, " + str(len(gone_keys)) + " resolved")

    worst_new = max((SEV_ORDER.get(current[k]["severity"], 0) for k in new_keys),
                    default=0)

    # ---------------- report ----------------
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    by_project: dict = defaultdict(list)
    for k in new_keys:
        by_project[current[k]["project"]].append(current[k])

    lines = ["# Nightly SBOM vulnerability sweep", "",
             "- Run: " + now,
             "- Projects scanned: **" + str(len(projects)) + "**",
             "- Unique packages checked: **" + str(len(by_purl)) + "**",
             "- Findings total: **" + str(len(current)) + "**",
             "- **New since last run: " + str(len(new_keys)) + "**",
             "- Resolved since last run: " + str(len(gone_keys)), ""]
    if first_run:
        lines += ["> First run: every finding below is reported as new. "
                  "Subsequent runs report only genuine changes.", ""]
    if n_unscannable:
        lines += ["> **" + str(n_unscannable) + " component(s) carry no version** "
                  "and cannot be matched against any vulnerability database. "
                  "Absence of findings for those is not evidence of safety.", ""]

    if new_keys:
        lines += ["## New findings", ""]
        for project in sorted(by_project):
            rows = sorted(by_project[project],
                          key=lambda r: -SEV_ORDER.get(r["severity"], 0))
            lines += ["### " + project, "",
                      "| Severity | Package | Advisory | Fix available |",
                      "|---|---|---|---|"]
            for r in rows:
                ident = ", ".join(r["cves"]) if r["cves"] else r["id"]
                fix = ("upgrade to >= " + r["fixed"][-1]) if r["fixed"] else "none published"
                lines.append("| " + r["severity"] + " | `" + r["package"] + "` | ["
                             + ident + "](" + r["url"] + ") | " + fix + " |")
            lines.append("")
    else:
        lines += ["## No new findings", "",
                  "Nothing has appeared since the last sweep.", ""]

    if gone_keys:
        lines += ["## Resolved since last run", ""]
        for k in gone_keys[:40]:
            r = prev["findings"][k]
            lines.append("- `" + str(r.get("package")) + "` in **"
                         + str(r.get("project")) + "** - " + str(r.get("id")))
        if len(gone_keys) > 40:
            lines.append("- ... and " + str(len(gone_keys) - 40) + " more")
        lines.append("")

    lines += ["## Projects in the inventory", "",
              "| Project | Components | SBOM generated |", "|---|---|---|"]
    for p in sorted(projects):
        m = projects[p]
        lines.append("| " + p + " | " + str(m["components"]) + " | "
                     + str(m["timestamp"] or "unknown") + " |")

    report = "\n".join(lines) + "\n"
    if args.out_report:
        with open(args.out_report, "w", encoding="utf-8") as f:
            f.write(report)
        log("wrote " + args.out_report)

    if args.out_summary:
        head = (str(len(new_keys)) + " new vulnerability finding(s) across "
                + str(len(set(r["project"] for r in by_project.values() for r in r)))
                if new_keys else "No new vulnerability findings")
        s = ["**" + ("" if new_keys else "")
             + str(len(new_keys)) + " new finding(s)** across "
             + str(len(by_project)) + " project(s) - sweep of "
             + str(len(projects)) + " project(s), " + now, ""]
        for project in sorted(by_project):
            rows = sorted(by_project[project],
                          key=lambda r: -SEV_ORDER.get(r["severity"], 0))[:5]
            s.append("**" + project + "**")
            for r in rows:
                ident = ", ".join(r["cves"]) if r["cves"] else r["id"]
                s.append("- `" + r["package"] + "` - " + r["severity"] + " - " + ident)
            extra = len(by_project[project]) - len(rows)
            if extra > 0:
                s.append("- ... and " + str(extra) + " more")
            s.append("")
        with open(args.out_summary, "w", encoding="utf-8") as f:
            f.write("\n".join(s) + "\n")
        log("wrote " + args.out_summary)

    # ---------------- state ----------------
    if not args.no_state_write:
        state = {
            "generated": now,
            "projects": projects,
            "findings": current,
        }
        os.makedirs(os.path.dirname(os.path.abspath(args.state)) or ".",
                    exist_ok=True)
        with open(args.state, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=1, sort_keys=True)
        log("wrote " + args.state)

    # GitHub Actions outputs, when running there
    gh = os.environ.get("GITHUB_OUTPUT")
    if gh:
        with open(gh, "a", encoding="utf-8") as f:
            f.write("new_count=" + str(len(new_keys)) + "\n")
            f.write("total_count=" + str(len(current)) + "\n")
            f.write("worst_new=" + SEV_LABEL.get(worst_new, "none") + "\n")
            f.write("has_new=" + ("1" if new_keys else "0") + "\n")
            f.write("projects=" + str(len(projects)) + "\n")

    if args.fail_on and worst_new >= SEV_ORDER[args.fail_on]:
        log("FAIL new finding at or above " + args.fail_on)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
