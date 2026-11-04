#!/usr/bin/env python3
"""
validate_bom.py -- fail if a CycloneDX JSON file is not schema-valid.

Strict validation against the official CycloneDX schema for the file's own
specVersion, plus the referential checks the schema cannot express (every
dependsOn / affects ref must name a component that exists).

Without this step an enrichment bug shipped a bom.certin.json with 25 schema
errors ("moderate" severities, LicenseRef in license.id) and nothing noticed.

Needs: pip install "cyclonedx-python-lib[json-validation]"
Usage: validate_bom.py bom.json bom.certin.json
"""
from __future__ import annotations

import json
import sys

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator


def check(path: str) -> int:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    bom = json.loads(raw)
    spec = str(bom.get("specVersion") or "1.6")
    try:
        sv = SchemaVersion.from_version(spec)
    except Exception:
        print("[validate] " + path + ": unsupported specVersion " + spec)
        return 1
    errs = JsonStrictValidator(sv).validate_str(raw, all_errors=True)
    errs = list(errs) if errs else []
    for e in errs[:25]:
        d = e.data
        print("[validate] " + path + ": " + str(d.message)[:200]
              + " at /" + "/".join(str(p) for p in d.absolute_path))

    # Nested components (cyclonedx-npm emits them) are components too.
    refs: set = set()
    stack = list(bom.get("components") or [])
    root_comp = (bom.get("metadata") or {}).get("component") or {}
    stack.append(root_comp)
    while stack:
        c = stack.pop()
        if isinstance(c, dict):
            if c.get("bom-ref"):
                refs.add(c["bom-ref"])
            stack.extend(c.get("components") or [])
    for s in (bom.get("services") or []):
        if isinstance(s, dict) and s.get("bom-ref"):
            refs.add(s["bom-ref"])
    bad = []
    for d in (bom.get("dependencies") or []):
        for r in [d.get("ref")] + list(d.get("dependsOn") or []):
            if r not in refs:
                bad.append("dependency ref " + str(r))
    for v in (bom.get("vulnerabilities") or []):
        for a in (v.get("affects") or []):
            if a.get("ref") not in refs:
                bad.append("vulnerability " + str(v.get("id")) + " affects " + str(a.get("ref")))
    for b in bad[:25]:
        print("[validate] " + path + ": dangling " + b)

    n = len(errs) + len(bad)
    print("[validate] " + path + ": CycloneDX " + spec + " - "
          + ("OK" if n == 0 else str(len(errs)) + " schema error(s), "
             + str(len(bad)) + " dangling ref(s)"))
    return 1 if n else 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    return 1 if any([check(p) for p in sys.argv[1:]]) else 0


if __name__ == "__main__":
    sys.exit(main())
