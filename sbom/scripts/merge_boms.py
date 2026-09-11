#!/usr/bin/env python3
"""
merge_boms.py -- combine several CycloneDX SBOMs into one.

A repository with more than one ecosystem (a Python backend and a
TypeScript frontend, say) produces one SBOM per ecosystem. CERT-In wants a
single SBOM per delivered product, so they have to be merged.

The official `cyclonedx-cli merge` does this too, but it is a separate .NET
binary to install in CI. This is stdlib-only and does the same job for the
shapes the ecosystem generators actually emit.

What it does:
  - concatenates `components`, de-duplicating on purl (or name@version)
  - rewrites the root component so the merged BOM describes the whole product
  - preserves each source BOM's `dependencies` graph, re-pointing every
    sub-root at the new single root so the graph stays connected
  - tags each component with certin:sourceBom so you can tell which
    ecosystem it came from
  - carries `vulnerabilities` through if any input has them

Usage:
  merge_boms.py -o bom.json --name myapp --version 1.2.0 \
      backend.bom.json frontend.bom.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone


def comp_key(c: dict) -> str:
    """Identity for de-duplication."""
    purl = c.get("purl")
    if purl:
        return purl.split("?")[0]
    return str(c.get("name")) + "@" + str(c.get("version"))


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        bom = json.load(f)
    if bom.get("bomFormat") != "CycloneDX":
        print("[merge] ERROR not a CycloneDX BOM: " + path, file=sys.stderr)
        sys.exit(2)
    return bom


def main() -> int:
    ap = argparse.ArgumentParser(description="Merge CycloneDX SBOMs")
    ap.add_argument("inputs", nargs="+", help="input .json BOMs")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--name", default="merged-application",
                    help="name of the merged root component")
    ap.add_argument("--version", default="0.0.0",
                    help="version of the merged root component")
    ap.add_argument("--spec-version", default=None,
                    help="force a specVersion; default = highest among inputs")
    args = ap.parse_args()

    boms = [(p, load(p)) for p in args.inputs]

    # highest spec version wins unless overridden
    spec = args.spec_version
    if not spec:
        seen = [b.get("specVersion", "1.5") for _p, b in boms]
        spec = max(seen, key=lambda s: [int(x) for x in s.split(".")])

    root_ref = "root-" + args.name
    merged: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": args.name,
                "version": args.version,
            },
            "tools": [{"name": "merge_boms.py"}],
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": [],
    }

    seen_keys: dict = {}
    root_children: list = []     # ONLY true direct deps + orphans, never everything
    dep_entries: list = []
    all_refs: list = []          # every kept component's ref
    reached: set = set()         # every ref some dependency entry points at
    dropped = 0

    for path, bom in boms:
        label = path.replace("\\", "/").split("/")[-1]
        sub_root = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")

        for c in (bom.get("components") or []):
            k = comp_key(c)
            if k in seen_keys:
                dropped += 1
                continue
            props = c.setdefault("properties", [])
            if not any(p.get("name") == "certin:sourceBom" for p in props):
                props.append({"name": "certin:sourceBom", "value": label})
            seen_keys[k] = c
            merged["components"].append(c)
            ref = c.get("bom-ref") or c.get("purl")
            if ref:
                all_refs.append(ref)
            # NOTE: deliberately NOT appended to root_children here. An earlier
            # version did, which made every component a direct dependency of
            # the merged root and destroyed the direct/transitive distinction
            # the criticality policy depends on (measured: 27 direct became 652).

        # Keep each input's graph. The input's own root is replaced by the new
        # merged root, so its direct dependencies become the merged root's.
        for d in (bom.get("dependencies") or []):
            ref = d.get("ref")
            targets = d.get("dependsOn") or []
            if ref and sub_root and ref == sub_root:
                root_children.extend(targets)
                reached.update(targets)
                continue
            dep_entries.append(d)
            reached.update(targets)

        for v in (bom.get("vulnerabilities") or []):
            merged["vulnerabilities"].append(v)

    # Orphans: components no edge points at. Happens when a generator emits no
    # graph at all (then ALL its components are orphans, which correctly makes
    # them direct - the same conservative fallback the enricher uses). Attach
    # them to the root so the graph stays connected, but ONLY them.
    orphans = [r for r in all_refs if r not in reached and r not in root_children]
    root_children.extend(orphans)

    merged["dependencies"].append(
        {"ref": root_ref, "dependsOn": list(dict.fromkeys(root_children))})
    merged["dependencies"].extend(dep_entries)
    direct_n = len(dict.fromkeys(root_children))
    print("[merge] direct deps : " + str(direct_n) + " of " + str(len(all_refs))
          + " components (" + str(len(orphans)) + " orphans attached to root)")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)

    print("[merge] inputs      : " + ", ".join(p for p, _ in boms))
    print("[merge] specVersion : " + spec)
    print("[merge] components  : " + str(len(merged["components"]))
          + (" (" + str(dropped) + " duplicates dropped)" if dropped else ""))
    print("[merge] graph       : " + str(len(merged["dependencies"])) + " entries")
    print("[merge] wrote       : " + args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
