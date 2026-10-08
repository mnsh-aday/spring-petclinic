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
import uuid
from datetime import datetime, timezone
from typing import Any

TOOL_VERSION = "1.1.0"



def comp_key(c: dict) -> str:
    """Identity for de-duplication."""
    purl = c.get("purl")
    if purl:
        return purl.split("?")[0]
    return str(c.get("name")) + "@" + str(c.get("version"))


def flatten(components: Any) -> list:
    """Return every component, including ones nested inside others.

    A nested component is still a component that ships in the product. Leaving
    it nested hides it from de-duplication, enrichment and the compliance
    count, so it is lifted to the top level here. Its own `components` key is
    removed once its children have been lifted, and an edge is recorded on the
    parent so the relationship survives in the dependency graph.
    """
    out: list = []

    def walk(lst, parent_ref=None):
        for c in (lst or []):
            if not isinstance(c, dict):
                continue
            children = c.pop("components", None)
            out.append(c)
            ref = c.get("bom-ref") or c.get("purl")
            if children:
                kids = []
                for k in children:
                    if isinstance(k, dict):
                        kr = k.get("bom-ref") or k.get("purl")
                        if kr:
                            kids.append(kr)
                if kids and ref:
                    NESTED_EDGES.append({"ref": ref, "dependsOn": kids})
                walk(children, ref)

    walk(components)
    return out


# Edges recovered from nesting, folded into the merged graph so the
# parent/child relationship is not lost when components are flattened.
NESTED_EDGES: list = []


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

    # Carry forward every generator that contributed. An earlier version
    # replaced the whole tools list with "merge_boms.py", erasing which tool
    # actually produced each half of the SBOM - provenance a reader needs, and
    # which quality scorers check for.
    tools: list = []
    seen_tools: set = set()
    for _p, b in boms:
        t = (b.get("metadata") or {}).get("tools")
        entries = t.get("components", []) if isinstance(t, dict) else (t or [])
        for e in entries:
            if not isinstance(e, dict):
                continue
            key = (e.get("name"), e.get("version"))
            if e.get("name") and key not in seen_tools:
                seen_tools.add(key)
                tools.append({k: v for k, v in e.items()
                              if k in ("vendor", "name", "version", "type")})
    tools.append({"name": "merge_boms.py", "version": TOOL_VERSION,
                  "type": "application"})

    root_ref = "root-" + args.name
    merged: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        # A document identity of its own. Required by CycloneDX and used to
        # tell two SBOMs of the same product apart.
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            # CycloneDX's native field for WHEN in the lifecycle this was taken.
            # CERT-In s3.2 calls the same thing an SBOM "classification".
            "lifecycles": [{"phase": "build"}],
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": args.name,
                "version": args.version,
            },
            "tools": {"components": tools},
            # Licence of the SBOM DOCUMENT itself, not of its contents.
            # CC0 is the convention, matching SPDX's dataLicense.
            "licenses": [{"license": {"id": "CC0-1.0"}}],
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

        # FLATTEN nested components. CycloneDX permits components to contain
        # sub-components, and cyclonedx-npm uses that heavily. Anything left
        # nested is invisible to every later stage: it is never de-duplicated,
        # never enriched, and never counted in the compliance report. Measured
        # on one real SBOM: 114 of 766 components sat nested and received none
        # of the 21 CERT-In fields, while the report claimed full coverage of
        # "652 components". Relationships are preserved in `dependencies`,
        # which is where CycloneDX expects them, so flattening loses nothing.
        for c in flatten(bom.get("components")):
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

    # Edges recovered from flattening, so a parent/child relationship that was
    # expressed by nesting survives as a real graph edge.
    dep_entries.extend(NESTED_EDGES)
    for e in NESTED_EDGES:
        reached.update(e.get("dependsOn") or [])

    # Orphans: components no edge points at. Happens when a generator emits no
    # graph at all (then ALL its components are orphans, which correctly makes
    # them direct - the same conservative fallback the enricher uses). Attach
    # them to the root so the graph stays connected, but ONLY them.
    orphans = [r for r in all_refs if r not in reached and r not in root_children]
    root_children.extend(orphans)

    # PRUNE DANGLING EDGES. De-duplicating components can leave `dependsOn`
    # entries pointing at refs that no longer exist, and entries whose own
    # `ref` was dropped. An independent scorer (sbomqs) counted 767 "components"
    # on a 652-component BOM for exactly this reason - the graph was asserting
    # things that were not there. A reference to a component that does not
    # exist is a false statement in a compliance document.
    known = set(all_refs) | {root_ref}
    pruned_targets = 0
    pruned_entries = 0
    clean_entries = []
    for d in dep_entries:
        if d.get("ref") not in known:
            pruned_entries += 1
            continue
        before = len(d.get("dependsOn") or [])
        d["dependsOn"] = [t for t in (d.get("dependsOn") or []) if t in known]
        pruned_targets += before - len(d["dependsOn"])
        clean_entries.append(d)

    root_children = [r for r in dict.fromkeys(root_children) if r in known]
    merged["dependencies"].append({"ref": root_ref, "dependsOn": root_children})
    merged["dependencies"].extend(clean_entries)
    if pruned_targets or pruned_entries:
        print("[merge] pruned     : " + str(pruned_targets) + " dangling edge(s), "
              + str(pruned_entries) + " orphaned graph entr(ies)")
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
