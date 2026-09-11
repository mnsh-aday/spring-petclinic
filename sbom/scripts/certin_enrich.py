#!/usr/bin/env python3
"""
certin_enrich.py -- turn a generic CycloneDX SBOM into a CERT-In compliant one.

CERT-In "Technical Guidelines on SBOM" v1.0 (03.10.2024) section 4.2 mandates 21
data fields per component. Standard generators (Syft, cdxgen, cyclonedx-*) emit
roughly half. This script fills the rest from three sources, in priority order:

  1. What the generator already produced        (never overwritten)
  2. Curated metadata file                      (human-owned judgement fields)
  3. Derived / looked-up                        (endoflife.date, deps.dev, heuristics)

It then VALIDATES coverage and exits non-zero when required fields are missing,
so CERT-In compliance is enforced by CI rather than assumed.

Usage:
  certin_enrich.py -i sbom.cdx.json -o sbom.certin.cdx.json \
      -m sbom-metadata.yml \
      --vulns dependency-check-report.json \
      --report certin-compliance.md \
      [--offline] [--fail-on-missing name,version,uniqueId,license,supplier]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

PROP_NS = "certin"
HTTP_TIMEOUT = 8

# ---------------------------------------------------------------------------
# The 21 CERT-In section 4.2 data fields, and where each lives in CycloneDX.
# key -> (human label, accessor kind, locator)
# ---------------------------------------------------------------------------
CERTIN_FIELDS: "OrderedDict[str, tuple]" = OrderedDict([
    ("name",              ("Component Name",         "native",  "name")),
    ("version",           ("Component Version",      "native",  "version")),
    ("description",       ("Component Description",  "native",  "description")),
    ("supplier",          ("Component Supplier",     "native",  "supplier")),
    ("license",           ("Component License",      "native",  "licenses")),
    ("origin",            ("Component Origin",       "prop",    "origin")),
    ("dependencies",      ("Component Dependencies", "bomwide", "dependencies")),
    ("vulnerabilities",   ("Vulnerabilities",        "bomwide", "vulnerabilities")),
    ("patchStatus",       ("Patch Status",           "prop",    "patchStatus")),
    ("releaseDate",       ("Release Date",           "prop",    "releaseDate")),
    ("eolDate",           ("End-of-Life Date",       "prop",    "eolDate")),
    ("criticality",       ("Criticality",            "prop",    "criticality")),
    ("usageRestrictions", ("Usage Restrictions",     "prop",    "usageRestrictions")),
    ("hashes",            ("Checksums or Hashes",    "native",  "hashes")),
    ("comments",          ("Comments or Notes",      "prop",    "comments")),
    ("sbomAuthor",        ("Author of SBOM Data",    "bomwide", "metadata.authors")),
    ("timestamp",         ("Timestamp",              "bomwide", "metadata.timestamp")),
    ("executable",        ("Executable Property",    "prop",    "executable")),
    ("archive",           ("Archive Property",       "prop",    "archive")),
    ("structured",        ("Structured Property",    "prop",    "structured")),
    ("uniqueId",          ("Unique Identifier",      "native",  "purl")),
])

ARCHIVE_EXT = (".jar", ".war", ".ear", ".zip", ".tar", ".tar.gz", ".tgz",
               ".whl", ".egg", ".nupkg", ".gem", ".apk", ".aar", ".crate")
EXEC_EXT = (".exe", ".sh", ".bat", ".cmd", ".bin", ".ps1", ".dll", ".so", ".dylib")

# PURL name fragment -> endoflife.date product slug. High-confidence only.
EOL_SLUGS = {
    "tomcat": "tomcat", "postgresql": "postgresql", "mysql": "mysql",
    "nginx": "nginx", "redis": "redis", "mongodb": "mongodb",
    "spring-boot": "spring-boot", "spring-framework": "spring-framework",
    "django": "django", "flask": "flask", "rails": "rails", "laravel": "laravel",
    "nodejs": "nodejs", "python": "python", "openjdk": "java",
    "kubernetes": "kubernetes", "elasticsearch": "elasticsearch",
    "rabbitmq": "rabbitmq", "kafka": "apache-kafka", "angular": "angular",
    "react": "react", "vue": "vue", "log4j": "log4j",
}

# PURL type -> deps.dev system name
DEPSDEV_SYS = {"maven": "MAVEN", "npm": "NPM", "pypi": "PYPI",
               "golang": "GO", "cargo": "CARGO", "nuget": "NUGET"}


# cyclonedx-py emits PyPI trove classifiers, not SPDX ids, so without this
# every Python package lands in the "needs legal review" queue. Where a
# classifier does not name the exact variant (plain "BSD License" could be
# 2- or 3-clause) it maps to a LicenseRef that records the RISK honestly
# rather than guessing a specific identifier.
CLASSIFIER_TO_SPDX = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "LicenseRef-PyPI-BSD-unspecified",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)": "MPL-1.1",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)":
        "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)":
        "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)":
        "LGPL-2.1-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)":
        "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)":
        "LGPL-3.0-or-later",
    "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)":
        "LicenseRef-PyPI-LGPL-unspecified",
    "License :: OSI Approved :: GNU Affero General Public License v3":
        "AGPL-3.0-only",
    "License :: OSI Approved :: Zope Public License": "ZPL-2.1",
    "License :: OSI Approved :: Academic Free License (AFL)": "AFL-3.0",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: Public Domain": "CC0-1.0",
}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def log(msg: str) -> None:
    print("[certin] " + msg, file=sys.stderr)


def http_json(url: str) -> Any:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "certin-enrich/1.0",
                          "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def parse_purl(purl: Any) -> dict:
    """Minimal PURL parser: pkg:type/ns/name@version?quals#subpath"""
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return {}
    body = purl[4:]
    subpath = None
    if "#" in body:
        body, subpath = body.split("#", 1)
    quals = None
    if "?" in body:
        body, quals = body.split("?", 1)
    version = None
    if "@" in body:
        body, version = body.rsplit("@", 1)
    parts = body.split("/")
    ptype = parts[0] if parts else None
    name = parts[-1] if len(parts) > 1 else None
    ns = "/".join(parts[1:-1]) if len(parts) > 2 else None
    # PURL segments are percent-encoded; npm scopes arrive as %40angular.
    # Without decoding, registry URLs 404 and suppliers read "%40angular".
    dec = urllib.parse.unquote
    return {"type": ptype,
            "namespace": dec(ns) if ns else None,
            "name": dec(name) if name else None,
            "version": dec(version) if version else None,
            "qualifiers": quals, "subpath": subpath}


def get_props(comp: dict) -> dict:
    out = {}
    for p in comp.get("properties", []) or []:
        if isinstance(p, dict):
            out[p.get("name")] = p.get("value")
    return out


def set_prop(comp: dict, key: str, value: Any, overwrite: bool = False) -> None:
    if value is None or value == "":
        return
    name = PROP_NS + ":" + key
    props = comp.setdefault("properties", [])
    for p in props:
        if p.get("name") == name:
            if overwrite or not p.get("value"):
                p["value"] = str(value)
            return
    props.append({"name": name, "value": str(value)})


def comp_keys(comp: dict) -> list:
    """All identifiers a curated-metadata entry may be keyed by."""
    keys = []
    purl = comp.get("purl")
    if purl:
        keys.append(purl)
        base = purl.split("?")[0].split("#")[0]
        keys.append(base)
        if "@" in base:
            keys.append(base.rsplit("@", 1)[0])   # version-agnostic
    name = comp.get("name")
    ver = comp.get("version")
    if name:
        if ver:
            keys.append(str(name) + "@" + str(ver))
        keys.append(str(name))
    ref = comp.get("bom-ref")
    if ref:
        keys.append(str(ref))
    return list(dict.fromkeys(keys))


# ---------------------------------------------------------------------------
# enrichment sources
# ---------------------------------------------------------------------------
def load_curated(path: Any) -> dict:
    if not path:
        return {}
    if not os.path.exists(path):
        log("WARNING curated metadata not found: " + str(path))
        return {}
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    if str(path).endswith((".yml", ".yaml")):
        try:
            import yaml
        except ImportError:
            log("ERROR pyyaml not installed. Run: pip install pyyaml "
                "(or supply metadata as .json)")
            sys.exit(2)
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    data = data or {}
    index = {}
    for entry in (data.get("components") or []):
        if not isinstance(entry, dict):
            continue
        for k in ("purl", "match", "name"):
            if entry.get(k):
                index[str(entry[k])] = entry
    return {"defaults": data.get("defaults") or {},
            "project": data.get("project") or {},
            "index": index}


def load_npm_hashes(paths: list) -> dict:
    """package-lock.json -> {"name@version": [CycloneDX hash dicts]}

    CERT-In field 14 (Checksums or Hashes) comes back empty from every
    generator we tested, yet npm lockfiles carry an `integrity` value for
    every package. It is Subresource-Integrity format - "sha512-<base64>" -
    so it needs decoding to the hex CycloneDX expects.

    Covers lockfile v2/v3 (`packages`) and v1 (`dependencies`).
    """
    import base64
    alg_map = {"sha1": "SHA-1", "sha256": "SHA-256",
               "sha384": "SHA-384", "sha512": "SHA-512"}
    out: dict = {}

    def integrity_to_hashes(integrity: str) -> list:
        hashes = []
        for part in str(integrity).split():
            if "-" not in part:
                continue
            alg, b64 = part.split("-", 1)
            cdx_alg = alg_map.get(alg.lower())
            if not cdx_alg:
                continue
            try:
                hexed = base64.b64decode(b64 + "=" * (-len(b64) % 4)).hex()
            except Exception:
                continue
            hashes.append({"alg": cdx_alg, "content": hexed})
        return hashes

    def pkg_name_from_path(path: str) -> Any:
        # node_modules/@angular/core            -> @angular/core
        # node_modules/a/node_modules/b         -> b
        if "node_modules/" not in path:
            return None
        tail = path.rsplit("node_modules/", 1)[1]
        segs = tail.split("/")
        if segs and segs[0].startswith("@") and len(segs) > 1:
            return segs[0] + "/" + segs[1]
        return segs[0] if segs else None

    for lp in paths:
        if not os.path.exists(lp):
            log("WARNING npm lockfile not found: " + str(lp))
            continue
        try:
            with open(lp, "r", encoding="utf-8") as f:
                lock = json.load(f)
        except Exception as e:
            log("WARNING could not read " + str(lp) + ": " + str(e))
            continue

        found = 0
        for path, node in (lock.get("packages") or {}).items():
            if not isinstance(node, dict) or not node.get("integrity"):
                continue
            name = pkg_name_from_path(path)
            ver = node.get("version")
            if not (name and ver):
                continue
            h = integrity_to_hashes(node["integrity"])
            if h:
                out[str(name) + "@" + str(ver)] = h
                found += 1

        def walk_v1(deps: dict) -> None:
            nonlocal found
            for name, node in (deps or {}).items():
                if not isinstance(node, dict):
                    continue
                if node.get("integrity") and node.get("version"):
                    h = integrity_to_hashes(node["integrity"])
                    if h:
                        out[str(name) + "@" + str(node["version"])] = h
                        found += 1
                walk_v1(node.get("dependencies") or {})

        if not lock.get("packages"):
            walk_v1(lock.get("dependencies") or {})

        log("npm lockfile " + os.path.basename(lp) + ": "
            + str(found) + " integrity hashes")
    return out


def load_license_table(path: Any) -> dict:
    """SPDX id -> {category, distributionRisk, restrictions}.

    Keyed on LICENCE, not component - which is why this file can be authored
    without knowing the dependency set. Unrecognised licences are flagged,
    never guessed (see meta.unknownRestriction).
    """
    if not path:
        return {}
    if not os.path.exists(path):
        log("WARNING licence table not found: " + str(path))
        return {}
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    if str(path).endswith((".yml", ".yaml")):
        try:
            import yaml
        except ImportError:
            log("ERROR pyyaml not installed. Run: pip install pyyaml")
            sys.exit(2)
        data = yaml.safe_load(raw) or {}
    else:
        data = json.loads(raw) or {}
    return {"meta": data.get("meta") or {},
            "licenses": data.get("licenses") or {}}


def normalise_license(raw: str) -> str:
    """Trove classifier -> SPDX id; anything else passes through unchanged."""
    raw = str(raw).strip()
    if raw in CLASSIFIER_TO_SPDX:
        return CLASSIFIER_TO_SPDX[raw]
    return raw


def license_ids(comp: dict) -> list:
    """Extract SPDX ids from any of the CycloneDX licence shapes.

    Handles three real-world messes seen in generator output:
      - SPDX expressions      "Apache-2.0 AND GPL-3.0-only"
      - trove classifiers     "License :: OSI Approved :: MIT License"
      - comma-joined lists    "...Apache Software License, ...BSD License"
    """
    out = []
    for lic in (comp.get("licenses") or []):
        if not isinstance(lic, dict):
            continue
        raw_values = []
        if lic.get("expression"):
            raw_values.append(str(lic["expression"]))
        else:
            node = lic.get("license") or {}
            if isinstance(node, dict):
                if node.get("id"):
                    raw_values.append(str(node["id"]))
                elif node.get("name"):
                    raw_values.append(str(node["name"]))
        for raw in raw_values:
            # comma-separated classifier lists first, then SPDX operators
            for chunk in raw.split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                if chunk.startswith("License ::"):
                    out.append(normalise_license(chunk))
                    continue
                for tok in re.split(r"\s+(?:OR|AND|WITH)\s+", chunk):
                    tok = tok.strip("()").strip()
                    if tok:
                        out.append(normalise_license(tok))
    return list(dict.fromkeys(out))


def resolve_restrictions(comp: dict, table: dict) -> tuple:
    """-> (restrictions_text, category, risk, unrecognised_ids)

    Multiple licences: the most restrictive wins the risk rating and ALL
    obligations are concatenated, because a component under
    "Apache-2.0 AND GPL-3.0" genuinely carries both sets.
    """
    lics = table.get("licenses") or {}
    meta = table.get("meta") or {}
    unknown_text = meta.get("unknownRestriction",
                            "UNRECOGNISED LICENCE - legal review required")
    ids = license_ids(comp)
    if not ids:
        return (unknown_text + " (no licence declared)",
                "unknown", "high", ["<no licence declared>"])

    risk_rank = {"low": 1, "medium": 2, "high": 3}
    parts: list = []
    cats: list = []
    unrecognised: list = []
    worst_n, worst_risk = 0, "low"
    for lid in ids:
        row = lics.get(lid)
        if not isinstance(row, dict):
            unrecognised.append(lid)
            continue
        txt = str(row.get("restrictions") or "").strip()
        if txt and txt not in parts:
            parts.append(txt)
        if row.get("category"):
            cats.append(str(row["category"]))
        r = str(row.get("distributionRisk") or "low")
        if risk_rank.get(r, 1) > worst_n:
            worst_n, worst_risk = risk_rank.get(r, 1), r

    if unrecognised:
        parts.append(unknown_text + " (" + ", ".join(unrecognised) + ")")
        worst_risk = "high"
    if not parts:
        return (unknown_text, "unknown", "high", unrecognised)

    if len(parts) == 1:
        text = parts[0]
    else:
        text = "; ".join(str(i + 1) + ") " + p for i, p in enumerate(parts))
    return (text, "/".join(dict.fromkeys(cats)) or "unknown",
            worst_risk, unrecognised)


def lookup_eol(comp: dict, cache: dict, offline: bool) -> Any:
    if offline:
        return None
    name = str(comp.get("name") or "").lower()
    if not name:
        return None
    slug = EOL_SLUGS.get(name)
    if not slug:
        for k, v in EOL_SLUGS.items():
            if k in name:
                slug = v
                break
    if not slug:
        return None
    if slug not in cache:
        cache[slug] = http_json("https://endoflife.date/api/" + slug + ".json") or []
    cycles = cache[slug]
    if not isinstance(cycles, list):
        return None
    ver = str(comp.get("version") or "")
    for cyc in cycles:
        if not isinstance(cyc, dict):
            continue
        c = str(cyc.get("cycle", ""))
        if c and (ver == c or ver.startswith(c + ".")):
            eol = cyc.get("eol")
            if isinstance(eol, str):
                return eol
            if eol is False:
                return "supported (no EOL announced)"
    return None


def lookup_pkg_meta(comp: dict, cache: dict, offline: bool) -> dict:
    """Best-effort {description, supplier, releaseDate} from public registries.

    Sources, by ecosystem:
      npm   -> registry.npmjs.org      (description, author/maintainer)
      pypi  -> pypi.org/pypi/*/json    (summary, author/maintainer)
      other -> api.deps.dev            (publishedAt, source repo -> description)

    Results are cached per package so a 400-component BOM does not make
    400 duplicate calls. Every failure degrades to {} - never raises.
    """
    out: dict = {}
    if offline:
        return out
    p = parse_purl(comp.get("purl"))
    ptype = str(p.get("type") or "").lower()
    pname = p.get("name")
    if not pname:
        return out

    ck = str(comp.get("purl") or "").split("?")[0]
    if ck in cache:
        return cache[ck]

    if ptype == "npm":
        full = (str(p["namespace"]) + "/" + str(pname)) if p.get("namespace") else str(pname)
        d = http_json("https://registry.npmjs.org/" + urllib.parse.quote(full, safe="@/"))
        if isinstance(d, dict):
            if d.get("description"):
                out["description"] = str(d["description"])[:500]
            author = d.get("author")
            sup = None
            if isinstance(author, dict) and author.get("name"):
                sup = author["name"]
            elif isinstance(author, str) and author:
                sup = author
            else:
                ms = d.get("maintainers")
                if isinstance(ms, list) and ms and isinstance(ms[0], dict):
                    sup = ms[0].get("name")
            if sup:
                out["supplier"] = str(sup)
            times = d.get("time") or {}
            ver = p.get("version")
            if isinstance(times, dict) and ver and isinstance(times.get(ver), str):
                out["releaseDate"] = times[ver][:10]

    elif ptype == "pypi":
        d = http_json("https://pypi.org/pypi/" + urllib.parse.quote(str(pname), safe="") + "/json")
        if isinstance(d, dict):
            info = d.get("info") or {}
            if info.get("summary"):
                out["description"] = str(info["summary"])[:500]
            sup = info.get("author") or info.get("maintainer")
            if sup:
                out["supplier"] = str(sup)

    sysname = DEPSDEV_SYS.get(ptype)
    if sysname and p.get("version") and (
            "releaseDate" not in out or "description" not in out):
        if sysname == "MAVEN" and p.get("namespace"):
            pkg = str(p["namespace"]) + ":" + str(pname)
        elif p.get("namespace"):
            pkg = str(p["namespace"]) + "/" + str(pname)
        else:
            pkg = str(pname)
        vurl = ("https://api.deps.dev/v3alpha/systems/" + sysname + "/packages/"
                + urllib.parse.quote(pkg, safe="") + "/versions/"
                + urllib.parse.quote(str(p["version"]), safe=""))
        d = http_json(vurl)
        if isinstance(d, dict):
            pub = d.get("publishedAt") or d.get("published_at")
            if "releaseDate" not in out and isinstance(pub, str) and len(pub) >= 10:
                out["releaseDate"] = pub[:10]
            repo = None
            for ln in (d.get("links") or []):
                if isinstance(ln, dict) and ln.get("label") == "SOURCE_REPO":
                    repo = ln.get("url")
                    break
            if repo and "description" not in out:
                slug = re.sub(r"^https?://", "", str(repo)).rstrip("/")
                slug = re.sub(r"\.git$", "", slug)
                pj = http_json("https://api.deps.dev/v3alpha/projects/"
                               + urllib.parse.quote(slug, safe=""))
                if isinstance(pj, dict) and pj.get("description"):
                    out["description"] = str(pj["description"])[:500]
            if repo and "supplier" not in out and not p.get("namespace"):
                parts = re.sub(r"^https?://", "", str(repo)).strip("/").split("/")
                if len(parts) >= 2:
                    out["supplier"] = parts[1]

    cache[ck] = out
    return out


def derive_origin(comp: dict, org_names: list) -> str:
    sup = str((comp.get("supplier") or {}).get("name") or comp.get("publisher") or "")
    for org in org_names:
        if org and str(org).lower() in sup.lower():
            return "proprietary"
    lic = comp.get("licenses") or []
    ptype = str(parse_purl(comp.get("purl")).get("type") or "").lower()
    oss_types = ("maven", "npm", "pypi", "golang", "cargo", "gem",
                 "composer", "deb", "rpm", "apk", "conan", "hex", "cocoapods")
    if lic and ptype in oss_types:
        return "open-source"
    if ptype in ("nuget", "generic", "docker", "oci"):
        return "third-party vendor"
    return "open-source" if lic else "third-party vendor"


def derive_file_props(comp: dict) -> tuple:
    """(executable, archive, structured) -- derived, auditor-overridable."""
    blob = (str(comp.get("name") or "") + " " + str(comp.get("purl") or "")).lower()
    ctype = str(comp.get("type") or "").lower()
    ptype = str(parse_purl(comp.get("purl")).get("type") or "").lower()

    if ctype in ("application", "container", "operating-system", "device", "firmware"):
        executable = "yes"
    elif any(e in blob for e in EXEC_EXT):
        executable = "yes"
    elif ptype in ("golang", "cargo", "docker", "oci", "deb", "rpm", "apk"):
        executable = "yes"
    else:
        executable = "no"

    pkg_archive = ("maven", "npm", "pypi", "gem", "nuget",
                   "composer", "hex", "cargo")
    archive = "yes" if (any(e in blob for e in ARCHIVE_EXT)
                        or ptype in pkg_archive) else "no"

    structured = "yes" if comp.get("purl") else "no"
    return executable, archive, structured


def derive_criticality(comp: dict, direct: set, vuln_index: dict) -> str:
    keys = comp_keys(comp)
    has_vuln = any(vuln_index.get(k) for k in keys)
    is_direct = any(k in direct for k in keys)
    if has_vuln and is_direct:
        return "critical"
    if has_vuln:
        return "high"
    if is_direct:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# vulnerability folding (OWASP Dependency-Check JSON, or CycloneDX VDR)
# ---------------------------------------------------------------------------
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "moderate": 2,
             "low": 1, "none": 0}
SEV_LABEL = {4: "critical", 3: "high", 2: "medium", 1: "low"}


def load_vulns(path: Any) -> tuple:
    """-> (index keyed by purl/name/file -> [vuln dicts], cyclonedx vulnerabilities[])"""
    if not path:
        return {}, []
    if not os.path.exists(path):
        log("WARNING vulnerability report not found: " + str(path))
        return {}, []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    index: dict = {}
    cdx_vulns: list = []

    # --- CycloneDX VDR / VEX shape ---
    if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
        for v in (data.get("vulnerabilities") or []):
            cdx_vulns.append(v)
            for aff in (v.get("affects") or []):
                ref = aff.get("ref")
                if ref:
                    index.setdefault(ref, []).append(v)
        return index, cdx_vulns

    # --- OWASP Dependency-Check JSON shape ---
    for dep in (data.get("dependencies") or []):
        vulns = dep.get("vulnerabilities") or []
        if not vulns:
            continue
        refs = []
        for pkg in (dep.get("packages") or []):
            if isinstance(pkg, dict) and pkg.get("id"):
                refs.append(pkg["id"])
        for ident in (dep.get("identifiers") or []):
            if isinstance(ident, dict) and ident.get("id"):
                refs.append(ident["id"])
        if dep.get("fileName"):
            refs.append(dep["fileName"])
        refs = list(dict.fromkeys(refs))
        for v in vulns:
            cvss3 = v.get("cvssv3") or {}
            cvss2 = v.get("cvssv2") or {}
            score = cvss3.get("baseScore") or cvss2.get("score")
            sev = str(v.get("severity") or "unknown").lower()
            ratings = []
            if score or sev != "unknown":
                method = "CVSSv31" if cvss3 else ("CVSSv2" if cvss2 else "other")
                r = {"severity": sev, "method": method}
                if score is not None:
                    r["score"] = score
                ratings.append(r)
            fixes = set()
            for sw in (v.get("vulnerableSoftware") or []):
                if not isinstance(sw, dict):
                    continue
                fv = sw.get("versionEndExcluding") or sw.get("versionEndIncluding")
                if fv:
                    fixes.add(str(fv))
            cdxv = {
                "id": v.get("name"),
                "source": {"name": v.get("source") or "NVD"},
                "description": str(v.get("description") or "")[:2000],
                "ratings": ratings,
                "affects": [{"ref": r} for r in refs],
                "_fixVersions": sorted(fixes),
            }
            cdx_vulns.append(cdxv)
            for r in refs:
                index.setdefault(r, []).append(cdxv)
    return index, cdx_vulns


def norm_pyname(n: Any) -> str:
    """PEP 503 normalisation: Django, python_dotenv, Pillow -> django, python-dotenv, pillow."""
    return re.sub(r"[-_.]+", "-", str(n or "")).lower()


def load_declared_direct(paths: list) -> set:
    """Package names a project DECLARES as its direct dependencies.

    Why this exists: cyclonedx-py's environment mode scans an installed venv,
    and a venv has no notion of a root project - it cannot tell what the
    developer asked for from what came along. Inferring 'direct' as 'nothing
    depends on it' misread 15 of 26 declared packages on a real repo,
    including Django, cryptography and bcrypt, because central packages are
    exactly the ones other packages depend on.

    Sources, one requirement per line or PEP 621:
      requirements.in           (pip-tools style; requirements.txt is usually
                                 pip-freeze output listing EVERYTHING, so it
                                 cannot serve here)
      pyproject.toml            [project].dependencies (needs Python 3.11+)
    Returns normalised names. Environment markers, extras and version pins
    are stripped; `-r`/`-e` lines are skipped.
    """
    names: set = set()
    for p in paths:
        if not os.path.exists(p):
            log("WARNING direct-deps file not found: " + str(p))
            continue
        reqs: list = []
        if str(p).endswith(".toml"):
            try:
                import tomllib
                with open(p, "rb") as f:
                    data = tomllib.load(f)
                reqs = list((data.get("project") or {}).get("dependencies") or [])
            except Exception as e:
                log("WARNING could not read " + str(p) + ": " + str(e))
        else:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                reqs = [line for line in f]
        for line in reqs:
            s = str(line).split("#", 1)[0].strip()
            if not s or s.startswith("-"):
                continue
            name = re.split(r"[<>=!~\[;@\s]", s, 1)[0].strip()
            if name:
                names.add(norm_pyname(name))
    return names


def scan_osv(components: list) -> tuple:
    """Query OSV.dev for every component and return CycloneDX vulnerabilities.

    This is what fills CERT-In fields 8 (Vulnerabilities) and 9 (Patch
    Status). It is deliberately ecosystem-agnostic: OSV is queried by PURL,
    so npm, PyPI, Maven, Go and the rest all go through one code path.

    Components WITHOUT a version cannot be matched and are returned
    separately - a scanner silently skipping them is how a broken SBOM
    produces a falsely clean report.
    """
    index: dict = {}
    vulns: list = []
    unscannable: list = []
    queries = []
    queried = []

    for c in components:
        purl = c.get("purl")
        p = parse_purl(purl)
        if not purl or not p.get("version"):
            unscannable.append(str(c.get("name")) + "@" + str(c.get("version")))
            continue
        queries.append({"package": {"purl": purl}})
        queried.append(c)

    if not queries:
        return index, vulns, unscannable

    log("scanning " + str(len(queries)) + " components against OSV.dev"
        + (" (" + str(len(unscannable)) + " unscannable, no version)"
           if unscannable else ""))

    ids_by_comp: dict = {}
    BATCH = 500
    for i in range(0, len(queries), BATCH):
        payload = {"queries": queries[i:i + BATCH]}
        try:
            req = urllib.request.Request(
                "https://api.osv.dev/v1/querybatch",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": "certin-enrich/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                res = json.loads(r.read().decode())
        except Exception as e:
            log("WARNING OSV batch failed: " + str(e))
            continue
        for comp, entry in zip(queried[i:i + BATCH], res.get("results", [])):
            got = [v.get("id") for v in (entry.get("vulns") or []) if v.get("id")]
            if got:
                ids_by_comp[id(comp)] = got

    # fetch detail (severity, fixed version) once per unique advisory
    detail_cache: dict = {}
    all_ids = sorted({vid for ids in ids_by_comp.values() for vid in ids})
    log("resolving " + str(len(all_ids)) + " advisories")
    for vid in all_ids:
        d = http_json("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(vid))
        if isinstance(d, dict):
            detail_cache[vid] = d

    for comp in queried:
        got = ids_by_comp.get(id(comp))
        if not got:
            continue
        ref = comp.get("bom-ref") or comp.get("purl")
        for vid in got:
            d = detail_cache.get(vid) or {}
            sev_label = "unknown"
            score = None
            for sev in (d.get("severity") or []):
                if sev.get("type", "").startswith("CVSS") and sev.get("score"):
                    score = sev["score"]
            db = d.get("database_specific") or {}
            if db.get("severity"):
                sev_label = str(db["severity"]).lower()
            fixed = set()
            for aff in (d.get("affected") or []):
                for rng in (aff.get("ranges") or []):
                    for ev in (rng.get("events") or []):
                        if ev.get("fixed"):
                            fixed.add(str(ev["fixed"]))
            rec = {
                "id": vid,
                "source": {"name": "OSV", "url": "https://osv.dev/vulnerability/" + vid},
                "description": str(d.get("summary") or d.get("details") or "")[:1000],
                "ratings": ([{"severity": sev_label,
                              "method": "other",
                              **({"vector": score} if score else {})}]
                            if sev_label != "unknown" or score else []),
                "affects": [{"ref": ref}],
                "_fixVersions": sorted(fixed),
            }
            vulns.append(rec)
            for k in comp_keys(comp):
                index.setdefault(k, []).append(rec)

    return index, vulns, unscannable


def patch_status_for(comp: dict, vuln_index: dict, scanned: bool = True) -> str:
    hits = []
    for k in comp_keys(comp):
        hits.extend(vuln_index.get(k, []))
    if not hits:
        if not scanned:
            return ("NOT ASSESSED - no vulnerability scan supplied "
                    "(pass --vulns or --scan-osv)")
        return "up to date; no known vulnerabilities at SBOM timestamp"
    seen = {}
    for h in hits:
        seen[h.get("id") or id(h)] = h
    hits = list(seen.values())
    fixes = sorted({fv for h in hits for fv in (h.get("_fixVersions") or []) if fv})
    worst = 0
    for h in hits:
        for r in (h.get("ratings") or []):
            worst = max(worst, SEV_ORDER.get(str(r.get("severity") or "").lower(), 0))
    label = SEV_LABEL.get(worst, "unknown")
    n = len(hits)
    if fixes:
        return ("patch available (upgrade to >= " + fixes[-1] + "); "
                + str(n) + " known issue(s), max severity " + label)
    return ("patch pending; no fixed version published; " + str(n)
            + " known issue(s), max severity " + label)


# ---------------------------------------------------------------------------
# field presence check
# ---------------------------------------------------------------------------
def field_present(field: str, comp: dict, bom: dict, dep_refs: set) -> bool:
    _label, kind, loc = CERTIN_FIELDS[field]
    if kind == "native":
        if loc == "supplier":
            return bool((comp.get("supplier") or {}).get("name")
                        or comp.get("publisher"))
        return bool(comp.get(loc))
    if kind == "prop":
        return bool(get_props(comp).get(PROP_NS + ":" + loc))
    if kind == "bomwide":
        if loc == "dependencies":
            refs = comp_keys(comp)
            return any(r in dep_refs for r in refs)
        if loc == "vulnerabilities":
            # A non-empty list is evidence. An EMPTY list is only evidence
            # if a scan actually ran and found nothing - otherwise the field
            # is unassessed, and reporting it "complete" would assert a clean
            # bill of health that nobody checked.
            if bom.get("vulnerabilities"):
                return True
            md = bom.get("metadata") or {}
            for pr in (md.get("properties") or []):
                if pr.get("name") == "certin:vulnScanSource" and pr.get("value"):
                    return True
            return False
        if loc == "metadata.authors":
            md = bom.get("metadata") or {}
            return bool(md.get("authors") or md.get("supplier")
                        or md.get("manufacture"))
        if loc == "metadata.timestamp":
            return bool((bom.get("metadata") or {}).get("timestamp"))
    return False


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Enrich a CycloneDX SBOM to CERT-In SBOM Guidelines v1.0 s4.2")
    ap.add_argument("-i", "--input", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("-m", "--metadata", help="curated metadata YAML/JSON")
    ap.add_argument("-l", "--licenses",
                    help="SPDX licence -> usage-restrictions table "
                         "(default: data/license-restrictions.yml beside this script)")
    ap.add_argument("--npm-lock", action="append", default=[],
                    metavar="package-lock.json",
                    help="npm lockfile to pull integrity hashes from for "
                         "CERT-In field 14; repeatable for monorepos")
    ap.add_argument("--direct-deps", action="append", default=[], metavar="FILE",
                    help="requirements.in or pyproject.toml naming a project's DIRECT "
                         "dependencies; overrides the graph-derived direct set. Needed "
                         "for Python, whose venv scan cannot tell asked-for from came-along")
    ap.add_argument("--vulns", help="OWASP Dependency-Check JSON or CycloneDX VDR")
    ap.add_argument("--scan-osv", action="store_true",
                    help="query OSV.dev directly to fill CERT-In fields 8 and 9; "
                         "ecosystem-agnostic, no separate scanner needed")
    ap.add_argument("--report", help="write markdown compliance report here")
    ap.add_argument("--offline", action="store_true",
                    help="skip endoflife.date / deps.dev lookups")
    ap.add_argument("--fail-on-missing", default="",
                    help="comma-separated field keys required on EVERY component")
    ap.add_argument("--min-coverage", type=float, default=0.0,
                    help="fail if overall field coverage percent is below this")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        bom = json.load(f)

    if bom.get("bomFormat") != "CycloneDX":
        log("ERROR input is not CycloneDX (bomFormat=" + repr(bom.get("bomFormat"))
            + "). Convert SPDX first, e.g.:")
        log("  cyclonedx-cli convert --input-file in.spdx.json "
            "--output-file out.cdx.json --output-format json")
        return 2

    # Licence table: explicit path, else the copy shipped beside this script.
    lic_path = args.licenses
    if not lic_path:
        guess = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.pardir, "data", "license-restrictions.yml")
        if os.path.exists(guess):
            lic_path = os.path.normpath(guess)
    lic_table = load_license_table(lic_path)
    if lic_table and not (lic_table.get("meta") or {}).get("reviewed"):
        log("NOTE licence table is not marked legal-reviewed "
            "(meta.reviewed: false) - restrictions text is engineering triage")
    unrecognised_licences: dict = {}
    npm_hashes = load_npm_hashes(args.npm_lock) if args.npm_lock else {}

    curated = load_curated(args.metadata)
    defaults = curated.get("defaults", {})
    project = curated.get("project", {})
    cindex = curated.get("index", {})
    org_names = [n for n in [project.get("organization"),
                             project.get("supplier")] if n]

    vuln_index, cdx_vulns = load_vulns(args.vulns)
    scan_ran = bool(args.vulns)
    unscannable: list = []
    scan_source = os.path.basename(str(args.vulns)) if args.vulns else None

    # ---- BOM-level fields: author, timestamp, supplier -------------------
    md = bom.setdefault("metadata", {})
    if not md.get("timestamp"):
        md["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not md.get("authors"):
        author = (project.get("sbomAuthor")
                  or os.environ.get("GITHUB_REPOSITORY")
                  or project.get("organization"))
        if author:
            md["authors"] = [{"name": str(author)}]
    if not md.get("supplier") and project.get("organization"):
        md["supplier"] = {"name": str(project["organization"])}
    md.setdefault("properties", [])
    bom_props = [
        ("certin:guidelineVersion",
         "CERT-In Technical Guidelines on SBOM v1.0 (03.10.2024)"),
        ("certin:sbomLevel", project.get("sbomLevel", "Complete SBOM")),
        ("certin:sbomClassification", project.get("sbomClassification", "Build SBOM")),
    ]
    for k, v in bom_props:
        if not any(p.get("name") == k for p in md["properties"]):
            md["properties"].append({"name": k, "value": str(v)})

    # ---- direct-dependency set (for criticality policy) ------------------
    root = md.get("component") or {}
    root_ref = root.get("bom-ref") or root.get("purl")
    direct = set()
    dep_refs = set()
    for d in (bom.get("dependencies") or []):
        if d.get("ref"):
            dep_refs.add(d["ref"])
        for on in (d.get("dependsOn") or []):
            dep_refs.add(on)
        if root_ref and d.get("ref") == root_ref:
            direct.update(d.get("dependsOn") or [])

    components = bom.get("components") or []
    if not direct:
        # no usable graph -> treat all as direct so criticality stays meaningful
        for c in components:
            direct.update(comp_keys(c))

    # Declared direct dependencies (requirements.in / pyproject.toml) override
    # whatever the graph implied. Also written back into the root's dependsOn
    # so the SBOM's own graph (field 7) is correct, not just our criticality.
    declared = load_declared_direct(args.direct_deps) if args.direct_deps else set()
    if declared:
        root_dep = next((d for d in (bom.get("dependencies") or [])
                         if root_ref and d.get("ref") == root_ref), None)
        promoted = 0
        for c in components:
            if norm_pyname(c.get("name")) not in declared:
                continue
            keys = comp_keys(c)
            if not any(k in direct for k in keys):
                direct.update(keys)
                promoted += 1
                ref = c.get("bom-ref") or c.get("purl")
                if root_dep is not None and ref:
                    lst = root_dep.setdefault("dependsOn", [])
                    if ref not in lst:
                        lst.append(ref)
        log("declared direct deps: " + str(len(declared)) + " names -> "
            + str(promoted) + " components promoted from transitive to direct")

    if args.scan_osv:
        if args.offline:
            log("WARNING --scan-osv ignored because --offline was given")
        else:
            osv_index, osv_vulns, unscannable = scan_osv(components)
            for k, v in osv_index.items():
                vuln_index.setdefault(k, []).extend(v)
            cdx_vulns.extend(osv_vulns)
            scan_ran = True
            scan_source = ((scan_source + " + OSV.dev") if scan_source
                           else "OSV.dev")
            affected = len({a.get("ref") for v in osv_vulns
                            for a in (v.get("affects") or [])})
            log("OSV: " + str(len(osv_vulns)) + " advisories across "
                + str(affected) + " components")

    # Record WHAT scanned. Field 8 only counts as assessed with this present,
    # so an empty vulnerability list can never masquerade as "clean".
    if scan_source:
        md.setdefault("properties", [])
        if not any(p.get("name") == "certin:vulnScanSource"
                   for p in md["properties"]):
            md["properties"].append({"name": "certin:vulnScanSource",
                                     "value": scan_source})
        if unscannable:
            md["properties"].append(
                {"name": "certin:unscannableComponents",
                 "value": str(len(unscannable))})

    log("enriching " + str(len(components)) + " components ("
        + ("offline" if args.offline else "online lookups enabled") + ")")

    eol_cache: dict = {}
    meta_cache: dict = {}
    for comp in components:
        entry = {}
        for k in comp_keys(comp):
            if k in cindex:
                entry = cindex[k]
                break

        # one registry round-trip per package, reused for 3 fields below;
        # returns {} immediately when --offline, and is cached per package
        online = lookup_pkg_meta(comp, meta_cache, args.offline)

        # checksums (field 14): from the npm lockfile when the generator
        # omitted them. Matched on the scoped name, e.g. "@angular/core@20.3.26".
        if npm_hashes and not comp.get("hashes"):
            p = parse_purl(comp.get("purl"))
            cand = []
            if p.get("name") and p.get("version"):
                full = ((str(p["namespace"]) + "/" + str(p["name"]))
                        if p.get("namespace") else str(p["name"]))
                cand.append(full + "@" + str(p["version"]))
            grp = comp.get("group")
            if comp.get("name") and comp.get("version"):
                if grp:
                    cand.append(str(grp) + "/" + str(comp["name"])
                                + "@" + str(comp["version"]))
                cand.append(str(comp["name"]) + "@" + str(comp["version"]))
            for k in cand:
                if k in npm_hashes:
                    comp["hashes"] = npm_hashes[k]
                    set_prop(comp, "hashSource", "npm lockfile integrity")
                    break

        # supplier: generator -> curated -> PURL namespace -> registry owner
        if not ((comp.get("supplier") or {}).get("name") or comp.get("publisher")):
            sup = (entry.get("supplier")
                   or parse_purl(comp.get("purl")).get("namespace")
                   or online.get("supplier"))
            if sup:
                comp["supplier"] = {"name": str(sup)}

        # description: generator -> curated -> registry
        if not comp.get("description"):
            desc = entry.get("description") or online.get("description")
            if desc:
                comp["description"] = str(desc)

        # usage restrictions (field 13): curated -> licence table -> flagged.
        # Never guessed: an unrecognised licence produces a loud marker so a
        # human routes it to Legal.
        if entry.get("usageRestrictions"):
            set_prop(comp, "usageRestrictions", entry["usageRestrictions"])
        elif lic_table:
            rtext, rcat, rrisk, runknown = resolve_restrictions(comp, lic_table)
            set_prop(comp, "usageRestrictions", rtext)
            set_prop(comp, "licenseCategory", rcat)
            set_prop(comp, "distributionRisk", rrisk)
            if runknown:
                unrecognised_licences.setdefault(
                    ", ".join(runknown), []).append(
                        str(comp.get("name")) + "@" + str(comp.get("version")))
        else:
            set_prop(comp, "usageRestrictions",
                     defaults.get("usageRestrictions", "none"))
        set_prop(comp, "comments", entry.get("comments"))
        set_prop(comp, "origin",
                 entry.get("origin") or derive_origin(comp, org_names))

        # dates
        set_prop(comp, "releaseDate",
                 entry.get("releaseDate") or online.get("releaseDate"))
        set_prop(comp, "eolDate",
                 entry.get("eolDate")
                 or lookup_eol(comp, eol_cache, args.offline)
                 or defaults.get("eolDate", "not published by supplier"))

        # vulnerabilities -> patch status (always recomputed; it is time-sensitive)
        set_prop(comp, "patchStatus",
                 entry.get("patchStatus")
                 or patch_status_for(comp, vuln_index, scanned=scan_ran),
                 overwrite=True)

        # criticality
        set_prop(comp, "criticality",
                 entry.get("criticality")
                 or derive_criticality(comp, direct, vuln_index))

        # file-nature properties
        ex, ar, st = derive_file_props(comp)
        set_prop(comp, "executable", entry.get("executable", ex))
        set_prop(comp, "archive", entry.get("archive", ar))
        set_prop(comp, "structured", entry.get("structured", st))

        set_prop(comp, "enrichedBy", "certin_enrich.py")

    # ---- attach vulnerabilities (VDR) ------------------------------------
    if cdx_vulns:
        bom["vulnerabilities"] = [
            {k: v for k, v in vd.items() if not k.startswith("_")}
            for vd in cdx_vulns
        ]
    else:
        bom.setdefault("vulnerabilities", [])

    # ---- validate --------------------------------------------------------
    coverage = dict((f, 0) for f in CERTIN_FIELDS)
    gaps: dict = dict((f, []) for f in CERTIN_FIELDS)
    for comp in components:
        cname = str(comp.get("name")) + "@" + str(comp.get("version"))
        for f in CERTIN_FIELDS:
            if field_present(f, comp, bom, dep_refs):
                coverage[f] += 1
            elif len(gaps[f]) < 50:
                gaps[f].append(cname)

    total = len(components) or 1
    overall = sum(coverage.values()) / float(total * len(CERTIN_FIELDS)) * 100

    required = [f.strip() for f in args.fail_on_missing.split(",") if f.strip()]
    unknown = [f for f in required if f not in CERTIN_FIELDS]
    bad = [f for f in required if f in CERTIN_FIELDS and coverage[f] < total]

    # ---- write outputs ---------------------------------------------------
    outdir = os.path.dirname(os.path.abspath(args.output))
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2, ensure_ascii=False)
    log("wrote " + args.output)

    if args.report:
        nvulns = len(bom.get("vulnerabilities") or [])
        lines = [
            "# CERT-In SBOM Compliance Report",
            "",
            "Generated by `certin_enrich.py` against **CERT-In Technical Guidelines "
            "on SBOM v1.0 (03.10.2024), section 4.2**.",
            "",
            "- Input: `" + os.path.basename(args.input) + "`",
            "- Components analysed: **" + str(total) + "**",
            "- Vulnerabilities recorded: **" + str(nvulns) + "**",
            "- Overall field coverage: **" + ("%.1f" % overall) + "%**",
            "- SBOM timestamp: `" + str(md.get("timestamp")) + "`",
            "",
            "## Field coverage (21 mandated data fields)",
            "",
            "| # | CERT-In Data Field | Covered | % | Status | Source |",
            "|---|---|---|---|---|---|",
        ]
        srcmap = {"native": "generator", "prop": "enrichment",
                  "bomwide": "BOM metadata"}
        for n, key in enumerate(CERTIN_FIELDS, 1):
            label, kind, _loc = CERTIN_FIELDS[key]
            cov = coverage[key]
            pct = cov / float(total) * 100
            # Status comes from the exact count, never the rounded percentage,
            # and the percentage floors so 649/652 shows 99% and not 100%.
            if cov == total:
                status, disp = "complete", "100"
            elif cov:
                status, disp = "partial", str(int(pct))
            else:
                status, disp = "MISSING", "0"
            lines.append("| " + str(n) + " | " + label + " | "
                         + str(cov) + "/" + str(total) + " | "
                         + disp + "% | " + status + " | "
                         + srcmap[kind] + " |")
        if unscannable:
            lines += ["", "## Components that could NOT be scanned", "",
                      "**" + str(len(unscannable)) + " components have no version**, "
                      "so no vulnerability database can match them. A scanner "
                      "skips these silently - absence of findings here is NOT "
                      "evidence of safety.", ""]
            for u in unscannable[:20]:
                lines.append("- `" + u + "`")
            if len(unscannable) > 20:
                lines.append("- ... and " + str(len(unscannable) - 20) + " more")
            lines.append("")

        if unrecognised_licences:
            lines += ["", "## Licences requiring legal review", "",
                      "Not present in `data/license-restrictions.yml`. These are "
                      "flagged rather than guessed - add a row for each once "
                      "Legal has ruled.", "",
                      "| Licence | Components |", "|---|---|"]
            for lid, comps in sorted(unrecognised_licences.items()):
                shown = ", ".join("`" + c + "`" for c in comps[:6])
                if len(comps) > 6:
                    shown += " and " + str(len(comps) - 6) + " more"
                lines.append("| `" + lid + "` | " + shown + " |")

        holes = dict((f, g) for f, g in gaps.items() if g)
        if holes:
            lines += ["", "## Gaps requiring attention", ""]
            for f, g in holes.items():
                # g is a capped SAMPLE of names; the true count is derived from
                # coverage so the report can never understate a gap.
                true_missing = total - coverage[f]
                shown = ", ".join("`" + x + "`" for x in g[:10])
                more = (" ... and " + str(true_missing - 10) + " more"
                        if true_missing > 10 else "")
                lines.append("**" + CERTIN_FIELDS[f][0] + "** - "
                             + str(true_missing) + " component(s): " + shown + more)
                lines.append("")
        if bad:
            lines += ["", "## GATE FAILED", "",
                      "Required fields not present on every component:", ""]
            lines += ["- `" + f + "` (" + CERTIN_FIELDS[f][0] + ")" for f in bad]
        with open(args.report, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log("wrote " + args.report)

    # ---- console summary -------------------------------------------------
    print("")
    print("CERT-In field coverage: " + ("%.1f" % overall) + "%  ("
          + str(total) + " components, "
          + str(len(bom.get("vulnerabilities") or [])) + " vulns)")
    weak = [(CERTIN_FIELDS[f][0], coverage[f]) for f in CERTIN_FIELDS
            if coverage[f] < total]
    if weak:
        print("Incomplete fields:")
        for label, c in weak:
            print("  - " + label + ": " + str(c) + "/" + str(total))
    else:
        print("All 21 CERT-In data fields present on every component.")
    if unknown:
        log("WARNING unknown field keys in --fail-on-missing: " + str(unknown))
    if bad:
        log("GATE FAILED required fields incomplete: " + str(bad))
        return 1
    if overall < args.min_coverage:
        log("GATE FAILED coverage " + ("%.1f" % overall)
            + "% < required " + str(args.min_coverage) + "%")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
