#!/usr/bin/env python3
"""
certin_enrich.py -- turn a generic CycloneDX SBOM into a CERT-In compliant one.

CERT-In "Technical Guidelines on SBOM" section 4.2 mandates 21 data fields per
component (v1.0, 03.10.2024; unchanged in v2.0, 09.07.2025). Standard
generators (Syft, cdxgen, cyclonedx-*) emit roughly half. This script fills the rest from three sources, in priority order:

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
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

PROP_NS = "certin"
TOOL_VERSION = "1.2.0"
HTTP_TIMEOUT = 8
GUIDELINE = "CERT-In Technical Guidelines on SBOM v2.0 (09.07.2025)"

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
# Extensions only count at the END of a name. As a substring test, ".bin"
# matched "jakarta.xml.bind-api" and marked an XML API jar executable.
EXEC_RE = re.compile(r"(?:" + "|".join(re.escape(e) for e in EXEC_EXT) + r")$")

# PURL name fragment -> endoflife.date product slug. High-confidence only.
# Keyed by (purl type, package name), or by namespace for product families
# whose artefacts all carry the product's version. Only packages whose own
# version IS the product's version: the "postgresql" Maven artefact is the
# JDBC driver (42.x), not PostgreSQL 42, and PyPI "redis" is a client
# library, so server products are deliberately absent.
EOL_SLUGS = {
    ("maven", "spring-boot"): "spring-boot",
    ("pypi", "django"): "django", ("pypi", "flask"): "flask",
    ("gem", "rails"): "rails",
    ("npm", "react"): "react", ("npm", "vue"): "vue",
}
EOL_NAMESPACES = {
    "org.apache.tomcat.embed": "tomcat", "org.apache.tomcat": "tomcat",
    "org.springframework.boot": "spring-boot",
    "org.springframework": "spring-framework",
    "org.apache.logging.log4j": "log4j",
    "org.apache.kafka": "apache-kafka",
    "@angular": "angular",
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

# Free-text licence names that Maven POMs actually carry, mapped to SPDX.
# Unmapped spellings are not matched against the restrictions table: "EPL 1.0"
# went unrecognised and rated h2 high-risk although EPL-1.0 is medium.
NAME_TO_SPDX = {
    "EPL 1.0": "EPL-1.0",
    "Eclipse Public License 1.0": "EPL-1.0",
    "Eclipse Public License - v 1.0": "EPL-1.0",
    "Eclipse Public License v2.0": "EPL-2.0",
    "Openfont-1.1": "OFL-1.1",
    "SIL Open Font License 1.1": "OFL-1.1",
    "The GNU General Public License, v2 with Universal FOSS Exception, v1.0":
        "GPL-2.0-only WITH Universal-FOSS-exception-1.0",
    "The Apache Software License, Version 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "MIT License": "MIT",
    "The MIT License": "MIT",
}

# Deprecated SPDX ids -> current expression.
DEPRECATED_SPDX = {
    "GPL-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
    "GPL-2.0": "GPL-2.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def log(msg: str) -> None:
    print("[certin] " + msg, file=sys.stderr)


def http_json(url: str, payload: Any = None, tries: int = 1,
              timeout: int = HTTP_TIMEOUT) -> Any:
    """GET (or POST `payload`) and parse JSON; None after `tries` failures."""
    headers = {"User-Agent": "certin-enrich/1.0", "Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:
            if attempt + 1 < tries:
                time.sleep(2 * (attempt + 1))
            elif tries > 1:
                log("WARNING " + url + " failed after " + str(tries)
                    + " tries: " + str(e))
    return None


class ScanIncomplete(Exception):
    """OSV could not be asked about every component.

    Raised instead of carrying on, because a component nobody asked about
    would otherwise be reported as having no known vulnerabilities.
    """


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


def vuln_keys(comp: dict) -> list:
    """Identifiers that name exactly one component version (for findings)."""
    keys = []
    if comp.get("bom-ref"):
        keys.append(str(comp["bom-ref"]))
    purl = comp.get("purl")
    if purl:
        keys.append(purl)
        # Qualifiers stay when they distinguish a file (classifier).
        base, _, quals = purl.split("#")[0].partition("?")
        cls = [q for q in quals.split("&") if q.startswith("classifier=")]
        keys.append(base + ("?" + cls[0] if cls else ""))
    return list(dict.fromkeys(keys))


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
            # Known free-text names first: some contain commas ("The GNU
            # General Public License, v2 with Universal FOSS Exception, v1.0")
            # and would otherwise be cut apart by the classifier-list split.
            raw = NAME_TO_SPDX.get(raw.strip(), raw)
            # comma-separated classifier lists first, then SPDX operators
            for chunk in raw.split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                if chunk.startswith("License ::"):
                    out.append(normalise_license(chunk))
                    continue
                chunk = NAME_TO_SPDX.get(chunk, chunk)
                for tok in re.split(r"\s+(?:OR|AND)\s+", chunk):
                    tok = tok.strip("()").strip()
                    if not tok:
                        continue
                    # "X WITH exception" is one licence, not two: the exception
                    # is not a licence of its own and would always read as
                    # unrecognised. Keyed by the table's legacy id where one
                    # exists, else by the base licence (the stricter reading).
                    base, _, exc = tok.partition(" WITH ")
                    if exc:
                        legacy = {v: k for k, v in DEPRECATED_SPDX.items()}
                        tok = legacy.get(tok.strip(), base.strip())
                    out.append(normalise_license(tok))
    out = list(dict.fromkeys(out))
    if any(not o.startswith("LicenseRef-") for o in out):
        out = [o for o in out if not o.startswith("LicenseRef-PyPI-")]
    return out


def normalise_component_licenses(comp: dict) -> int:
    """Write resolved SPDX identifiers back into the component.

    Generators emit what the package claims. For Python that is a PyPI trove
    classifier - "License :: OSI Approved :: Apache Software License" - which
    is not an SPDX identifier, and CERT-In s3.4(b) asks for SPDX identifiers.

    We already translate those to look up restrictions; this records the
    translation in the document too. The original stays as the DECLARED
    licence (what the package says about itself) and the SPDX identifier is
    added as CONCLUDED (what we determined it means) - which is exactly what
    those two CycloneDX terms mean, so nothing is overstated.

    Free-text names with a known SPDX equivalent ("EPL 1.0") and deprecated
    SPDX ids are rewritten in place. A `LicenseRef-` is not an SPDX list id,
    so it goes in `license.name`: in `license.id` it fails schema validation.

    Maven lists several licences on one POM to mean "any of these" (POM
    reference, <licenses>), so a Maven component with more than one becomes a
    single `A OR B` expression instead of an array a reader could take as AND.

    Returns how many licences were added or rewritten.
    """
    lics = comp.get("licenses") or []
    if not lics or any("expression" in l for l in lics):
        return 0
    changed = 0
    for l in lics:
        node = l.get("license") or {}
        if not isinstance(node, dict):
            continue
        if node.get("id") in DEPRECATED_SPDX:
            node["id"] = DEPRECATED_SPDX[node["id"]]
            changed += 1
        elif node.get("name") in NAME_TO_SPDX:
            node["id"] = NAME_TO_SPDX[node.pop("name")]
            node.setdefault("acknowledgement", "declared")
            changed += 1

    # Anything that resolved to a WITH expression cannot stay in license.id.
    terms = []
    for l in lics:
        node = l.get("license") or {}
        terms.append(str(node.get("id") or "") if isinstance(node, dict) else "")
    is_maven = str(parse_purl(comp.get("purl")).get("type") or "") == "maven"
    if all(terms) and (any(" " in t for t in terms) or (is_maven and len(terms) > 1)):
        expr = " OR ".join(("(" + t + ")") if (" " in t and len(terms) > 1) else t
                           for t in dict.fromkeys(terms))
        comp["licenses"] = [{"expression": expr, "acknowledgement": "declared"}]
        return changed + 1
    # Mixed with an unmapped free-text licence, an expression is not
    # possible (CycloneDX allows one expression OR a list of licences), and an
    # expression is not a valid license.id. Keep it, readably, as the name.
    for l in lics:
        node = l.get("license") or {}
        if isinstance(node, dict) and " " in str(node.get("id") or ""):
            node["name"] = node.pop("id")

    have = set()
    for l in lics:
        node = l.get("license") or {}
        if isinstance(node, dict):
            have.add(node.get("id") or node.get("name"))
    for l in list(lics):
        node = l.get("license") or {}
        if not isinstance(node, dict) or node.get("id") or not node.get("name"):
            continue
        node.setdefault("acknowledgement", "declared")
        for chunk in str(node["name"]).split(","):
            chunk = chunk.strip()
            if not chunk.startswith("License ::"):
                continue
            spdx = CLASSIFIER_TO_SPDX.get(chunk)
            # A vague classifier adds nothing when the package already names
            # an exact SPDX id (idna: BSD-3-Clause in its LICENSE file).
            if spdx and spdx.startswith("LicenseRef-PyPI-") and any(
                    h and not str(h).startswith(("License ::", "LicenseRef-"))
                    for h in have):
                continue
            if spdx and spdx not in have:
                key = "name" if spdx.startswith("LicenseRef-") else "id"
                lics.append({"license": {key: spdx,
                                         "acknowledgement": "concluded"}})
                have.add(spdx)
                changed += 1
    return changed


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
    # Exact package or product namespace only. Substring matching gave
    # redis-py the Redis SERVER's EOL date and vue-router Vue's.
    p = parse_purl(comp.get("purl"))
    ptype = str(p.get("type") or "").lower()
    ns = str(p.get("namespace") or "").lower()
    name = str(p.get("name") or "").lower()
    slug = (EOL_NAMESPACES.get(ns) if ns else None) or EOL_SLUGS.get((ptype, name))
    if not slug:
        return None
    if slug not in cache:
        cache[slug] = http_json("https://endoflife.date/api/" + slug + ".json", tries=2)
    cycles = cache[slug]
    if cycles is None:
        # Not "not published by supplier": the supplier does publish it, we
        # just could not reach the source.
        return "unknown (endoflife.date unreachable)"
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
            # No supplier from the source-repo URL: its path segment is an
            # account name at best and "sponsors" (a GitHub Sponsors link) at
            # worst. A missing supplier is reported as a gap; a guessed one
            # reads as fact.

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
    ends = (str(comp.get("name") or "").lower(),
            str(comp.get("purl") or "").split("?")[0].split("@")[0].lower())

    if ctype in ("application", "container", "operating-system", "device", "firmware"):
        executable = "yes"
    elif any(EXEC_RE.search(s) for s in ends):
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
    keys = vuln_keys(comp)
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
            # Same rule as for OSV: "moderate" is not a CycloneDX severity.
            for r in (v.get("ratings") or []):
                if "severity" in r:
                    r["severity"] = norm_severity(r["severity"])
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
            sev = norm_severity(v.get("severity"))
            ratings = []
            if score or sev != "unknown":
                method = "CVSSv3" if cvss3 else ("CVSSv2" if cvss2 else "other")
                r = {"severity": sev, "method": method}
                if score is not None:
                    r["score"] = score
                ratings.append(r)
            # Each vulnerable range is kept whole; the fix is chosen per
            # component in attach_to_components, from the range holding the
            # installed version. Taking the largest end across ranges sent a
            # Tomcat 9.0.50 user to 11.0.0-M21.
            # A CVE's configurations can list other vendors' products, each
            # with its own end version; only the product Dependency-Check
            # matched (vulnerabilityIdMatched) describes this dependency.
            ranges = []
            for sw in (v.get("vulnerableSoftware") or []):
                if isinstance(sw, dict):
                    sw = sw.get("software", sw)
                if isinstance(sw, dict):
                    r = {k: str(sw[k]) for k in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndExcluding", "versionEndIncluding") if sw.get(k)}
                    cpe = str(sw.get("id") or "").split(":")
                    r["_product"] = ":".join(cpe[3:5]) if len(cpe) > 4 else ""
                    r["_matched"] = str(sw.get("vulnerabilityIdMatched")).lower() == "true"
                    ranges.append(r)
            matched = {r["_product"] for r in ranges if r["_matched"] and r["_product"]}
            if not matched:
                # Older reports carry no vulnerabilityIdMatched flag: fall back
                # to CPE products named like the dependency's own package.
                pkg_names = {str(parse_purl(x).get("name") or "").lower() for x in refs}
                pkg_names.discard("")
                matched = {r["_product"] for r in ranges
                           if r["_product"].split(":")[-1].lower() in pkg_names}
            if matched:
                ranges = [r for r in ranges if r["_product"] in matched]
            cdxv = {
                "id": v.get("name"),
                "source": {"name": v.get("source") or "NVD"},
                "description": str(v.get("description") or "")[:2000],
                "ratings": ratings,
                "affects": [{"ref": r} for r in refs],
                "_dcRanges": ranges,
            }
            cdx_vulns.append(cdxv)
            for r in refs:
                index.setdefault(r, []).append(cdxv)
    return index, cdx_vulns


# VEX analysis states meaning "this finding does not apply (any more)".
NOT_COUNTED = {"not_affected", "false_positive", "resolved", "resolved_with_pedigree"}


def comp_vkey(comp: dict):
    """Version ordering for this component's ecosystem (SemVer for npm/Go/Cargo)."""
    ptype = str(parse_purl(comp.get("purl")).get("type") or "").lower()
    sv = OSV_ECOSYSTEM.get(ptype) in SEMVER_ECOSYSTEMS
    return lambda x: version_key(x, semver=sv)


def dc_fix(ranges: list, version: Any, vk: Any = None) -> Any:
    """Fix for `version` from Dependency-Check ranges: the end of the range
    that contains it. versionEndIncluding is the last AFFECTED version, so a
    range ending that way has no fix of its own. `vk` is the ecosystem's
    version ordering (comp_vkey)."""
    if not version:
        return None
    vk = vk or version_key
    ik = vk(version)
    hits, later, unfixed = [], [], False
    for r in ranges:
        lo_ok = True
        if r.get("versionStartIncluding"):
            lo_ok = vk(r["versionStartIncluding"]) <= ik
        elif r.get("versionStartExcluding"):
            lo_ok = vk(r["versionStartExcluding"]) < ik
        end = r.get("versionEndExcluding")
        if end and vk(end) > ik:
            later.append(end)
        if not lo_ok:
            continue
        if end:
            if ik < vk(end):
                hits.append(end)
        elif r.get("versionEndIncluding"):
            if ik <= vk(r["versionEndIncluding"]):
                unfixed = True
        else:
            unfixed = True
    if hits:
        return min(hits, key=vk)
    if unfixed or any(r.get("versionStartIncluding") or r.get("versionStartExcluding")
                      for r in ranges):
        return None
    return min(later, key=vk) if later else None


def attach_to_components(vulns: list, components: list, root: Any = None) -> tuple:
    """Point supplied findings at the SBOM's own components.

    A Dependency-Check report names packages by purl, CPE or jar file name;
    none of those is a bom-ref, so copied as-is every `affects` entry dangled.
    Each ref is matched to the component (or the product root) whose bom-ref
    or purl it is; anything else in the affects entry, such as a VEX
    `versions` list, is kept. Refs that match nothing (CPEs, file names) are
    dropped, and a finding that matches nothing at all is left out with a
    warning rather than attached to a component it may not describe.

    A finding stays in the document but is not counted against a component
    when its VEX analysis says it does not apply (not_affected, ...) or its
    affects entry marks that component's version unaffected.
    -> (findings, index keyed by bom-ref)
    """
    by_key: dict = {}
    by_ref: dict = {}
    for c in list(components) + ([root] if isinstance(root, dict) else []):
        if c.get("bom-ref"):
            by_ref.setdefault(c["bom-ref"], c)
            for k in vuln_keys(c):
                by_key.setdefault(k, c["bom-ref"])
    kept, index, unmatched = [], {}, 0
    for v in vulns:
        affects: dict = {}
        for a in (v.get("affects") or []):
            r = str(a.get("ref") or "")
            target = by_key.get(r) or by_key.get(r.split("?")[0])
            if not target:
                continue
            if target in affects:
                vs = affects[target].get("versions") or []
                for x in (a.get("versions") or []):
                    if x not in vs:
                        vs.append(x)
                if vs:
                    affects[target]["versions"] = vs
            else:
                affects[target] = dict(a, ref=target)
        if not affects:
            unmatched += 1
            continue
        v["affects"] = list(affects.values())
        kept.append(v)
        state = str((v.get("analysis") or {}).get("state") or "")
        for ref, a in affects.items():
            comp = by_ref.get(ref) or {}
            if v.get("_dcRanges"):
                f = dc_fix(v["_dcRanges"], comp.get("version"), comp_vkey(comp))
                if f:
                    v.setdefault("_fixByRef", {})[ref] = f
            if state in NOT_COUNTED:
                continue
            if any(str(x.get("version")) == str(comp.get("version"))
                   and x.get("status") == "unaffected"
                   for x in (a.get("versions") or []) if isinstance(x, dict)):
                continue
            index.setdefault(ref, []).append(v)
    if unmatched:
        log("WARNING " + str(unmatched) + " supplied finding(s) matched no "
            "component in the SBOM by bom-ref or purl and were left out")
    return kept, index


def finding_names(v: dict) -> set:
    """Every identifier a finding goes by: its id, CVEs and listed twins."""
    names = {str(v.get("id") or "")} | set(v.get("_cves") or [])
    names |= {str(r.get("id")) for r in (v.get("references") or [])
              if isinstance(r, dict) and r.get("id")}
    names.discard("")
    return names


def suppress_by_vex(index: dict, vulns: list, components: list, root: Any) -> None:
    """A VEX "not_affected" (etc.) for CVE-X on a component also stops OSV's
    record for the same vulnerability (GHSA-..., alias CVE-X) being counted
    against THAT component. Other components are unaffected. `vulns` are the
    supplied (--vulns) findings, already attached to bom-refs."""
    by_ref = {c.get("bom-ref"): c for c in list(components) + [root or {}]
              if c.get("bom-ref")}
    for v in vulns:
        record_level = str((v.get("analysis") or {}).get("state") or "") in NOT_COUNTED
        names = finding_names(v)
        for a in (v.get("affects") or []):
            comp = by_ref.get(a.get("ref"))
            if not comp:
                continue
            # Same two forms attach_to_components honours: a record-level
            # analysis state, or this component's version marked unaffected.
            version_level = any(
                str(x.get("version")) == str(comp.get("version"))
                and x.get("status") == "unaffected"
                for x in (a.get("versions") or []) if isinstance(x, dict))
            if not (record_level or version_level):
                continue
            for k in vuln_keys(comp):
                if k in index:
                    index[k] = [x for x in index[k]
                                if x is v or not (finding_names(x) & names)]


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


CVSS31_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
CVSS31_AC = {"L": 0.77, "H": 0.44}
CVSS31_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
CVSS31_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
CVSS31_UI = {"N": 0.85, "R": 0.62}
CVSS31_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss31_base_score(vector: str) -> Any:
    """CVSS v3.x base score from a vector string, per the official formula.

    Why bother: OSV supplies a severity LABEL for GitHub advisories but often
    not for PYSEC ones, which then render as "unknown" even though the vector
    is right there. On one real scan, 16 of 19 unrated findings carried a
    v3.x vector. Returns None for v4.0 (a different formula - better unrated
    than wrong) and for anything unparseable.
    """
    v = str(vector or "")
    if not v.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in v.split("/")[1:] if ":" in p)
    try:
        scope_changed = m["S"] == "C"
        iss = 1 - ((1 - CVSS31_CIA[m["C"]]) * (1 - CVSS31_CIA[m["I"]])
                   * (1 - CVSS31_CIA[m["A"]]))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        if impact <= 0:
            return 0.0
        pr = (CVSS31_PR_C if scope_changed else CVSS31_PR_U)[m["PR"]]
        expl = 8.22 * CVSS31_AV[m["AV"]] * CVSS31_AC[m["AC"]] * pr * CVSS31_UI[m["UI"]]
        raw = min((1.08 * (impact + expl)) if scope_changed else (impact + expl), 10)
    except (KeyError, ValueError, OverflowError):
        return None
    # CVSS "Roundup": smallest one-decimal value >= raw
    i = int(raw * 100000)
    return float(i) / 100000 if i % 10000 == 0 else (int(i / 10000) + 1) / 10.0


def severity_from_score(score: Any) -> str:
    """CVSS qualitative band."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "none"


def osv_more_pages(purl: Any, token: Any) -> list:
    """Advisory ids from the remaining result pages of one OSV query."""
    ids: list = []
    pages = 0
    while token:
        pages += 1
        if pages > 50:
            raise ScanIncomplete("OSV kept paging for " + str(purl))
        res = http_json("https://api.osv.dev/v1/querybatch",
                        {"queries": [{"package": {"purl": purl}, "page_token": token}]},
                        tries=3, timeout=60)
        results = res.get("results") if isinstance(res, dict) else None
        if not isinstance(results, list) or len(results) != 1:
            raise ScanIncomplete("OSV paging failed for " + str(purl))
        ids += [v.get("id") for v in ((results[0] or {}).get("vulns") or []) if v.get("id")]
        token = (results[0] or {}).get("next_page_token")
    return ids


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
        chunk = queries[i:i + BATCH]
        res = http_json("https://api.osv.dev/v1/querybatch", {"queries": chunk},
                        tries=3, timeout=60)
        results = res.get("results") if isinstance(res, dict) else None
        if not isinstance(results, list) or len(results) != len(chunk):
            raise ScanIncomplete("OSV querybatch failed for components "
                                 + str(i + 1) + "-" + str(i + len(chunk)))
        for comp, entry in zip(queried[i:i + BATCH], results):
            got = [v.get("id") for v in ((entry or {}).get("vulns") or []) if v.get("id")]
            # More advisories than one page holds: follow the pages, since a
            # partial list would understate the component's exposure.
            got += osv_more_pages(comp.get("purl"), (entry or {}).get("next_page_token"))
            if got:
                ids_by_comp[id(comp)] = list(dict.fromkeys(got))

    # fetch detail (severity, fixed version) once per unique advisory
    detail_cache: dict = {}
    all_ids = sorted({vid for ids in ids_by_comp.values() for vid in ids})
    log("resolving " + str(len(all_ids)) + " advisories")
    for vid in all_ids:
        d = http_json("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(vid), tries=3)
        if not isinstance(d, dict):
            # Without the record there is no severity and no fix version;
            # reporting "no fixed version published" would be invented.
            raise ScanIncomplete("could not fetch OSV advisory " + vid)
        detail_cache[vid] = d

    # One record per vulnerability, however many advisory databases describe
    # it. OSV returns the same CVE as a GHSA and a PYSEC record for every
    # Python finding, which doubled the Python count (59 records, 40 CVEs).
    by_primary: dict = {}
    for comp in queried:
        got = ids_by_comp.get(id(comp))
        if not got:
            continue
        ref = comp.get("bom-ref") or comp.get("purl")
        for group in group_aliases(got, detail_cache):
            primary = pick_primary(group)
            d = detail_cache.get(primary) or {}
            rec = by_primary.get(primary)
            if rec is None:
                # CERT-In field 8 asks for "CVE identifiers". OSV returns its
                # own id (GHSA-/PYSEC-) and carries the CVE as an alias.
                cves = sorted({str(a) for g in group
                               for a in ((detail_cache.get(g) or {}).get("aliases") or [])
                               if str(a).startswith("CVE-")})
                ratings = osv_ratings(d)
                if not ratings:
                    for g in group:
                        ratings = osv_ratings(detail_cache.get(g) or {})
                        if ratings:
                            break
                rec = {
                    "id": primary,
                    "source": {"name": "OSV",
                               "url": "https://osv.dev/vulnerability/" + primary},
                    "description": str(d.get("summary") or d.get("details") or "")[:1000],
                    "ratings": ratings,
                    "affects": [],
                    "_fixByRef": {},
                    "_cves": cves,
                }
                refs = [{"id": c, "source": {"name": "NVD",
                                             "url": "https://nvd.nist.gov/vuln/detail/" + c}}
                        for c in cves]
                refs += [{"id": g, "source": {"name": "OSV",
                                              "url": "https://osv.dev/vulnerability/" + g}}
                         for g in group if g != primary]
                if refs:
                    rec["references"] = refs
                by_primary[primary] = rec
                vulns.append(rec)
            if ref and all(a.get("ref") != ref for a in rec["affects"]):
                rec["affects"].append({"ref": ref})
            # Twins should agree on the fix; where they do not, the higher
            # one is the one that closes the vulnerability for both.
            fixes = [f for f in (fix_for(detail_cache.get(g) or {}, comp)
                                 for g in group) if f]
            if fixes:
                rec["_fixByRef"][ref] = max(fixes, key=comp_vkey(comp))
            # Indexed by this component's own identity only. comp_keys() also
            # yields the bare name, which would pin semver@5.7.1's advisory on
            # semver@7.6.0 in the same SBOM.
            for k in vuln_keys(comp):
                lst = index.setdefault(k, [])
                if not any(x is rec for x in lst):
                    lst.append(rec)

    return index, vulns, unscannable


def version_key(v: Any, semver: bool = False) -> tuple:
    """Ordering for release numbers across PyPI, npm, Maven and Go.

    Plain string comparison put 9.0.121 above 11.0.25 and 3.7 above 3.15,
    which is how a downgrade got recommended as a fix. Numbers compare as
    numbers; pre-release words (rc, beta, SNAPSHOT) sort before the release;
    release words (Final, GA) are ignored; a Go-style leading "v" is
    dropped; trailing zeros do not count (2.0 == 2.0.0, and both are above
    2.0.0-rc1).

    semver=True (npm, Go, Cargo): everything after the first "-" is a
    pre-release, so 1.0.0-0 < 1.0.0 and 2.0.0-1 < 2.0.0; build metadata
    ("+...") is ignored. Maven/PyPI keep the default, where 2.0.0-1 is a
    post-release above 2.0.0.
    """
    pre = {"dev": 0, "snapshot": 1, "a": 2, "alpha": 2, "b": 3, "beta": 3,
           "m": 4, "milestone": 4, "pre": 5, "preview": 5, "c": 6, "rc": 6, "cr": 6}
    s = re.sub(r"^[vV](?=\d)", "", str(v or "").strip())
    if semver:
        main, _, prerel = s.split("+", 1)[0].partition("-")
        k = version_key(main)[:-1]
        if not prerel:
            return k + ((1, 0, ""),)
        # SemVer 11: dot-separated identifiers; numeric ones compare as
        # numbers and below alphanumeric ones ("alpha1" is one identifier,
        # "alpha.1" two); fewer identifiers sort lower when all else is equal.
        tail = tuple((1, int(i), "") if i.isdigit() else (2, 0, i)
                     for i in prerel.split("."))
        return k + ((0, -1, ""),) + tail + ((0, 0, ""),)
    out: list = []

    def trim() -> None:
        # Zeros at the end of a numeric run carry no ordering information.
        while len(out) > 1 and out[-1] == (2, 0, "") and out[-2][0] == 2:
            out.pop()

    for tok in re.findall(r"\d+|[A-Za-z]+", s):
        low = tok.lower()
        if tok.isdigit():
            out.append((2, int(tok), ""))
            continue
        if low in ("final", "ga", "release", "r"):
            continue
        trim()
        out.append((0, pre[low], "") if low in pre else (1, 0, low))
    trim()
    out.append((1, 0, ""))
    return tuple(out)


# OSV ecosystems whose versions follow SemVer pre-release rules.
SEMVER_ECOSYSTEMS = {"npm", "go", "crates.io"}


def is_commit_hash(s: str) -> bool:
    """A git SHA, as OSV gives for GIT ranges - not a release number.

    Hex with at least one letter: an all-digit string of 7+ digits is a
    date-style version (org.json 20231013), not a hash.
    """
    return bool(re.fullmatch(r"[0-9a-f]{7,40}", s)) and not s.isdigit()


def fix_from_affected(affected: list, eco: Any, want: str, installed: str) -> Any:
    """Smallest fix in OSV `affected` entries for package `want` at version `installed`.

    Only the entry for that exact package counts, and only the range that
    contains the installed version. An advisory covering Tomcat 9, 10 and 11
    lists a fix per branch; taking the largest string across all of them told
    an 11.0.22 user to "upgrade to >= 9.0.121". GIT ranges (whose "fixed" is
    a commit SHA) are skipped. Returns None when no published fix applies.
    """
    sv = eco in SEMVER_ECOSYSTEMS
    vk = lambda x: version_key(x, semver=sv)
    ik = vk(installed)
    in_range: list = []
    later: list = []
    unfixed = False
    for aff in affected:
        pkg = aff.get("package") or {}
        if eco and str(pkg.get("ecosystem", "")).lower().split(":")[0] != eco:
            continue
        pname = str(pkg.get("name") or "")
        pname = re.sub(r"[-_.]+", "-", pname).lower() if eco == "pypi" else pname.lower()
        if pname != want:
            continue
        for rng in (aff.get("ranges") or []):
            if str(rng.get("type", "")).upper() == "GIT":
                continue
            # OSV's evaluation sorts events by version before pairing them;
            # "0" (introduced at the very beginning) sorts first.
            evs = [ev for ev in (rng.get("events") or [])
                   if isinstance(ev, dict) and ev]
            evs.sort(key=lambda ev: (0,) if str(next(iter(ev.values()))) == "0"
                     else (1, vk(next(iter(ev.values())))))
            intro = None
            spans = []
            for ev in evs:
                if "introduced" in ev:
                    intro = str(ev["introduced"])
                elif "fixed" in ev:
                    spans.append((intro, str(ev["fixed"]), False))
                    intro = None
                elif "last_affected" in ev:
                    spans.append((intro, str(ev["last_affected"]), True))
                    intro = None
            if intro is not None:
                spans.append((intro, None, False))
            for lo, end, inclusive in spans:
                if end and not inclusive and is_commit_hash(end):
                    continue
                lo_ok = lo in (None, "0") or vk(lo) <= ik
                if end is None:
                    hit = lo_ok
                elif inclusive:
                    hit = lo_ok and ik <= vk(end)
                else:
                    hit = lo_ok and ik < vk(end)
                    if vk(end) > ik:
                        later.append(end)
                if hit and end and not inclusive:
                    in_range.append(end)
                elif hit:
                    unfixed = True
    if in_range:
        return min(in_range, key=vk)
    if unfixed:
        # Inside a range with no published fix on its branch: a fix from
        # another branch is not this version's fix.
        return None
    # The installed version sits in no listed range (OSV matched it some other
    # way, e.g. an explicit `versions` list): nearest fix above it.
    return min(later, key=vk) if later else None


OSV_ECOSYSTEM = {"pypi": "pypi", "npm": "npm", "maven": "maven", "golang": "go",
                 "cargo": "crates.io", "nuget": "nuget", "gem": "rubygems",
                 "composer": "packagist"}


def osv_name(p: dict) -> str:
    """The package name as OSV writes it for this purl."""
    ptype = str(p.get("type") or "").lower()
    name, ns = str(p.get("name") or ""), p.get("namespace")
    if ptype == "maven" and ns:
        return (str(ns) + ":" + name).lower()
    if ptype == "pypi":
        return norm_pyname(name)
    return ((str(ns) + "/" + name) if ns else name).lower()


def fix_for(d: dict, comp: dict) -> Any:
    """Smallest version that fixes advisory `d` for THIS component's version
    (see fix_from_affected), or None."""
    p = parse_purl(comp.get("purl"))
    inst = p.get("version")
    if not inst:
        return None
    eco = OSV_ECOSYSTEM.get(str(p.get("type") or "").lower())
    want = osv_name(p)
    return fix_from_affected(d.get("affected") or [], eco, want, inst)


def group_aliases(ids: list, details: dict) -> list:
    """Split advisory ids into groups that describe the same vulnerability."""
    groups: list = []
    for vid in ids:
        names = {vid} | {str(a) for a in ((details.get(vid) or {}).get("aliases") or [])}
        hit = [g for g in groups if g["names"] & names]
        merged = {"ids": [vid], "names": names}
        for g in hit:
            merged["ids"] = g["ids"] + merged["ids"]
            merged["names"] |= g["names"]
            groups.remove(g)
        groups.append(merged)
    return [list(dict.fromkeys(g["ids"])) for g in groups]


def pick_primary(group: list) -> str:
    """GitHub advisories carry a reviewed severity label; prefer them."""
    for prefix in ("GHSA-", "CVE-"):
        for g in group:
            if g.startswith(prefix):
                return g
    return sorted(group)[0]


def norm_severity(label: Any) -> str:
    s = str(label or "").lower()
    if s == "moderate":
        return "medium"
    return s if s in ("critical", "high", "medium", "low", "info", "none") else "unknown"


def osv_ratings(d: dict) -> list:
    """CycloneDX ratings for one OSV record, one per source of severity.

    Each CVSS vector gets its own rating with its own method. A score is only
    given where it was computed FROM that vector (v3.x); a v4 vector is
    recorded without a score rather than paired with the v3 one. The advisory
    database's own label, when there is one, comes first and is what the
    report shows.
    """
    out: list = []
    db = norm_severity((d.get("database_specific") or {}).get("severity"))
    if db != "unknown":
        src = "GitHub Advisory Database" if str(d.get("id", "")).startswith("GHSA-") \
            else "OSV"
        out.append({"source": {"name": src}, "severity": db, "method": "other"})
    for sev in (d.get("severity") or []):
        vec = str(sev.get("score") or "")
        if vec.startswith("CVSS:3"):
            score = cvss31_base_score(vec)
            r = {"method": "CVSSv31" if vec.startswith("CVSS:3.1") else "CVSSv3",
                 "vector": vec}
            if score is not None:
                r["score"] = score
                r["severity"] = severity_from_score(score)
            out.append(r)
        elif vec.startswith("CVSS:4"):
            out.append({"method": "CVSSv4", "vector": vec})
        elif str(sev.get("type", "")) == "CVSS_V2" and vec:
            out.append({"method": "CVSSv2", "vector": vec})
    return out


def headline_severity(v: dict) -> str:
    """The first rating that carries a severity: the database label if any."""
    for r in (v.get("ratings") or []):
        s = norm_severity(r.get("severity"))
        if s != "unknown":
            return s
    return "unknown"


def component_fixes(comp: dict, hits: list) -> list:
    """One fix version per advisory that has one, for this component."""
    keys = set(vuln_keys(comp))
    out = []
    for h in hits:
        byref = h.get("_fixByRef") or {}
        f = next((byref[k] for k in byref if k in keys), None)
        if f is None and h.get("_fixVersions"):
            f = max(h["_fixVersions"], key=comp_vkey(comp))
        if f:
            out.append(f)
    return out


def patch_status_for(comp: dict, vuln_index: dict, scanned: bool = True) -> str:
    hits = []
    for k in vuln_keys(comp):
        hits.extend(vuln_index.get(k, []))
    if not hits:
        if not scanned:
            return ("NOT ASSESSED - no vulnerability scan supplied "
                    "(pass --vulns or --scan-osv)")
        # Only vulnerabilities were checked, not whether a newer release
        # exists, so "up to date" would claim more than was looked at.
        return ("no known vulnerabilities at scan time "
                "(newer releases not checked)")
    seen = {}
    for h in hits:
        seen[h.get("id") or id(h)] = h
    hits = list(seen.values())
    fixes = component_fixes(comp, hits)
    worst = max((SEV_ORDER.get(headline_severity(h), 0) for h in hits), default=0)
    label = SEV_LABEL.get(worst, "unknown")
    n = len(hits)
    if fixes and len(fixes) == n:
        return ("patch available (upgrade to >= " + max(fixes, key=comp_vkey(comp))
                + "); " + str(n) + " known issue(s), max severity " + label)
    if fixes:
        return ("partial patch (upgrade to >= " + max(fixes, key=comp_vkey(comp))
                + " fixes " + str(len(fixes)) + " of " + str(n)
                + "); max severity " + label)
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
        description="Enrich a CycloneDX SBOM to CERT-In SBOM Guidelines s4.2")
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

    # ---- BOM-level fields: identity, author, timestamp, supplier ---------
    # The enriched SBOM is a different document from its input (vulnerabilities,
    # thousands of properties, rewritten licences), so it gets its own serial
    # and timestamp. Sharing them made consumers that key on serial+version
    # treat the two as one. The input's serial is kept for traceability.
    md = bom.setdefault("metadata", {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    md.setdefault("properties", [])
    # Findings already in the input are dropped. Whether they came from an
    # earlier run of this script or were carried through merge_boms.py from
    # a generator, they describe an earlier moment, and without their scan
    # provenance they would sit in field 8 while patch status said "not
    # assessed". This run's findings come only from --vulns / --scan-osv;
    # to keep a file's findings, pass it as --vulns.
    if bom.get("vulnerabilities"):
        log("NOTE dropped " + str(len(bom["vulnerabilities"])) + " finding(s) "
            "already in the input; pass a findings file with --vulns to keep them")
    bom["vulnerabilities"] = []
    md["properties"] = [p for p in md["properties"] if p.get("name") not in (
        "certin:vulnScanSource", "certin:vulnScanTime",
        "certin:unscannableComponents")]
    if bom.get("serialNumber"):
        md["properties"] = [p for p in md["properties"]
                            if p.get("name") != "certin:derivedFromSerial"]
        md["properties"].append({"name": "certin:derivedFromSerial",
                                 "value": str(bom["serialNumber"])})
    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid4())
    bom["version"] = 1
    md["timestamp"] = now
    tools = md.setdefault("tools", {"components": []})
    if isinstance(tools, dict):
        # Replace, never duplicate: the schema requires unique tool entries,
        # and re-enriching an enriched SBOM must stay valid.
        tc = [t for t in (tools.get("components") or [])
              if not (isinstance(t, dict) and t.get("name") == "certin_enrich.py")]
        tc.append({"type": "application", "name": "certin_enrich.py",
                   "version": TOOL_VERSION})
        tools["components"] = tc
    if not md.get("authors"):
        author = (project.get("sbomAuthor")
                  or os.environ.get("GITHUB_REPOSITORY")
                  or project.get("organization"))
        if author:
            md["authors"] = [{"name": str(author)}]
    if not md.get("supplier") and project.get("organization"):
        md["supplier"] = {"name": str(project["organization"])}
    bom_props = [
        ("certin:guidelineVersion", GUIDELINE),
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
    if cdx_vulns:
        cdx_vulns, vuln_index = attach_to_components(cdx_vulns, components, root)
    if not direct:
        # no usable graph -> treat all as direct so criticality stays meaningful
        for c in components:
            direct.update(vuln_keys(c))

    # Declared direct dependencies (requirements.in / pyproject.toml) override
    # whatever the graph implied. Also written back into the root's dependsOn
    # so the SBOM's own graph (field 7) is correct, not just our criticality.
    declared = load_declared_direct(args.direct_deps) if args.direct_deps else set()
    if declared:
        root_dep = next((d for d in (bom.get("dependencies") or [])
                         if root_ref and d.get("ref") == root_ref), None)
        promoted = 0
        for c in components:
            # Declared names are Python package names: an npm or Maven
            # component that happens to share one is not being declared.
            if str(parse_purl(c.get("purl")).get("type") or "").lower() != "pypi":
                continue
            if norm_pyname(c.get("name")) not in declared:
                continue
            keys = vuln_keys(c)
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
            try:
                osv_index, osv_vulns, unscannable = scan_osv(components)
            except ScanIncomplete as e:
                log("ERROR vulnerability scan incomplete: " + str(e))
                log("No SBOM written: an incomplete scan would report "
                    "unchecked components as having no known vulnerabilities.")
                return 3
            for k, v in osv_index.items():
                vuln_index.setdefault(k, []).extend(v)
            suppress_by_vex(vuln_index, cdx_vulns, components, root)
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
        md["properties"].append({"name": "certin:vulnScanSource",
                                 "value": scan_source})
        md["properties"].append({"name": "certin:vulnScanTime", "value": now})
        if unscannable:
            md["properties"].append(
                {"name": "certin:unscannableComponents",
                 "value": str(len(unscannable))})

    log("enriching " + str(len(components)) + " components ("
        + ("offline" if args.offline else "online lookups enabled") + ")")

    eol_cache: dict = {}
    meta_cache: dict = {}
    spdx_added = 0
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

        # supplier: generator -> curated -> registry-declared author.
        # A Maven groupId is a namespace, not an organisation, so it is never
        # used ("org.apache.tomcat.embed" is not a supplier). Where the value
        # came from is recorded, because the report attributes field 4 to the
        # generator and 59 of 146 were not.
        if (comp.get("supplier") or {}).get("name") or comp.get("publisher"):
            set_prop(comp, "supplierSource", "generator")
        else:
            if entry.get("supplier"):
                sup, src = entry["supplier"], "curated metadata"
            else:
                sup, src = online.get("supplier"), "package registry author field"
            if sup:
                comp["supplier"] = {"name": str(sup)}
                set_prop(comp, "supplierSource", src)

        # description: generator -> curated -> registry
        if not comp.get("description"):
            desc = entry.get("description") or online.get("description")
            if desc:
                comp["description"] = str(desc)

        # Resolve trove classifiers into SPDX identifiers IN the document,
        # not just for the lookup below.
        spdx_added += normalise_component_licenses(comp)

        # usage restrictions (field 13): curated -> licence table -> flagged.
        # Never guessed: an unrecognised licence produces a loud marker so a
        # human routes it to Legal.
        if entry.get("usageRestrictions"):
            set_prop(comp, "usageRestrictions", entry["usageRestrictions"], overwrite=True)
        elif lic_table:
            rtext, rcat, rrisk, runknown = resolve_restrictions(comp, lic_table)
            set_prop(comp, "usageRestrictions", rtext, overwrite=True)
            set_prop(comp, "licenseCategory", rcat, overwrite=True)
            set_prop(comp, "distributionRisk", rrisk, overwrite=True)
            if runknown:
                unrecognised_licences.setdefault(
                    ", ".join(runknown), []).append(
                        str(comp.get("name")) + "@" + str(comp.get("version")))
        else:
            set_prop(comp, "usageRestrictions",
                     defaults.get("usageRestrictions", "none"), overwrite=True)
        set_prop(comp, "comments", entry.get("comments"))
        set_prop(comp, "origin",
                 entry.get("origin") or derive_origin(comp, org_names), overwrite=True)

        # dates
        set_prop(comp, "releaseDate",
                 entry.get("releaseDate") or online.get("releaseDate"))
        # EOL: curated -> endoflife.date -> default. Refreshed on every online
        # run. An offline run did not look, so it says so instead of claiming
        # the supplier publishes nothing, and it keeps a value found earlier.
        if entry.get("eolDate"):
            set_prop(comp, "eolDate", entry["eolDate"], overwrite=True)
        elif args.offline:
            set_prop(comp, "eolDate", "not looked up (offline run)")
        else:
            set_prop(comp, "eolDate",
                     lookup_eol(comp, eol_cache, args.offline)
                     or defaults.get("eolDate", "not published by supplier"),
                     overwrite=True)

        # vulnerabilities -> patch status (always recomputed; it is time-sensitive)
        set_prop(comp, "patchStatus",
                 entry.get("patchStatus")
                 or patch_status_for(comp, vuln_index, scanned=scan_ran),
                 overwrite=True)

        # criticality. sbom-metadata.yml calls this human judgement; where no
        # human has ruled, the derived value says so rather than passing as one.
        if entry.get("criticality"):
            set_prop(comp, "criticality", entry["criticality"], overwrite=True)
            set_prop(comp, "criticalitySource", "curated metadata", overwrite=True)
        else:
            set_prop(comp, "criticality",
                     derive_criticality(comp, direct, vuln_index), overwrite=True)
            set_prop(comp, "criticalitySource",
                     "derived: vulnerable+direct=critical, vulnerable=high, "
                     "direct=medium, else low; not yet reviewed", overwrite=True)

        # file-nature properties. Derived values above are recomputed on every
        # run (overwrite=True): re-enriching must not keep a criticality or
        # licence risk that the new data no longer supports.
        ex, ar, st = derive_file_props(comp)
        set_prop(comp, "executable", entry.get("executable", ex), overwrite=True)
        set_prop(comp, "archive", entry.get("archive", ar), overwrite=True)
        set_prop(comp, "structured", entry.get("structured", st), overwrite=True)

        set_prop(comp, "enrichedBy", "certin_enrich.py")

    if spdx_added:
        log("normalised " + str(spdx_added) + " licence entr(ies) to SPDX "
            "(classifiers added as concluded; known names, deprecated ids and "
            "Maven multi-licence lists rewritten)")

    # ---- attach vulnerabilities (VDR) ------------------------------------
    # Sorted, so an identical scan yields an identical document: OSV's
    # response order varies, and the inventory publish step compares content.
    out_vulns = []
    for vd in sorted(cdx_vulns, key=lambda x: str(x.get("id"))):
        rec = {k: v for k, v in vd.items() if not k.startswith("_")}
        if rec.get("affects"):
            rec["affects"] = sorted(rec["affects"], key=lambda a: str(a.get("ref")))
        out_vulns.append(rec)
    bom["vulnerabilities"] = out_vulns

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
            "Generated by `certin_enrich.py` against **" + GUIDELINE
            + ", section 4.2** (the 21 fields are unchanged from v1.0).",
            "",
            "- Input: `" + os.path.basename(args.input) + "`; the figures below "
            "measure the enriched output `" + os.path.basename(args.output) + "`",
            "- Components analysed: **" + str(total) + "**",
            "- Vulnerabilities recorded: **" + str(nvulns) + "** ("
            + str(len({c for v in cdx_vulns
                       for c in (v.get("_cves")
                                 or [x for x in [str(v.get("id") or "")]
                                     if x.startswith("CVE-")])}))
            + " distinct CVE ids; advisories describing the same CVE are merged)",
            "- Overall field coverage: **" + ("%.1f" % overall) + "%**",
            "- SBOM timestamp: `" + str(md.get("timestamp")) + "`",
        ]
        if lic_table and not (lic_table.get("meta") or {}).get("reviewed"):
            lines.append("- **Usage restrictions (field 13) are DRAFT**: the "
                         "licence table has not been reviewed by Legal "
                         "(`meta.reviewed: false`)")
        lines += [
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
        # ---- the findings themselves -------------------------------
        # A report that says "59 vulnerabilities recorded" and then never
        # names one makes the reader open a 500KB JSON to learn anything.
        # cdx_vulns still carries the internal _fixVersions/_cves keys;
        # bom["vulnerabilities"] has had them stripped for output.
        # Only findings counted against a component (see the vulnerability
        # index): a VEX "not_affected" entry stays in the SBOM but is not an
        # exposure, so it is not listed or counted here.
        def counted(v: dict, ref: Any) -> bool:
            return any(x is v for x in vuln_index.get(ref, []))
        vulns = [v for v in cdx_vulns
                 if any(counted(v, a.get("ref")) for a in (v.get("affects") or []))]
        if vulns:
            sev_rank = {"critical": 4, "high": 3, "medium": 2,
                        "moderate": 2, "low": 1}
            # group by affected component
            label_for = {}
            for c in components:
                lbl = (((str(c.get("group")) + "/") if c.get("group") else "")
                       + str(c.get("name")) + "@" + str(c.get("version")))
                # Classifier variants (netty linux/osx) are separate files and
                # get separate rows, not one row counting both sets.
                cls = [q for q in str(c.get("purl") or "").partition("?")[2].split("&")
                       if q.startswith("classifier=")]
                if cls:
                    lbl += " [" + cls[0].split("=", 1)[1] + "]"
                for k in (c.get("bom-ref"), c.get("purl")):
                    if k:
                        label_for[k] = lbl
            grouped: dict = {}
            comp_for: dict = {}
            for c in components:
                for k in vuln_keys(c):
                    comp_for.setdefault(k, c)
            for v in vulns:
                for aff in (v.get("affects") or []):
                    if not counted(v, aff.get("ref")):
                        continue
                    key = label_for.get(aff.get("ref"), str(aff.get("ref")))
                    grouped.setdefault(key, []).append(v)
                    comp_for.setdefault(key, comp_for.get(aff.get("ref"), {}))

            def worst_of(vs):
                return max((sev_rank.get(headline_severity(x), 0) for x in vs),
                           default=0)

            sev_of = headline_severity

            counts: dict = {}
            for v in vulns:
                counts[sev_of(v)] = counts.get(sev_of(v), 0) + 1
            tally = ", ".join(str(counts[k]) + " " + k for k in
                              sorted(counts, key=lambda k: -sev_rank.get(k, 0)))

            # The product root is not one of the `total` components.
            root_label = str(root_ref) if root_ref else None
            n_comp = len([k for k in grouped if k != root_label])
            on_root = root_label in grouped
            not_counted = nvulns - len(vulns)
            lines += ["", "## Vulnerability findings", "",
                      "**" + str(len(vulns)) + " advisor"
                      + ("y" if len(vulns) == 1 else "ies")
                      + " affecting " + str(n_comp)
                      + " of " + str(total) + " components"
                      + (" and the product itself" if on_root else "")
                      + "** — " + tally + "."
                      + ((" A further " + str(not_counted) + " recorded finding(s) "
                          "are marked not applicable (VEX) and not counted.")
                         if not_counted > 0 else ""),
                      "",
                      "Scanned against " + str(scan_source or "no source")
                      + " at " + now + ". An advisory match means a "
                      "version range matches; it does not confirm the vulnerable "
                      "code is reachable in this product.",
                      "",
                      "| Severity | Component | Advisories | Fix available | CVE / advisory ids |",
                      "|---|---|---|---|---|"]
            for comp_label in sorted(grouped,
                                     key=lambda c: (-worst_of(grouped[c]),
                                                    -len(grouped[c]), c)):
                vs = grouped[comp_label]
                sev = {4: "critical", 3: "high", 2: "medium",
                       1: "low"}.get(worst_of(vs), "unrated")
                ccomp = comp_for.get(comp_label) or {}
                fixes = component_fixes(ccomp, vs)
                if not fixes:
                    fix = "none published"
                else:
                    fix = "upgrade to >= " + max(fixes, key=comp_vkey(ccomp))
                    if len(fixes) < len(vs):
                        fix += " (fixes " + str(len(fixes)) + " of " + str(len(vs)) + ")"
                ids = []
                for x in vs:
                    cves = x.get("_cves") or []
                    ids.extend(cves if cves else [str(x.get("id"))])
                ids = list(dict.fromkeys(ids))
                shown = ", ".join(ids[:3])
                if len(ids) > 3:
                    shown += " +" + str(len(ids) - 3)
                lines.append("| " + sev + " | `" + comp_label + "` | "
                             + str(len(vs)) + " | " + fix + " | " + shown + " |")
            lines.append("")

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
