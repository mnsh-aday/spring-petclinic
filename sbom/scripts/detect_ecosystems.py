#!/usr/bin/env python3
"""
detect_ecosystems.py -- find every dependency manifest in a repository.

This is the piece that makes ONE workflow serve every repo. It walks the
checkout, finds the manifests that identify each package ecosystem, and emits
JSON the workflow uses to decide which SBOM generators to run.

Design rules, each learned the hard way on this project:

  1. SEARCH SUBDIRECTORIES. Real repos keep manifests in backend/, frontend/,
     services/x/. A root-only check finds nothing and produces an empty SBOM
     that looks clean.

  2. REPORT EVERY MATCH, not just the first. A monorepo with three
     package-lock.json files needs the generator run three times.

  3. NAME WHAT IS DETECTED BUT NOT SUPPORTED. A build.gradle we cannot yet
     handle must surface as a loud gap, never as silence.

  4. FAIL IF NOTHING IS FOUND. An SBOM of zero components is not a result,
     it is a misconfiguration.

Usage:
  detect_ecosystems.py [repo-root] [--github-output FILE]

Prints JSON to stdout. With --github-output, also writes key=value lines in
the form GitHub Actions reads from $GITHUB_OUTPUT.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# Directories that hold vendored or generated code. Manifests inside these
# belong to dependencies, not to the project, and must be ignored or the
# generator runs hundreds of times.
SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", ".tox", "__pycache__",
    "target", "build", "dist", "out", ".gradle", ".idea", ".vscode",
    "site-packages", ".mvn", "bower_components", ".next", ".nuxt", "vendor",
}

# manifest filename -> ecosystem key
SUPPORTED = {
    "package-lock.json": "npm",
    "requirements.txt": "python",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "build.sbt": "sbt",
    # Swift: only LOCKFILES. Package.swift alone states ranges, not the
    # versions actually in use - the same reason pom.xml needs Maven to run.
    "Package.resolved": "swift",
    "Podfile.lock": "swift",
}

# Detected and named, but no generator wired in yet. These appear in the
# report as gaps so nobody mistakes "not scanned" for "nothing there".
UNSUPPORTED = {
    "yarn.lock": "npm (yarn lockfile - use cyclonedx-npm on package-lock, or add yarn support)",
    "pnpm-lock.yaml": "npm (pnpm lockfile)",
    "go.mod": "go",
    "Cargo.lock": "rust",
    "Gemfile.lock": "ruby",
    "composer.lock": "php",
    "Package.swift": "swift (Package.swift with no committed Package.resolved - run `swift package resolve` and commit the lockfile)",
    "pyproject.toml": "python (pyproject - only if no requirements.txt beside it)",
    "poetry.lock": "python (poetry)",
    "Pipfile.lock": "python (pipenv)",
}


def outermost(dirs: list) -> list:
    """Keep only directories with no ancestor in the list.

    A Gradle or sbt build at a parent directory already aggregates its
    sub-projects; running the generator again in each child would rebuild the
    same dependencies several times and, for Gradle, can fail outright when a
    child is not runnable on its own.
    """
    keep: list = []
    for d in sorted(dirs, key=lambda x: (0 if x == "." else x.count("/") + 1, x)):
        if d == "." or not any(k == "." or d.startswith(k + "/") for k in keep):
            keep.append(d)
    return keep


def java_version_from_pom(pom_path: str) -> str | None:
    """Best-effort read of the Java release a pom.xml targets.

    Checks the properties Spring Boot and plain Maven projects actually use.
    Returns e.g. "17", or None if nothing is declared (caller defaults).
    """
    try:
        with open(pom_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    for tag in ("java.version", "maven.compiler.release",
                "maven.compiler.source", "maven.compiler.target", "release"):
        m = re.search(r"<" + re.escape(tag) + r">\s*(1\.)?(\d+)\s*</" + re.escape(tag) + ">", text)
        if m:
            return m.group(2)
    return None


def java_version_from_gradle(build_dir: str) -> str | None:
    """Best-effort read of the Java version a Gradle build targets."""
    for name in ("build.gradle", "build.gradle.kts"):
        p = os.path.join(build_dir, name)
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for pat in (r"JavaLanguageVersion\.of\(\s*(\d+)\s*\)",
                    r"jvmToolchain\(\s*(\d+)\s*\)",
                    r"JavaVersion\.VERSION_(?:1_)?(\d+)",
                    r"sourceCompatibility\s*=?\s*['\"]?(?:1\.)?(\d+)"):
            m = re.search(pat, text)
            if m:
                return m.group(1)
    return None


def find_maven_settings(root: str) -> str | None:
    """Locate the settings file a repo's own CI uses, if it ships one."""
    candidates = [
        ".github/workflows/maven-settings.xml",
        ".github/maven-settings.xml",
        ".mvn/settings.xml",
        "maven-settings.xml",
        "settings.xml",
    ]
    for rel in candidates:
        p = os.path.join(root, rel)
        if os.path.isfile(p):
            return rel.replace(os.sep, "/")
    return None


def detect(root: str) -> dict:
    root = os.path.abspath(root)
    found: dict = {k: [] for k in set(SUPPORTED.values())}
    unsupported: dict = {}

    for dirpath, dirnames, filenames in os.walk(root):
        # prune vendored/generated trees in place so os.walk never descends
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir

        for fn in filenames:
            if fn in SUPPORTED:
                found[SUPPORTED[fn]].append(rel_dir or ".")
            elif fn in UNSUPPORTED:
                unsupported.setdefault(UNSUPPORTED[fn], []).append(
                    (rel_dir + "/" if rel_dir else "") + fn)

    # pyproject.toml is only a gap when there is no requirements.txt beside it
    key = UNSUPPORTED["pyproject.toml"]
    if key in unsupported:
        py_dirs = set(found["python"])
        unsupported[key] = [p for p in unsupported[key]
                            if os.path.dirname(p) not in py_dirs
                            and (os.path.dirname(p) or ".") not in py_dirs]
        if not unsupported[key]:
            del unsupported[key]

    # de-duplicate while keeping discovery order
    for k in found:
        found[k] = list(dict.fromkeys(found[k]))

    # Package.swift is only a gap when no lockfile sits beside it.
    key = UNSUPPORTED["Package.swift"]
    if key in unsupported:
        swift_dirs = set(found["swift"])
        unsupported[key] = [p for p in unsupported[key]
                            if (os.path.dirname(p) or ".") not in swift_dirs]
        if not unsupported[key]:
            del unsupported[key]

    # A directory with BOTH pom.xml and build.gradle (Spring Petclinic ships
    # both) is one project described twice. Maven is proven here, so it wins
    # and Gradle is skipped for that directory - recorded, not silent.
    skipped: list = []
    maven_set = set(found["maven"])
    both = [d for d in found["gradle"] if d in maven_set]
    for d in both:
        skipped.append({"dir": d, "ecosystem": "gradle",
                        "reason": "pom.xml in the same directory; Maven used instead"})
    found["gradle"] = [d for d in found["gradle"] if d not in maven_set]

    # Multi-module Gradle and sbt builds: generate once at the outermost build.
    for eco in ("gradle", "sbt"):
        kept = outermost(found[eco])
        for d in found[eco]:
            if d not in kept:
                skipped.append({"dir": d, "ecosystem": eco,
                                "reason": "covered by the enclosing build"})
        found[eco] = kept

    # Files naming a Python project's DIRECT dependencies. requirements.txt is
    # frequently pip-freeze output - every package, transitives included - so
    # it cannot say what the developer asked for. requirements.in (pip-tools)
    # or pyproject.toml can. The enricher uses these to correct the direct
    # set; without them, 'direct' is approximated and Django-class packages
    # get misread as transitive because other packages depend on them.
    python_direct_files = []
    for d in found["python"]:
        base = root if d == "." else os.path.join(root, d)
        for cand in ("requirements.in", "pyproject.toml"):
            if os.path.isfile(os.path.join(base, cand)):
                python_direct_files.append((d + "/" if d != "." else "") + cand)

    java_version, java_source = None, "default"
    for d in found["maven"]:
        v = java_version_from_pom(os.path.join(root, d, "pom.xml"))
        if v:
            java_version, java_source = v, "pom.xml"
            break
    if not java_version:
        for d in found["gradle"]:
            v = java_version_from_gradle(root if d == "." else os.path.join(root, d))
            if v:
                java_version, java_source = v, "build.gradle"
                break

    result = {
        "root": root,
        "npm": found["npm"],
        "python": found["python"],
        "maven": found["maven"],
        "gradle": found["gradle"],
        "sbt": found["sbt"],
        "swift": found["swift"],
        "java_version": java_version or "17",
        "java_version_source": java_source,
        "maven_settings": find_maven_settings(root) if found["maven"] else None,
        "python_direct_files": python_direct_files,
        "skipped": skipped,
        "unsupported": unsupported,
        "any_supported": any(found.values()),
    }
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Detect package ecosystems in a repo")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--github-output", metavar="FILE",
                    help="also append key=value lines for GitHub Actions")
    args = ap.parse_args()

    r = detect(args.root)
    print(json.dumps(r, indent=2))

    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as f:
            f.write("has_npm=" + ("1" if r["npm"] else "0") + "\n")
            f.write("has_python=" + ("1" if r["python"] else "0") + "\n")
            f.write("has_maven=" + ("1" if r["maven"] else "0") + "\n")
            f.write("npm_dirs=" + " ".join(r["npm"]) + "\n")
            f.write("python_dirs=" + " ".join(r["python"]) + "\n")
            f.write("python_direct_files=" + " ".join(r["python_direct_files"]) + "\n")
            f.write("maven_dirs=" + " ".join(r["maven"]) + "\n")
            f.write("has_gradle=" + ("1" if r["gradle"] else "0") + "\n")
            f.write("gradle_dirs=" + " ".join(r["gradle"]) + "\n")
            f.write("has_sbt=" + ("1" if r["sbt"] else "0") + "\n")
            f.write("sbt_dirs=" + " ".join(r["sbt"]) + "\n")
            f.write("has_swift=" + ("1" if r["swift"] else "0") + "\n")
            f.write("swift_dirs=" + " ".join(r["swift"]) + "\n")
            # one JDK serves Maven, Gradle and sbt
            f.write("has_jvm=" + ("1" if (r["maven"] or r["gradle"] or r["sbt"]) else "0") + "\n")
            f.write("skipped_json=" + json.dumps(r["skipped"]) + "\n")
            f.write("java_version=" + r["java_version"] + "\n")
            f.write("maven_settings=" + (r["maven_settings"] or "") + "\n")
            f.write("has_unsupported=" + ("1" if r["unsupported"] else "0") + "\n")
            f.write("unsupported_json=" + json.dumps(r["unsupported"]) + "\n")

    # Rule 4: nothing found is a failure, not an empty success.
    if not r["any_supported"]:
        print("[detect] ERROR no supported manifests found under "
              + r["root"], file=sys.stderr)
        if r["unsupported"]:
            print("[detect] detected but unsupported: "
                  + ", ".join(r["unsupported"].keys()), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
