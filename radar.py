
#!/usr/bin/env python3
"""Dependency Risk Radar: inspect Python requirements for dependency risk."""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests
from packaging.requirements import Requirement
from packaging.version import InvalidVersion, Version

PYPI_URL = "https://pypi.org/pypi/{}/json"
OSV_URL = "https://api.osv.dev/v1/query"
TIMEOUT = 12


def parse_requirements(file_path):
    """Parse requirements.txt, ignoring comments and unsupported options."""
    dependencies = []

    for line_number, raw in enumerate(
        Path(file_path).read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw.strip()

        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Remove inline comments preceded by whitespace.
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()

        # requirements.txt may contain environment markers.
        try:
            requirement = Requirement(line)
        except Exception:
            print(
                f"Warning: skipping unrecognized line {line_number}: {line}",
                file=sys.stderr,
            )
            continue

        # This first version checks ordinary PyPI dependencies.
        if requirement.url:
            print(
                f"Warning: skipping direct URL dependency: {requirement.name}",
                file=sys.stderr,
            )
            continue

        if requirement.marker and not requirement.marker.evaluate():
            continue

        dependencies.append({
            "name": requirement.name,
            "specifier": str(requirement.specifier),
            "line": line_number,
        })

    return dependencies


def fetch_json(url, payload=None):
    """Fetch JSON, returning None when the service is unavailable."""
    try:
        if payload is None:
            response = requests.get(url, timeout=TIMEOUT)
        else:
            response = requests.post(
                url,
                json=payload,
                timeout=TIMEOUT,
                headers={"Content-Type": "application/json"},
            )

        if response.status_code == 404:
            return None

        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as exc:
        print(f"Warning: API request failed: {exc}", file=sys.stderr)
        return None


def check_dependency(dependency):
    name = dependency["name"]
    specifier = dependency["specifier"]

    result = {
        **dependency,
        "latest_version": None,
        "outdated": None,
        "vulnerabilities": [],
        "risk": "UNKNOWN",
        "evidence": [],
    }

    # Query the current package metadata from PyPI.
    pypi = fetch_json(PYPI_URL.format(quote(name, safe="")))

    if pypi:
        latest = pypi.get("info", {}).get("version")
        result["latest_version"] = latest

        if latest:
            result["evidence"].append({
                "type": "package_release",
                "url": f"https://pypi.org/project/{quote(name, safe='')}/",
            })

            if specifier:
                try:
                    # Check whether the latest release satisfies the
                    # declared requirement, not whether it is installed.
                    result["outdated"] = not Version(latest) in (
                        __import__("packaging.specifiers", fromlist=["SpecifierSet"])
                        .SpecifierSet(specifier)
                    )
                except InvalidVersion:
                    result["outdated"] = None
            else:
                result["outdated"] = None

    # Query OSV for known vulnerabilities affecting this package version.
    # Version constraints in requirements.txt are not proof of the
    # version actually installed in a running environment.
    osv_payload = {
        "package": {"name": name, "ecosystem": "PyPI"},
    }

    osv = fetch_json(OSV_URL, osv_payload)

    if osv is not None:
        for vuln in osv.get("vulns", []):
            aliases = vuln.get("aliases", [])
            vuln_id = vuln.get("id", "Unknown")
            result["vulnerabilities"].append({
                "id": vuln_id,
                "aliases": aliases,
                "summary": vuln.get("summary", "No summary supplied"),
                "url": f"https://osv.dev/vulnerability/{quote(vuln_id, safe='')}",
            })

    # The package-level OSV query above finds advisories for the package;
    # it does NOT establish that a particular installed version is affected.
    if result["vulnerabilities"]:
        result["risk"] = "REVIEW"
        result["evidence"].append({
            "type": "osv_advisories",
            "url": f"https://osv.dev/list?ecosystem=PyPI&name={quote(name, safe='')}",
        })
    elif result["outdated"] is True:
        result["risk"] = "REVIEW"
        result["evidence"].append({
            "type": "declared_version_constraint",
            "detail": f"Latest release {result['latest_version']} "
                      f"does not satisfy {specifier}",
        })
    elif result["latest_version"]:
        result["risk"] = "LOW"
    else:
        result["risk"] = "UNKNOWN"

    return result


def print_report(results):
    print("\nDEPENDENCY RISK RADAR")
    print("=" * 72)

    for item in results:
        print(f"\n{item['name']}  [{item['risk']}]")
        print(f"  Requirement: {item['specifier'] or '(unconstrained)'}")
        print(f"  Latest PyPI version: {item['latest_version'] or 'unknown'}")
        print(f"  Constraint excludes latest: {item['outdated']}")

        if item["vulnerabilities"]:
            print(f"  OSV advisories: {len(item['vulnerabilities'])}")
            for vuln in item["vulnerabilities"]:
                print(f"    - {vuln['id']}: {vuln['summary']}")
                print(f"      {vuln['url']}")
        else:
            print("  OSV advisories returned: 0")

        for evidence in item["evidence"]:
            print(f"  Evidence: {evidence.get('url', evidence.get('detail', ''))}")

    print("\nNote: UNKNOWN means a check could not be completed.")
    print("A package-level advisory does not prove your version is vulnerable.")


def main():
    parser = argparse.ArgumentParser(
        description="Scan Python requirements for dependency risk."
    )
    parser.add_argument(
        "requirements",
        nargs="?",
        default="requirements.txt",
        help="Path to requirements.txt",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        default="risk-report.json",
        help="JSON report path (default: risk-report.json)",
    )
    args = parser.parse_args()

    path = Path(args.requirements)
    if not path.is_file():
        parser.error(f"Requirements file not found: {path}")

    dependencies = parse_requirements(path)
    results = [check_dependency(dep) for dep in dependencies]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(path),
        "dependency_count": len(results),
        "results": results,
    }

    print_report(results)
    Path(args.json_path).write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(f"\nJSON report written to: {args.json_path}")


if __name__ == "__main__":
    main()
