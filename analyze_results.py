#!/usr/bin/env python3
"""Aggregate Seyon scan results from batch scanning."""
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

def load_results(results_dir):
    """Load all JSON result files."""
    results = []
    for f in sorted(Path(results_dir).glob("*.json")):
        try:
            data = json.loads(f.read_text())
            if "error" in data:
                continue
            data["_file"] = f.name
            results.append(data)
        except (json.JSONDecodeError, Exception):
            continue
    return results

def analyze(results):
    """Produce aggregate statistics."""
    total_repos = len(results)
    total_findings = 0
    by_severity = Counter()
    by_class = Counter()
    by_confidence = Counter()
    by_cwe = Counter()
    by_owasp = Counter()
    repos_with_critical = []
    repos_with_high = []
    finding_details = []

    for r in results:
        findings = r.get("findings", [])
        repo = r.get("target", r.get("_file", "unknown"))
        total_findings += len(findings)

        has_critical = False
        has_high = False
        for f in findings:
            sev = f.get("severity", "unknown")
            cls = f.get("class", "unknown")
            conf = f.get("confidence", "unknown")
            cwe = f.get("cwe", "")
            owasp_ids = f.get("owasp_ids", [])

            by_severity[sev] += 1
            by_class[cls] += 1
            by_confidence[conf] += 1
            if cwe:
                by_cwe[cwe] += 1
            for oid in owasp_ids:
                by_owasp[oid] += 1

            if sev == "critical":
                has_critical = True
            if sev == "high":
                has_high = True

            finding_details.append({
                "repo": repo,
                "class": cls,
                "severity": sev,
                "confidence": conf,
                "title": f.get("title", ""),
                "source": f.get("target", {}).get("source", ""),
                "tool": f.get("target", {}).get("tool", ""),
                "cwe": cwe,
            })

        if has_critical:
            repos_with_critical.append(repo)
        if has_high:
            repos_with_high.append(repo)

    return {
        "total_repos_scanned": total_repos,
        "total_findings": total_findings,
        "by_severity": dict(by_severity.most_common()),
        "by_class": dict(by_class.most_common()),
        "by_confidence": dict(by_confidence.most_common()),
        "by_cwe_top20": dict(by_cwe.most_common(20)),
        "by_owasp_top10": dict(by_owasp.most_common(10)),
        "repos_with_critical": len(repos_with_critical),
        "repos_with_high": len(repos_with_high),
        "avg_findings_per_repo": round(total_findings / max(total_repos, 1), 1),
    }

def print_report(stats):
    """Print a formatted summary report."""
    print("=" * 70)
    print("SEYON MCP ECOSYSTEM SECURITY SCAN — AGGREGATE REPORT")
    print("=" * 70)
    print(f"\nRepos scanned:          {stats['total_repos_scanned']}")
    print(f"Total findings:         {stats['total_findings']}")
    print(f"Avg findings/repo:      {stats['avg_findings_per_repo']}")
    print(f"Repos with critical:    {stats['repos_with_critical']}")
    print(f"Repos with high:        {stats['repos_with_high']}")

    print("\n--- By Severity ---")
    for sev, cnt in stats["by_severity"].items():
        print(f"  {sev:12s}  {cnt:6d}")

    print("\n--- By Finding Class ---")
    for cls, cnt in stats["by_class"].items():
        print(f"  {cls:6s}  {cnt:6d}")

    print("\n--- By Confidence ---")
    for conf, cnt in stats["by_confidence"].items():
        print(f"  {conf:12s}  {cnt:6d}")

    print("\n--- Top 20 CWEs ---")
    for cwe, cnt in stats["by_cwe_top20"].items():
        print(f"  {cwe:12s}  {cnt:6d}")

    print("\n--- OWASP MCP Top 10 ---")
    for oid, cnt in stats["by_owasp_top10"].items():
        print(f"  {oid:8s}  {cnt:6d}")

if __name__ == "__main__":
    results_dir = sys.argv[1] if len(sys.argv) > 1 else "scan_results"
    results = load_results(results_dir)
    if not results:
        print(f"No results found in {results_dir}/")
        sys.exit(1)
    stats = analyze(results)
    print_report(stats)
    # Save JSON summary
    summary_path = os.path.join(results_dir, "_summary.json")
    with open(summary_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"\nSummary saved to {summary_path}")
