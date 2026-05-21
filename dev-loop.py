#!/usr/bin/env python3
"""
DeepSight Autonomous Development Pipeline

This script runs the continuous dev loop:
  1. Check for approved PRs → merge them
  2. Check for open PRs needing review → spawn review
  3. If no open PRs → pick next roadmap feature → implement → PR
  4. Update changelog on merges

Designed to be run as a cron job or scheduled task.
"""

import os
import sys
import json
import subprocess
import time
import re
from pathlib import Path

REPO_DIR = os.path.expanduser("~/apps/ram-dashboard")
ROADMAP = [
    # Phase 1 (highest ROI, lowest effort)
    {"feature": "syslog-ingestion", "title": "Syslog & external log ingestion",
     "desc": "UDP syslog server on port 514 for network device monitoring",
     "label": "enhancement", "phase": 1, "hours": 6},
    {"feature": "threat-intel", "title": "Threat intelligence feed integration",
     "desc": "AbuseIPDB, AlienVault OTX, URLhaus, Feodo, Tor exit nodes",
     "label": "enhancement", "phase": 1, "hours": 12},
    # Phase 2
    {"feature": "search-ui", "title": "Advanced search & investigation interface",
     "desc": "FTS5 full-text search with field-level query syntax",
     "label": "enhancement", "phase": 2, "hours": 15},
    {"feature": "security-dashboards", "title": "Security dashboards & visualization",
     "desc": "6 new Chart.js panels: alert timeline, top IPs, MITRE radar, agent health",
     "label": "enhancement", "phase": 2, "hours": 10},
    {"feature": "ueba-anomaly", "title": "UEBA + anomaly detection baselining",
     "desc": "Rolling z-score baselining with statistical alerting",
     "label": "enhancement", "phase": 2, "hours": 16},
    # Phase 3
    {"feature": "correlation-engine", "title": "Real-time event correlation engine",
     "desc": "Sequence matching for multi-stage attack chain detection",
     "label": "enhancement", "phase": 3, "hours": 20},
    {"feature": "case-management", "title": "Case management & incident tracking",
     "desc": "Full investigation workflow: triage → investigate → contain → close",
     "label": "enhancement", "phase": 3, "hours": 16},
    {"feature": "soar-playbooks", "title": "SOAR playbooks — enrichment only",
     "desc": "Automated enrichment playbooks on alert (threat intel, reverse DNS, GeoIP)",
     "label": "enhancement", "phase": 3, "hours": 12},
]


def run(cmd, **kwargs):
    """Run a command and return (returncode, stdout, stderr)."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                            cwd=kwargs.get("cwd", REPO_DIR), timeout=kwargs.get("timeout", 30))
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def gh_api(endpoint, method="GET", data=None):
    """Call GitHub API via gh CLI."""
    cmd = f"gh api {endpoint}"
    if method != "GET":
        cmd += f" --method {method}"
    if data:
        cmd += f" --input -"
    if data:
        result = subprocess.run(cmd, shell=True, input=json.dumps(data),
                                capture_output=True, text=True, cwd=REPO_DIR, timeout=15)
    else:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                cwd=REPO_DIR, timeout=15)
    try:
        return json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        return {}


def get_open_prs():
    """Get list of open PRs."""
    prs = gh_api("repos/R3dy/DeepSight/pulls?state=open&per_page=5")
    return prs if isinstance(prs, list) else []


def get_pr_reviews(pr_number):
    """Get reviews for a PR."""
    reviews = gh_api(f"repos/R3dy/DeepSight/pulls/{pr_number}/reviews?per_page=10")
    return reviews if isinstance(reviews, list) else []


def merge_pr(pr_number):
    """Merge a PR if approved."""
    print(f"[dev-loop] Merging PR #{pr_number}...")
    rc, stdout, stderr = run(f"gh pr merge {pr_number} --squash --delete-branch")
    if rc == 0:
        print(f"[dev-loop] ✅ PR #{pr_number} merged successfully")
        # Update changelog: remove "Unreleased" tag for this version
        return True
    else:
        print(f"[dev-loop] ❌ Failed to merge PR #{pr_number}: {stderr}")
        return False


def get_current_version():
    """Read VERSION file."""
    vf = Path(REPO_DIR) / "VERSION"
    if vf.exists():
        return vf.read_text().strip()
    return "0.1.0"


def bump_version(current, bump_type="minor"):
    """Bump semver version."""
    parts = [int(x) for x in current.split(".")]
    if bump_type == "major":
        parts[0] += 1; parts[1] = 0; parts[2] = 0
    elif bump_type == "minor":
        parts[1] += 1; parts[2] = 0
    else:
        parts[2] += 1
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


def get_next_feature():
    """Find the next unimplemented feature from the roadmap."""
    # Check which features already have merged PRs
    existing_prs = gh_api("repos/R3dy/DeepSight/pulls?state=closed&per_page=20&sort=updated&direction=desc")
    if not isinstance(existing_prs, list):
        existing_prs = []

    existing_branches = run("git branch -r")[1]
    completed_features = set()

    for pr in existing_prs:
        title = pr.get("title", "").lower()
        for feat in ROADMAP:
            if feat["title"].lower()[:20] in title:
                completed_features.add(feat["feature"])

    for feat in ROADMAP:
        if feat["feature"] not in completed_features:
            return feat
    return None


def check_and_advance():
    """Main dev loop iteration."""
    print(f"\n{'='*60}")
    print(f"[dev-loop] Running at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[dev-loop] Repo: {REPO_DIR}")

    # Ensure we're on main and up to date
    run("git checkout main")
    run("git pull origin main")

    open_prs = get_open_prs()
    print(f"[dev-loop] Open PRs: {len(open_prs)}")

    # Step 1: Check for approved PRs to merge
    for pr in open_prs:
        pr_num = pr["number"]
        reviews = get_pr_reviews(pr_num)
        approved = any(r.get("state") == "APPROVED" for r in reviews)
        changes_requested = any(r.get("state") == "CHANGES_REQUESTED" for r in reviews)

        if approved and not changes_requested:
            print(f"[dev-loop] PR #{pr_num} is approved — merging")
            merge_pr(pr_num)
            return  # One merge per loop iteration
        elif changes_requested:
            print(f"[dev-loop] PR #{pr_num} has requested changes — skipping")
        else:
            print(f"[dev-loop] PR #{pr_num} awaiting review — will review next cycle")

    # Step 2: If PRs exist but unapproved, we should request a review
    # (This is handled externally via the review agent spawn)

    # Step 3: No open PRs → pick next feature and implement
    if not open_prs:
        next_feat = get_next_feature()
        if next_feat:
            print(f"[dev-loop] 🚀 Next feature: {next_feat['title']}")
            print(f"[dev-loop] Phase {next_feat['phase']} · ~{next_feat['hours']}h")
            print(f"[dev-loop] Spawning implementation agent for: {next_feat['feature']}")

            # Write a trigger file for the implementation agent
            trigger = {
                "feature": next_feat["feature"],
                "title": next_feat["title"],
                "description": next_feat["desc"],
                "phase": next_feat["phase"],
                "timestamp": time.time(),
            }

            trigger_path = Path(REPO_DIR) / ".dev-loop" / "trigger.json"
            trigger_path.parent.mkdir(exist_ok=True)
            trigger_path.write_text(json.dumps(trigger, indent=2))

            print(f"[dev-loop] Trigger written to {trigger_path}")
            print(f"[dev-loop] ⏳ Agent will pick this up and create issue → branch → PR")
            return next_feat
        else:
            print("[dev-loop] ✅ All planned features implemented!")
            print("[dev-loop] Consider adding new items to the roadmap.")


def status():
    """Print current pipeline status."""
    print("\n═══ DeepSight Dev Pipeline Status ═══")
    print(f"Version: {get_current_version()}")
    open_prs = get_open_prs()
    print(f"Open PRs: {len(open_prs)}")
    for pr in open_prs:
        reviews = get_pr_reviews(pr["number"])
        approved = any(r.get("state") == "APPROVED" for r in reviews)
        status_icon = "✅" if approved else "⏳"
        print(f"  {status_icon} PR #{pr['number']}: {pr['title'][:60]}")
    next_feat = get_next_feature()
    if next_feat:
        print(f"Next: {next_feat['title']} (Phase {next_feat['phase']})")
    else:
        print("Next: None — all planned features complete")


if __name__ == "__main__":
    if "--status" in sys.argv:
        status()
    elif "--advance" in sys.argv:
        check_and_advance()
    elif "--now" in sys.argv:
        # Force immediate cycle
        check_and_advance()
    else:
        # Default: print status, run one cycle
        status()
        print("\nUse --advance to run one dev loop cycle")
        print("Use --status for pipeline status only")
