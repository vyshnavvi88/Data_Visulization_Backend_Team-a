"""
incident_builder.py
-------------------
Task 10 - Incident Creation

Reads correlated_events.csv, groups events by correlation_id,
creates incident records, and uploads to MongoDB Security_db.incidents
"""

import os
import sys
import pandas as pd
from datetime import datetime, timezone

# ── path setup so we can import from backend root ──────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from risk.recommendations import get_recommendations

# ── File paths ──────────────────────────────────────────────────────────────
INPUT_FILE  = os.path.join(os.path.dirname(__file__), "..", "data", "processed", "correlated_events.csv")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "processed", "incidents.csv")

# ── Priority map (numeric → label) ──────────────────────────────────────────
PRIORITY_MAP = {1: "Critical", 2: "High", 3: "Moderate", 4: "Medium", 5: "Low"}


# ============================================================
# INCIDENT BUILDER
# ============================================================

def build_incidents(df: pd.DataFrame) -> list:
    """
    Groups correlated events into incidents.
    - Correlated events  → grouped by correlation_id
    - Uncorrelated events → each becomes its own incident
    Returns list of incident dicts.
    """
    incidents = []
    incident_counter = 1

    # ── Group correlated events ─────────────────────────────────────────────
    correlated = df[df["is_correlated"] == True]
    uncorrelated = df[df["is_correlated"] == False]

    for corr_id, group in correlated.groupby("correlation_id"):
        group = group.sort_values("timestamp")

        # Pick representative values from the group (highest risk event)
        top = group.loc[group["risk_score"].idxmax()]

        priority_num = int(top["priority"]) if not pd.isna(top["priority"]) else 3
        priority_label = PRIORITY_MAP.get(priority_num, "Medium")

        ioc_match = bool(group["ioc_match"].any())
        cvss = float(top["cvss_score"]) if not pd.isna(top.get("cvss_score", None)) else 0.0

        recs = get_recommendations(
            event_type=str(top.get("event_type", "")),
            risk_class=str(top.get("risk_class", "Medium")),
            ioc_match=ioc_match,
            cvss_score=cvss,
            mitre_technique=str(top.get("mitre_id", ""))
        )

        incident = {
            "incident_id":     f"INC-{incident_counter:04d}",
            "correlation_id":  corr_id,
            "event_ids":       group["event_id"].tolist(),
            "event_count":     len(group),
            "threat_type":     str(top.get("event_type", "Unknown")),
            "risk_score":      round(float(top["risk_score"]), 2),
            "risk_class":      str(top.get("risk_class", "Medium")),
            "priority":        priority_label,
            "priority_rank":   priority_num,
            "asset_id":        str(top.get("asset_id", "")),
            "asset_name":      str(top.get("asset_name", "")),
            "criticality":     str(top.get("criticality", "")),
            "affected_user":   str(top.get("username", "")),
            "source_ip":       str(top.get("source_ip", "")),
            "destination_ip":  str(top.get("destination_ip", "")),
            "mitre_technique": str(top.get("mitre_id", "")),
            "technique_name":  str(top.get("technique_name", "")),
            "tactic":          str(top.get("tactic", "")),
            "ioc_match":       ioc_match,
            "ioc_type":        str(top.get("ioc_type", "")),
            "threat_actor":    str(top.get("threat_actor", "")),
            "cvss_score":      cvss,
            "cve_id":          str(top.get("cve_id", "")),
            "status":          "Open",
            "recommendation":  recs,
            "created_at":      datetime.now(timezone.utc).isoformat()
        }

        incidents.append(incident)
        incident_counter += 1

    # ── Uncorrelated events → individual incidents ──────────────────────────
    for _, row in uncorrelated.iterrows():
        priority_num = int(row["priority"]) if not pd.isna(row["priority"]) else 3
        priority_label = PRIORITY_MAP.get(priority_num, "Medium")

        ioc_match = bool(row.get("ioc_match", False))
        cvss = float(row["cvss_score"]) if not pd.isna(row.get("cvss_score", None)) else 0.0

        recs = get_recommendations(
            event_type=str(row.get("event_type", "")),
            risk_class=str(row.get("risk_class", "Medium")),
            ioc_match=ioc_match,
            cvss_score=cvss,
            mitre_technique=str(row.get("mitre_id", ""))
        )

        incident = {
            "incident_id":     f"INC-{incident_counter:04d}",
            "correlation_id":  None,
            "event_ids":       [str(row["event_id"])],
            "event_count":     1,
            "threat_type":     str(row.get("event_type", "Unknown")),
            "risk_score":      round(float(row["risk_score"]), 2),
            "risk_class":      str(row.get("risk_class", "Medium")),
            "priority":        priority_label,
            "priority_rank":   priority_num,
            "asset_id":        str(row.get("asset_id", "")),
            "asset_name":      str(row.get("asset_name", "")),
            "criticality":     str(row.get("criticality", "")),
            "affected_user":   str(row.get("username", "")),
            "source_ip":       str(row.get("source_ip", "")),
            "destination_ip":  str(row.get("destination_ip", "")),
            "mitre_technique": str(row.get("mitre_id", "")),
            "technique_name":  str(row.get("technique_name", "")),
            "tactic":          str(row.get("tactic", "")),
            "ioc_match":       ioc_match,
            "ioc_type":        str(row.get("ioc_type", "")),
            "threat_actor":    str(row.get("threat_actor", "")),
            "cvss_score":      cvss,
            "cve_id":          str(row.get("cve_id", "")),
            "status":          "Open",
            "recommendation":  recs,
            "created_at":      datetime.now(timezone.utc).isoformat()
        }

        incidents.append(incident)
        incident_counter += 1

    return incidents


def upload_to_mongodb(incidents: list):
    """Upload incidents to MongoDB Security_db.incidents collection."""
    try:
        from db import get_incidents_collection
        col = get_incidents_collection()
        if col is None:
            print("[WARN] MongoDB not available. Skipping upload.")
            return

        # Clear existing incidents
        col.delete_many({})
        col.insert_many(incidents)
        print(f"[OK] Uploaded {len(incidents)} incidents to MongoDB -> Security_db.incidents")
    except Exception as e:
        print(f"[ERROR] MongoDB upload failed: {e}")


def save_to_csv(incidents: list):
    """Save incidents to CSV (without recommendation list for readability)."""
    rows = []
    for inc in incidents:
        row = {k: v for k, v in inc.items() if k != "recommendation"}
        row["event_ids"] = "|".join(inc["event_ids"])
        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"[OK] Saved {len(incidents)} incidents to {OUTPUT_FILE}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 55)
    print("TASK 10 — INCIDENT CREATION")
    print("=" * 55)

    if not os.path.exists(INPUT_FILE):
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        sys.exit(1)

    df = pd.read_csv(INPUT_FILE)
    print(f"Loaded {len(df)} events from correlated_events.csv")

    incidents = build_incidents(df)
    print(f"\nCreated {len(incidents)} incidents")

    # Summary
    from collections import Counter
    priority_counts = Counter(i["priority"] for i in incidents)
    print("\nPriority breakdown:")
    for p in ["Critical", "High", "Moderate", "Medium", "Low"]:
        print(f"  {p:10s}: {priority_counts.get(p, 0)}")

    save_to_csv(incidents)
    upload_to_mongodb(incidents)
    print("\n[OK] Task 10 complete.")
