import pandas as pd
import os


# ============================================
# TASK 6 - RISK SCORE CALCULATION
# ============================================

INPUT_FILE = "backend/data/processed/m3_events_with_ioc.csv"
OUTPUT_FILE = "backend/data/processed/risk_scored_data.csv"


# ============================================
# SEVERITY NORMALIZATION
# ============================================

def severity_to_score(value):

    if pd.isna(value):
        return 0

    value = str(value).strip().lower()

    severity_map = {
        "critical": 100,
        "high": 80,
        "medium": 60,
        "moderate": 60,
        "low": 30,
        "info": 10,
        "informational": 10
    }

    # If severity is text
    if value in severity_map:
        return severity_map[value]

    # If severity is numeric
    try:
        number = float(value)

        # Already a 0-100 score
        if number <= 100:
            return number

    except ValueError:
        pass

    return 0


# ============================================
# NORMALIZE ML CONFIDENCE
# ============================================

def confidence_to_score(value):

    if pd.isna(value):
        return 0

    try:
        value = float(value)

        # Confidence stored between 0 and 1
        if 0 <= value <= 1:
            return value * 100

        # Confidence already between 0 and 100
        if 0 <= value <= 100:
            return value

    except (ValueError, TypeError):
        pass

    return 0


# ============================================
# NORMALIZE ASSET CRITICALITY
# ============================================

def criticality_to_score(value):

    if pd.isna(value):
        return 0

    try:
        value = float(value)

        # M3 criticality values:
        # Critical = 1.0
        # High     = 0.75
        # Medium   = 0.50
        # Low      = 0.25

        if 0 <= value <= 1:
            return value * 100

        # Already a 0-100 score
        if 0 <= value <= 100:
            return value

    except (ValueError, TypeError):
        pass

    value = str(value).strip().lower()

    criticality_map = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "moderate": 50,
        "low": 25
    }

    return criticality_map.get(value, 0)


# ============================================
# VULNERABILITY EXPOSURE SCORE
# ============================================

def vulnerability_to_score(value):

    if pd.isna(value):
        return 0

    try:
        value = float(value)

        # CVSS score is normally 0-10.
        # Convert it to 0-100.
        if 0 <= value <= 10:
            return value * 10

        # If already 0-100
        if 0 <= value <= 100:
            return value

    except (ValueError, TypeError):
        pass

    return 0


# ============================================
# TASK 6 FUNCTION
# ============================================

def calculate_risk_score():

    print("========================================")
    print("TASK 6 - RISK SCORE CALCULATION")
    print("========================================")

    # ----------------------------------------
    # Load Task 5 output
    # ----------------------------------------

    events = pd.read_csv(INPUT_FILE)

    print("Events loaded:", len(events))

    print("\nInput columns:")
    print(events.columns.tolist())

    # ----------------------------------------
    # Check required columns
    # ----------------------------------------

    required_columns = [
        "severity",
        "confidence_score",
        "criticality_score",
        "cvss_score_vul",
        "threat_intelligence_score"
    ]

    missing_columns = []

    for column in required_columns:

        if column not in events.columns:
            missing_columns.append(column)

    if missing_columns:

        print("\nERROR: Required columns are missing:")

        for column in missing_columns:
            print("-", column)

        return

    # ----------------------------------------
    # Calculate individual scores
    # ----------------------------------------

    events["severity_score"] = (
        events["severity"]
        .apply(severity_to_score)
    )

    events["ml_confidence_score"] = (
        events["confidence_score"]
        .apply(confidence_to_score)
    )

    events["asset_criticality_score"] = (
        events["criticality_score"]
        .apply(criticality_to_score)
    )

    events["vulnerability_exposure_score"] = (
        events["cvss_score_vul"]
        .apply(vulnerability_to_score)
    )

    events["threat_intelligence_score"] = pd.to_numeric(
        events["threat_intelligence_score"],
        errors="coerce"
    ).fillna(0)

    # Keep Threat Intelligence between 0 and 100
    events["threat_intelligence_score"] = (
        events["threat_intelligence_score"]
        .clip(0, 100)
    )

    # ----------------------------------------
    # M3 RISK SCORE FORMULA
    # ----------------------------------------
    #
    # Severity              = 25%
    # ML Confidence         = 25%
    # Asset Criticality     = 20%
    # Vulnerability Exposure= 20%
    # Threat Intelligence   = 10%
    #
    # Total = 100%
    # ----------------------------------------

    events["risk_score"] = (

        events["severity_score"] * 0.25

        + events["ml_confidence_score"] * 0.25

        + events["asset_criticality_score"] * 0.20

        + events["vulnerability_exposure_score"] * 0.20

        + events["threat_intelligence_score"] * 0.10
    )

    # Make sure risk score stays between 0 and 100
    events["risk_score"] = (
        events["risk_score"]
        .clip(0, 100)
        .round(2)
    )

    # ----------------------------------------
    # Create output directory
    # ----------------------------------------

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    # ----------------------------------------
    # Save results
    # ----------------------------------------

    events.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ----------------------------------------
    # Display results
    # ----------------------------------------

    print("\n========================================")
    print("TASK 6 COMPLETED SUCCESSFULLY")
    print("========================================")

    print("Total events:", len(events))

    print(
        "Average risk score:",
        round(events["risk_score"].mean(), 2)
    )

    print(
        "Maximum risk score:",
        round(events["risk_score"].max(), 2)
    )

    print(
        "Minimum risk score:",
        round(events["risk_score"].min(), 2)
    )

    print("\nRisk score sample:")

    columns_to_show = [
        "event_id",
        "severity_score",
        "ml_confidence_score",
        "asset_criticality_score",
        "vulnerability_exposure_score",
        "threat_intelligence_score",
        "risk_score"
    ]

    print(
        events[columns_to_show].head(10).to_string(
            index=False
        )
    )

    print("\nOutput file:")
    print(OUTPUT_FILE)

    print("========================================")


# ============================================
# RUN
# ============================================

if __name__ == "__main__":
    calculate_risk_score()