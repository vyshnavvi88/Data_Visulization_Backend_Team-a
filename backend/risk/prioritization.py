import pandas as pd
import os

INPUT_FILE = "backend/data/processed/risk_scored_data.csv"
OUTPUT_FILE = "backend/data/processed/risk_classified_data.csv"


def classify_risk(score):
    """
    Risk Classification:
    0–20   -> Low
    21–40  -> Medium
    41–60  -> Moderate
    61–80  -> High
    81–100 -> Critical
    """

    if pd.isna(score):
        return "Low"

    score = float(score)

    if score <= 20:
        return "Low"
    elif score <= 40:
        return "Medium"
    elif score <= 60:
        return "Moderate"
    elif score <= 80:
        return "High"
    else:
        return "Critical"


def classify_risks():

    print("========================================")
    print("TASK 7 - RISK CLASSIFICATION")
    print("========================================")

    # Load Task 6 output
    events = pd.read_csv(INPUT_FILE)

    print("Events loaded:", len(events))

    print("\nInput columns:")
    print(events.columns.tolist())

    # Check risk_score column
    if "risk_score" not in events.columns:
        print("\nERROR: risk_score column not found.")
        print("Please complete Task 6 first.")
        return

    # Apply risk classification
    events["risk_class"] = events["risk_score"].apply(classify_risk)

    # Create priority value
    priority_map = {
        "Critical": 1,
        "High": 2,
        "Moderate": 3,
        "Medium": 4,
        "Low": 5
    }

    events["priority"] = events["risk_class"].map(priority_map)

    # Sort highest priority first
    events = events.sort_values(
        by=["priority", "risk_score"],
        ascending=[True, False]
    )

    # Create output directory if required
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # Save output
    events.to_csv(OUTPUT_FILE, index=False)

    # Display classification summary
    print("\n========================================")
    print("RISK CLASSIFICATION SUMMARY")
    print("========================================")

    print(
        events["risk_class"]
        .value_counts()
        .reindex(
            ["Critical", "High", "Moderate", "Medium", "Low"],
            fill_value=0
        )
    )

    print("\nRisk classification sample:")

    columns_to_show = [
        "event_id",
        "risk_score",
        "risk_class",
        "priority"
    ]

    print(
        events[columns_to_show]
        .head(10)
        .to_string(index=False)
    )

    print("\n========================================")
    print("TASK 7 COMPLETED SUCCESSFULLY")
    print("========================================")
    print("Total events:", len(events))
    print("Output file:", OUTPUT_FILE)
    print("========================================")


if __name__ == "__main__":
    classify_risks()