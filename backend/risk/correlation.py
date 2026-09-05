import pandas as pd
import os

INPUT_FILE = "backend/data/processed/risk_classified_data.csv"
OUTPUT_FILE = "backend/data/processed/correlated_events.csv"

TIME_WINDOW_MINUTES = 30


def correlate_events():

    print("========================================")
    print("TASK 8 - EVENT CORRELATION")
    print("========================================")

    # ----------------------------------------
    # Step 1: Check input file
    # ----------------------------------------

    if not os.path.exists(INPUT_FILE):
        print("\nERROR: Task 7 output file not found.")
        print("Expected file:")
        print(INPUT_FILE)
        print("\nPlease complete Task 7 first.")
        return

    # ----------------------------------------
    # Step 2: Load Task 7 output
    # ----------------------------------------

    events = pd.read_csv(INPUT_FILE)

    print("Events loaded:", len(events))

    print("\nInput columns:")
    print(events.columns.tolist())

    # ----------------------------------------
    # Step 3: Check required columns
    # ----------------------------------------

    possible_group_columns = [
        "user_id",
        "source_ip",
        "destination_ip",
        "asset_id",
        "event_type"
    ]

    available_group_columns = [
        column
        for column in possible_group_columns
        if column in events.columns
    ]

    if not available_group_columns:
        print("\nERROR: No correlation columns found.")
        return

    print("\nCorrelation fields:")
    print(available_group_columns)

    # ----------------------------------------
    # Step 4: Convert timestamp
    # ----------------------------------------

    if "timestamp" in events.columns:
        events["timestamp"] = pd.to_datetime(
            events["timestamp"],
            errors="coerce"
        )

    # ----------------------------------------
    # Step 5: Create correlation ID
    # ----------------------------------------

    events["correlation_id"] = ""

    # ----------------------------------------
    # Step 6: Create correlation groups
    # ----------------------------------------

    # Replace missing values so grouping works correctly
    for column in available_group_columns:
        events[column] = events[column].fillna("UNKNOWN").astype(str)

    # Sort by timestamp if available
    if "timestamp" in events.columns:
        events = events.sort_values("timestamp")

    correlation_counter = 1

    # ----------------------------------------
    # Step 7: Correlate events
    # ----------------------------------------

    for index, row in events.iterrows():

        # If already assigned, skip
        if events.at[index, "correlation_id"] != "":
            continue

        current_group = []

        # Current event
        current_timestamp = row["timestamp"] if "timestamp" in events.columns else None

        for other_index, other_row in events.iterrows():

            if other_index == index:
                current_group.append(other_index)
                continue

            # Check matching correlation fields
            match = False

            for column in available_group_columns:
                if (
                    str(row[column]).strip() != "UNKNOWN"
                    and str(row[column]).strip()
                    == str(other_row[column]).strip()
                ):
                    match = True
                    break

            if not match:
                continue

            # ----------------------------------------
            # Check time window
            # ----------------------------------------

            if (
                current_timestamp is not None
                and pd.notna(current_timestamp)
                and "timestamp" in events.columns
                and pd.notna(other_row["timestamp"])
            ):
                time_difference = abs(
                    (
                        other_row["timestamp"]
                        - current_timestamp
                    ).total_seconds()
                ) / 60

                if time_difference <= TIME_WINDOW_MINUTES:
                    current_group.append(other_index)

            else:
                current_group.append(other_index)

        # ----------------------------------------
        # Assign correlation ID
        # ----------------------------------------

        if len(current_group) > 1:

            correlation_id = f"CORR-{correlation_counter:04d}"

            for event_index in current_group:
                events.at[
                    event_index,
                    "correlation_id"
                ] = correlation_id

            correlation_counter += 1

        else:
            # Single event
            correlation_id = f"CORR-{correlation_counter:04d}"

            events.at[
                index,
                "correlation_id"
            ] = correlation_id

            correlation_counter += 1

    # ----------------------------------------
    # Step 8: Calculate correlation size
    # ----------------------------------------

    correlation_counts = (
        events["correlation_id"]
        .value_counts()
    )

    events["correlated_event_count"] = (
        events["correlation_id"]
        .map(correlation_counts)
    )

    # ----------------------------------------
    # Step 9: Mark correlated events
    # ----------------------------------------

    events["is_correlated"] = (
        events["correlated_event_count"] > 1
    )

    # ----------------------------------------
    # Step 10: Save output
    # ----------------------------------------

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    events.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ----------------------------------------
    # Step 11: Display summary
    # ----------------------------------------

    print("\n========================================")
    print("CORRELATION SUMMARY")
    print("========================================")

    print(
        "Correlation groups:",
        events["correlation_id"].nunique()
    )

    print(
        "Correlated events:",
        int(events["is_correlated"].sum())
    )

    print(
        "Uncorrelated events:",
        int((~events["is_correlated"]).sum())
    )

    print(
        "Time window:",
        TIME_WINDOW_MINUTES,
        "minutes"
    )

    # ----------------------------------------
    # Step 12: Display sample
    # ----------------------------------------

    print("\n========================================")
    print("CORRELATION SAMPLE")
    print("========================================")

    columns_to_show = [
        "event_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "event_type",
        "risk_score",
        "risk_class",
        "correlation_id",
        "correlated_event_count",
        "is_correlated"
    ]

    available_columns = [
        column
        for column in columns_to_show
        if column in events.columns
    ]

    print(
        events[available_columns]
        .head(10)
        .to_string(index=False)
    )

    # ----------------------------------------
    # Step 13: Completion
    # ----------------------------------------

    print("\n========================================")
    print("TASK 8 COMPLETED SUCCESSFULLY")
    print("========================================")

    print("Total events:", len(events))
    print("Output file:", OUTPUT_FILE)

    print("========================================")


if __name__ == "__main__":
    correlate_events()