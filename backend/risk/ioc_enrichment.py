import pandas as pd
import os


# ============================================
# TASK 5 - THREAT INTELLIGENCE / IOC ENRICHMENT
# ============================================

EVENT_FILE = "backend/data/processed/m3_events_with_mitre.csv"
IOC_FILE = "backend/data/raw/threat_intelligence.csv"
OUTPUT_FILE = "backend/data/processed/m3_events_with_ioc.csv"


def enrich_ioc():

    print("========================================")
    print("TASK 5 - THREAT INTELLIGENCE / IOC")
    print("========================================")

    # Load event data
    events = pd.read_csv(EVENT_FILE)

    # Load threat intelligence data
    ioc_data = pd.read_csv(IOC_FILE)

    print("Events loaded:", len(events))
    print("IOC records loaded:", len(ioc_data))

    print("\nEvent columns:")
    print(events.columns.tolist())

    print("\nIOC columns:")
    print(ioc_data.columns.tolist())

    # ----------------------------------------
    # Create IOC enrichment columns
    # ----------------------------------------

    events["ioc_match"] = False
    events["ioc_type"] = "None"
    events["ioc_value"] = ""
    events["threat_name_ioc"] = ""
    events["threat_actor"] = ""
    events["ioc_confidence"] = 0
    events["threat_intelligence_score"] = 0

    # ----------------------------------------
    # Get IOC values
    # ----------------------------------------

    malicious_iocs = set(
        ioc_data["indicator_value"]
        .dropna()
        .astype(str)
        .str.strip()
    )

    print("\nMalicious IOC values:", len(malicious_iocs))

    # ----------------------------------------
    # Match source IP with IOC
    # ----------------------------------------

    if "source_ip" not in events.columns:

        print("\nERROR: source_ip column not found.")
        return

    for index, row in events.iterrows():

        source_ip = str(row["source_ip"]).strip()

        # Check whether source IP is malicious
        if source_ip in malicious_iocs:

            events.loc[index, "ioc_match"] = True
            events.loc[index, "ioc_value"] = source_ip

            # Get matching IOC record
            matching_ioc = ioc_data[
                ioc_data["indicator_value"]
                .astype(str)
                .str.strip()
                == source_ip
            ]

            if not matching_ioc.empty:

                ioc_row = matching_ioc.iloc[0]

                # IOC type
                events.loc[
                    index,
                    "ioc_type"
                ] = str(ioc_row["indicator_type"])

                # Threat name
                events.loc[
                    index,
                    "threat_name_ioc"
                ] = str(ioc_row["threat_name"])

                # Threat actor
                events.loc[
                    index,
                    "threat_actor"
                ] = str(ioc_row["threat_actor"])

                # IOC confidence
                events.loc[
                    index,
                    "ioc_confidence"
                ] = pd.to_numeric(
                    ioc_row["confidence"],
                    errors="coerce"
                )

                # Malicious IOC increases risk
                events.loc[
                    index,
                    "threat_intelligence_score"
                ] = 100

    # ----------------------------------------
    # Create output directory
    # ----------------------------------------

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    # ----------------------------------------
    # Save enriched data
    # ----------------------------------------

    events.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ----------------------------------------
    # Results
    # ----------------------------------------

    total_matches = int(
        events["ioc_match"].sum()
    )

    print("\n========================================")
    print("TASK 5 COMPLETED SUCCESSFULLY")
    print("========================================")

    print("Total events:", len(events))
    print("IOC matches:", total_matches)
    print("Output file:", OUTPUT_FILE)

    print("========================================")


# ============================================
# RUN
# ============================================

if __name__ == "__main__":
    enrich_ioc()