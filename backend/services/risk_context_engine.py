import pandas as pd
import numpy as np
import os

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_RAW_DIR = os.path.join(BASE_DIR, 'data', 'raw')
DATA_PROCESSED_DIR = os.path.join(BASE_DIR, 'data', 'processed')

PREDICTION_RESULTS_FILE = os.path.join(DATA_PROCESSED_DIR, 'prediction_results.csv')
SECURITY_EVENTS_FILE = os.path.join(DATA_RAW_DIR, 'security_events.csv')
ASSETS_FILE = os.path.join(DATA_PROCESSED_DIR, 'm3_asset_criticality.csv')
VULNERABILITIES_FILE = os.path.join(DATA_PROCESSED_DIR, 'm3_vulnerability_exposure_final.csv')
MITRE_MAPPING_FILE = os.path.join(DATA_RAW_DIR, 'mitre_attack_mapping.csv')
OUTPUT_FILE = os.path.join(DATA_PROCESSED_DIR, 'risk_enriched_data.csv')


def task1_collect_module2_inputs():
    """
    Load prediction results (Module 2 output) and merge with raw security events
    to recover basic event information (like asset_name, event_type).
    """
    print("--- MODULE 3 TASK 1 ---")
    if not os.path.exists(PREDICTION_RESULTS_FILE):
        raise FileNotFoundError(f"Missing {PREDICTION_RESULTS_FILE}")
        
    predictions_df = pd.read_csv(PREDICTION_RESULTS_FILE)
    print(f"Loaded Module 2 outputs from: {PREDICTION_RESULTS_FILE}")
    print(f"Module 2 fields found: {list(predictions_df.columns)}")
    print(f"Number of Module 2 records: {len(predictions_df)}")

    # Load base events for mapping
    events_df = pd.read_csv(SECURITY_EVENTS_FILE)
    events_subset = events_df[['event_id', 'asset_name', 'event_type']]
    
    # Merge on event_id to add asset_name and event_type
    merged_df = predictions_df.merge(events_subset, on='event_id', how='left')
    
    print("Merged Module 2 output with base event context (asset_name, event_type).")
    print(f"Columns after merge: {list(merged_df.columns)}")
    print(f"Test Result:\n{merged_df.head(2).to_dict(orient='records')}\n")
    
    return merged_df


def get_asset_criticality(criticality_str):
    """
    Deterministic mapping of Criticality string to Criticality Score.
    Critical = 1.00, High = 0.75, Medium = 0.50, Low = 0.25
    """
    mapping = {
        'Critical': 1.00,
        'High': 0.75,
        'Medium': 0.50,
        'Low': 0.25
    }
    return mapping.get(str(criticality_str).strip(), 0.50)


def task2_asset_criticality(input_df):
    """
    Load assets dataset, map criticality score, and join with the input dataset.
    """
    print("--- MODULE 3 TASK 2 ---")
    assets_df = pd.read_csv(ASSETS_FILE)
    print(f"Asset dataset used: {ASSETS_FILE}")
    
    # Calculate criticality score
    assets_df['criticality_score'] = assets_df['criticality'].apply(get_asset_criticality)
    print("Criticality logic applied: Critical=1.00, High=0.75, Medium=0.50, Low=0.25")
    
    assets_subset = assets_df[['asset_name', 'criticality', 'criticality_score']]
    
    # Merge on asset_name
    enriched_df = input_df.merge(assets_subset, on='asset_name', how='left')
    
    # Fill missing assets with safe defaults
    enriched_df['criticality'] = enriched_df['criticality'].fillna('Unknown')
    enriched_df['criticality_score'] = enriched_df['criticality_score'].fillna(0.0)
    
    print(f"Output fields added: ['criticality', 'criticality_score']")
    
    # Test result
    test_sample = enriched_df[['asset_name', 'criticality', 'criticality_score']].head(3)
    print(f"Test Result:\n{test_sample.to_dict(orient='records')}\n")
    
    return enriched_df


def compute_vulnerability_exposure(row):
    """
    Computes a simplified vulnerability exposure score.
    Higher CVSS + more vulnerabilities = higher exposure (capped at 1.0).
    """
    if pd.isna(row['max_cvss_score']) or row['max_cvss_score'] == 0:
        return 0.0
    score = (row['max_cvss_score'] / 10.0) + (row['vulnerability_count'] * 0.1)
    return min(score, 1.0)


def task3_vulnerability_exposure(input_df):
    """
    Load vulnerabilities, aggregate by asset, calculate exposure score, and merge.
    """
    print("--- MODULE 3 TASK 3 ---")
    vuln_df = pd.read_csv(VULNERABILITIES_FILE)
    print(f"Vulnerability dataset used: {VULNERABILITIES_FILE}")
    
    # Normalize column names to lowercase to avoid case issues
    vuln_df.columns = [c.lower() for c in vuln_df.columns]
    
    print(f"CVE fields used: {['cve_id', 'severity', 'cvss_score', 'affected_asset']}")
    
    # Aggregate vulnerabilities by affected_asset
    vuln_agg = vuln_df.groupby('affected_asset').agg(
        vulnerability_count=('cve_id', 'count'),
        max_cvss_score=('cvss_score', 'max'),
        cve_ids=('cve_id', lambda x: ', '.join(x.dropna())),
        vulnerability_severity=('severity', lambda x: x.iloc[0] if not x.empty else 'None')
    ).reset_index()
    
    # Compute exposure score
    vuln_agg['vulnerability_exposure_score'] = vuln_agg.apply(compute_vulnerability_exposure, axis=1)
    
    print("Exposure logic: min((max_cvss_score / 10.0) + (vulnerability_count * 0.1), 1.0)")
    
    # Merge on asset_name
    enriched_df = input_df.merge(vuln_agg, left_on='asset_name', right_on='affected_asset', how='left')
    
    # Handle assets with no vulnerabilities
    enriched_df['vulnerability_count'] = enriched_df['vulnerability_count'].fillna(0)
    enriched_df['max_cvss_score'] = enriched_df['max_cvss_score'].fillna(0.0)
    enriched_df['vulnerability_exposure_score'] = enriched_df['vulnerability_exposure_score'].fillna(0.0)
    enriched_df['cve_ids'] = enriched_df['cve_ids'].fillna('None')
    enriched_df['vulnerability_severity'] = enriched_df['vulnerability_severity'].fillna('None')
    
    if 'affected_asset' in enriched_df.columns:
        enriched_df.drop(columns=['affected_asset'], inplace=True)
        
    print(f"Asset matching method: input_df['asset_name'] == vulnerabilities['affected_asset']")
    
    # Test result
    test_sample = enriched_df[['asset_name', 'vulnerability_count', 'max_cvss_score', 'vulnerability_exposure_score']].head(3)
    print(f"Test Result:\n{test_sample.to_dict(orient='records')}\n")
    
    return enriched_df


def task4_mitre_mapping(input_df):
    """
    Load MITRE mapping and add context based on event_type.
    """
    print("--- MODULE 3 TASK 4 ---")
    mitre_df = pd.read_csv(MITRE_MAPPING_FILE)
    print(f"MITRE dataset used: {MITRE_MAPPING_FILE}")
    
    for col in ['event_type', 'technique_name']:
        if col in mitre_df.columns:
            mitre_df[col] = mitre_df[col].astype(str).str.strip()
    
    merge_key = 'event_type'
    if merge_key not in input_df.columns:
        merge_key = 'threat_type'
    
    input_df[merge_key] = input_df[merge_key].astype(str).str.strip()
    
    # Try merging on event_type first
    mitre_by_event = mitre_df.drop_duplicates(subset=['event_type'])
    enriched_df = input_df.merge(mitre_by_event, left_on=merge_key, right_on='event_type', how='left')
    
    # For unmatched, try merging on technique_name
    unmatched_mask = enriched_df['mitre_id'].isna()
    if unmatched_mask.any():
        mitre_by_tech = mitre_df.drop_duplicates(subset=['technique_name'])
        unmatched_df = input_df[unmatched_mask].copy()
        
        # Drop columns added by first merge
        cols_to_drop = [c for c in mitre_by_event.columns if c in unmatched_df.columns and c != merge_key]
        unmatched_df = unmatched_df.drop(columns=cols_to_drop, errors='ignore')
        
        unmatched_merged = unmatched_df.merge(mitre_by_tech, left_on=merge_key, right_on='technique_name', how='left')
        
        # Update the enriched_df with the newly matched rows
        for idx in unmatched_merged.index:
            orig_idx = unmatched_mask[unmatched_mask].index[idx]
            for col in ['mitre_id', 'technique_name', 'tactic', 'event_type_y']:
                # The merge might have created _x, _y or just the column name depending on overlap. 
                # Let's simplify this: just update the specific columns.
                pass
                
    # A cleaner approach for two-stage fallback mapping:
    # 1. Create a mapping dictionary for event_type -> mitre row
    # 2. Create a mapping dictionary for technique_name -> mitre row
    # 3. Apply the mapping
    
    records = mitre_df.to_dict('records')
    event_map = {r['event_type']: r for r in records if pd.notna(r.get('event_type'))}
    tech_map = {r['technique_name']: r for r in records if pd.notna(r.get('technique_name'))}
    
    def get_mitre(val):
        if val in event_map:
            return event_map[val]
        if val in tech_map:
            return tech_map[val]
        return {}
        
    mitre_results = input_df[merge_key].apply(get_mitre)
    mitre_results_df = pd.DataFrame(mitre_results.tolist())
    
    # Combine
    for col in ['mitre_id', 'technique_name', 'tactic']:
        if col in mitre_results_df.columns:
            input_df[col] = mitre_results_df[col]
        else:
            input_df[col] = np.nan
            
    enriched_df = input_df
    
    # Fill missing mitre info safely
    enriched_df['mitre_id'] = enriched_df['mitre_id'].fillna('No Mapping')
    enriched_df['technique_name'] = enriched_df['technique_name'].fillna('No Mapping')
    enriched_df['tactic'] = enriched_df['tactic'].fillna('No Mapping')
        
    print(f"Matching method: Custom dict lookup on '{merge_key}' against mitre 'event_type' and 'technique_name'")
    print(f"MITRE fields added: ['mitre_id', 'technique_name', 'tactic']")
    
    # Test result
    test_sample = enriched_df[[merge_key, 'mitre_id', 'technique_name', 'tactic']].head(3)
    print(f"Test Result:\n{test_sample.to_dict(orient='records')}\n")
    
    return enriched_df


def run_pipeline():
    print("Starting Module 3 Risk Context Pipeline...\n")
    
    # Tasks 1 to 4
    df = task1_collect_module2_inputs()
    df = task2_asset_criticality(df)
    df = task3_vulnerability_exposure(df)
    df = task4_mitre_mapping(df)
    
    # Save Final Dataset
    print("--- MODULE 3 INTEGRATION ---")
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"Final output saved to: {OUTPUT_FILE}")
    print(f"Total rows: {len(df)}")
    print(f"Final columns: {list(df.columns)}\n")
    
    print("--- FINAL REPORT ---")
    print("Task 1: COMPLETE")
    print("Task 2: COMPLETE")
    print("Task 3: COMPLETE")
    print("Task 4: COMPLETE")
    print("Module 3 Integration: COMPLETE")

if __name__ == "__main__":
    run_pipeline()
