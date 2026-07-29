import os
import pandas as pd
import difflib

# ==============================
# 📂 PATH SETUP
# ==============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")

EVENTS_FILE = os.path.join(RAW_DIR, "security_events.csv")
MITRE_FILE = os.path.join(RAW_DIR, "mitre_attack_mapping.csv")
OUTPUT_FILE = os.path.join(PROCESSED_DIR, "security_events_mitre.csv")

# ==============================
# ✅ CHECK FILES
# ==============================

print("🔍 Checking files...")

for file in [EVENTS_FILE, MITRE_FILE]:
    if not os.path.exists(file):
        print(f"❌ Missing file: {file}")
        exit()

print("✅ All files found\n")

# ==============================
# 📥 LOAD DATA
# ==============================

events_df = pd.read_csv(EVENTS_FILE)
mitre_df = pd.read_csv(MITRE_FILE)

# normalize columns
events_df.columns = events_df.columns.str.lower()
mitre_df.columns = mitre_df.columns.str.lower()

print(f"📊 Total Events: {len(events_df)}")
print(f"📊 MITRE Rules: {len(mitre_df)}\n")

# ==============================
# 🧠 CLEAN TEXT
# ==============================

def clean_text(text):
    return str(text).strip().lower()

events_df["event_type"] = events_df["event_type"].apply(clean_text)
mitre_df["event_type"] = mitre_df["event_type"].apply(clean_text)

# ==============================
# 🔥 SYNONYMS (BOOST ACCURACY)
# ==============================

SYNONYMS = {
    "login": ["authentication", "signin"],
    "failed": ["failure", "unsuccessful", "denied"],
    "command": ["cmd", "powershell", "bash"],
    "scan": ["probe", "recon"],
    "malware": ["virus", "trojan"],
    "attack": ["intrusion", "exploit"]
}

# ==============================
# ⚙️ PREPARE TEXT (CRITICAL)
# ==============================

events_df["event_text"] = (
    events_df["event_type"].astype(str) + " " +
    events_df.get("event_status", "").astype(str) + " " +
    events_df.get("severity", "").astype(str)
).str.lower()

# ==============================
# 🚀 MAPPING FUNCTION (ADVANCED)
# ==============================

def map_mitre(event_text):
    event_text = str(event_text).lower()

    # 🔥 Expand synonyms
    for word, syns in SYNONYMS.items():
        for syn in syns:
            if syn in event_text:
                event_text += " " + word

    event_words = set(event_text.split())

    best_match = None
    best_score = 0

    for _, row in mitre_df.iterrows():
        mitre_text = str(row["event_type"]).lower()
        mitre_words = set(mitre_text.split())

        # 1️⃣ Word overlap
        score = len(event_words.intersection(mitre_words))

        # 2️⃣ Substring boost
        if mitre_text in event_text or event_text in mitre_text:
            score += 3

        # 3️⃣ Partial word bonus
        for w in mitre_words:
            if w in event_text:
                score += 1

        # 4️⃣ Fuzzy matching (AI-like)
        similarity = difflib.SequenceMatcher(None, event_text, mitre_text).ratio()
        score += similarity * 2

        if score > best_score:
            best_score = score
            best_match = row

    # 🔥 Threshold tuning
    if best_score >= 2:
        return pd.Series([
            best_match["mitre_id"],
            best_match["technique_name"],
            best_match["tactic"]
        ])

    return pd.Series([None, None, None])

# ==============================
# ⚙️ APPLY MAPPING
# ==============================

print("⚙️ Applying MITRE mapping...\n")

events_df[["technique_id", "technique_name", "tactic"]] = \
    events_df["event_text"].apply(map_mitre)

# ==============================
# 📊 RESULTS
# ==============================

mapped_count = events_df["technique_id"].notna().sum()
total_count = len(events_df)
coverage = (mapped_count / total_count) * 100

print("📊 RESULTS")
print(f"Total Events: {total_count}")
print(f"Mapped Events: {mapped_count}")
print(f"Coverage: {coverage:.2f}%\n")

# ==============================
# 💾 SAVE OUTPUT
# ==============================

os.makedirs(PROCESSED_DIR, exist_ok=True)
events_df.to_csv(OUTPUT_FILE, index=False)

print(f"💾 Saved to: {OUTPUT_FILE}")
print("✅ MITRE mapping completed successfully!\n")

# ==============================
# 🔍 DEBUG (UNMAPPED)
# ==============================

print("🔍 Sample Unmapped Events:")
unmapped = events_df[events_df["technique_id"].isna()]

for i, row in unmapped.head(5).iterrows():
    print("-", row["event_text"])