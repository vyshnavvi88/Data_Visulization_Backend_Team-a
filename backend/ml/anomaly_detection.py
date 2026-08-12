import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest


# ---------------------------------------
# 1. Load ML-ready features
# ---------------------------------------

df = pd.read_csv(
    "backend/data/processed/ml_features.csv"
)

print("Dataset shape:", df.shape)


# ---------------------------------------
# 2. Load original dataset
#    Used to get the real event_id
# ---------------------------------------

original_df = pd.read_csv(
    "backend/data/processed/final_security_dataset.csv"
)

print("Original dataset shape:", original_df.shape)


# ---------------------------------------
# 3. Create Isolation Forest model
# ---------------------------------------

model = IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42
)


# ---------------------------------------
# 4. Train the model
# ---------------------------------------

model.fit(df)

print("Isolation Forest model trained successfully.")


# ---------------------------------------
# 5. Save trained model
# ---------------------------------------

joblib.dump(
    model,
    "backend/models/isolation_forest.pkl"
)

print("Model saved successfully.")


# ---------------------------------------
# 6. Generate predictions
# ---------------------------------------

predictions = model.predict(df)


# ---------------------------------------
# 7. Generate anomaly scores
# ---------------------------------------

anomaly_scores = model.decision_function(df)


# ---------------------------------------
# 8. Convert predictions to readable labels
# ---------------------------------------

prediction_labels = [
    "Suspicious" if prediction == -1 else "Normal"
    for prediction in predictions
]
# ---------------------------------------
# Threat Classification
# ---------------------------------------

def classify_threat(row, prediction):
    # Normal ML prediction
    if prediction == 1:
        return "Low"

    # Critical indicators
    if (
        row["malware_detected"] == "Yes"
        and row["cvss_score"] >= 9
    ):
        return "Critical"

    # High threat indicators
    if (
        row["failed_login_attempts"] > 10
        or row["cvss_score"] >= 7
        or row["malware_detected"] == "Yes"
        or row["severity"] == "High"
        or row["severity"] == "Critical"
    ):
        return "High"

    # Medium threat
    return "Medium"


threat_levels = [
    classify_threat(row, prediction)
    for (_, row), prediction in zip(
        original_df.iterrows(),
        predictions
    )
]
# ---------------------------------------
# Confidence Score
# ---------------------------------------

def calculate_confidence(row, prediction):
    score = 0

    # Anomaly detected
    if prediction == -1:
        score += 30

    # Failed login attempts
    if row["failed_login_attempts"] > 10:
        score += 20
    elif row["failed_login_attempts"] > 5:
        score += 10

    # CVSS score
    if row["cvss_score"] >= 9:
        score += 25
    elif row["cvss_score"] >= 7:
        score += 15
    elif row["cvss_score"] >= 4:
        score += 5

    # Malware detected
    if row["malware_detected"] == "Yes":
        score += 25

    return min(score, 100)


confidence_scores = [
    calculate_confidence(row, prediction)
    for (_, row), prediction in zip(
        original_df.iterrows(),
        predictions
    )
]


# ---------------------------------------
# 9. Create prediction results
# ---------------------------------------

results = pd.DataFrame({
    "event_id": original_df["event_id"],
    "prediction": prediction_labels,
    "anomaly_score": anomaly_scores,
    "threat_level": threat_levels,
    "confidence_score": confidence_scores
})


# ---------------------------------------
# 10. Save prediction results
# ---------------------------------------

results.to_csv(
    "backend/data/processed/prediction_results.csv",
    index=False
)

print("\nPrediction results saved successfully.")


# ---------------------------------------
# 11. Display first 10 predictions
# ---------------------------------------

print("\nPredictions:")
print(predictions[:10])


print("\nAnomaly scores:")
print(anomaly_scores[:10])


# ---------------------------------------
# 12. Display prediction summary
# ---------------------------------------


