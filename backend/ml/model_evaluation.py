import pandas as pd

# Load prediction results
df = pd.read_csv(
    "backend/data/processed/prediction_results.csv"
)

print("Total events:", len(df))

# Prediction counts
prediction_counts = df["prediction"].value_counts()

print("\nPrediction counts:")
print(prediction_counts)

# Calculate percentages
normal_count = prediction_counts.get("Normal", 0)
suspicious_count = prediction_counts.get("Suspicious", 0)

normal_percentage = (normal_count / len(df)) * 100
suspicious_percentage = (suspicious_count / len(df)) * 100

print("\nNormal percentage:", round(normal_percentage, 2), "%")
print("Suspicious percentage:", round(suspicious_percentage, 2), "%")

# Anomaly score statistics
print("\nAnomaly score statistics:")
print(df["anomaly_score"].describe())

print("\nModel evaluation completed.")