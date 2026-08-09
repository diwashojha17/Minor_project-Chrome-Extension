import json
from pathlib import Path
import matplotlib.pyplot as plt
from numpy import matrix
import seaborn as sns
import joblib
import pandas as pd

from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    cross_val_score,
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


# ============================================================
# PATHS
# ============================================================

MODEL_DIR = Path(__file__).resolve().parent

DATASET_PATH = MODEL_DIR / "dataset.csv"
MODEL_PATH = MODEL_DIR / "decision_tree_model.pkl"
COLUMNS_PATH = MODEL_DIR / "model_columns.json"
METRICS_PATH = MODEL_DIR / "training_metrics.json"


# ============================================================
# EXACT 33 FEATURES USED BY EXTENSION
# ============================================================

FEATURE_COLUMNS = [
    "https",
    "csp",
    "hsts",
    "x_frame_options",
    "x_content_type_options",
    "secure_cookie",
    "httponly_cookie",
    "samesite_cookie",
    "num_forms",
    "password_fields",
    "url_length",
    "query_parameters",
    "external_scripts",
    "inline_scripts",
    "http_status",
    "sql_error_indicator",
    "reflected_payload_indicator",
    "server_error_indicator",
    "mixed_content_count",
    "exposed_paths",
    "blind_sqli_indicator",
    "dom_xss_indicator",
    "csrf_missing_token",
    "unsafe_upload_indicator",
    "weak_session_indicator",
    "weak_csp_indicator",
    "open_redirect_indicator",
    "command_input_surface",
    "file_path_input_surface",
    "stored_input_surface",
    "file_upload_surface",
    "login_surface",
    "api_surface",
]


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading dataset...")

if not DATASET_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {DATASET_PATH}"
    )

df = pd.read_csv(DATASET_PATH)

print(f"Dataset rows: {len(df)}")
print(f"Dataset columns: {len(df.columns)}")


# ============================================================
# VALIDATE DATASET
# ============================================================

required_columns = FEATURE_COLUMNS + ["label"]

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing_columns:
    raise ValueError(
        f"Missing columns: {missing_columns}"
    )


# Only use the required columns

df = df[required_columns].copy()


# Remove completely empty rows

df = df.dropna(how="all")


# Make features numeric

for column in FEATURE_COLUMNS:
    df[column] = pd.to_numeric(
        df[column],
        errors="coerce"
    )


# Replace missing numeric values with 0

df[FEATURE_COLUMNS] = (
    df[FEATURE_COLUMNS]
    .fillna(0)
)


# Clean labels

df["label"] = (
    df["label"]
    .astype(str)
    .str.strip()
    .str.upper()
)


# Remove invalid labels

VALID_LABELS = {
    "SAFE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

invalid_labels = (
    set(df["label"].unique())
    - VALID_LABELS
)

if invalid_labels:
    raise ValueError(
        f"Invalid labels found: {invalid_labels}"
    )


# ============================================================
# SHOW CLASS DISTRIBUTION
# ============================================================

print("\nClass distribution:")

print(
    df["label"]
    .value_counts()
    .sort_index()
)


# ============================================================
# X AND Y
# ============================================================

X = df[FEATURE_COLUMNS]
y = df["label"]


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = (
    train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )
)


print("\nTraining rows:", len(X_train))
print("Testing rows:", len(X_test))


# ============================================================
# DECISION TREE
# ============================================================

model = DecisionTreeClassifier(
    criterion="gini",
    max_depth=6,
    min_samples_split=4,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
)


# ============================================================
# TRAIN
# ============================================================

print("\nTraining Decision Tree...")

model.fit(
    X_train,
    y_train
)


# ============================================================
# TEST
# ============================================================

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)


print("\n==============================")
print("MODEL RESULTS")
print("==============================")

print(
    f"\nAccuracy: {accuracy * 100:.2f}%"
)

print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)

# Confusion matrix heatmap
labels = sorted(df['label'].unique())
data = confusion_matrix(y_test, predictions, labels=labels)

plt.figure(figsize=(8, 6))
sns.heatmap(data, annot=True, fmt='d', cmap='Blues', cbar=False,
            xticklabels=labels, yticklabels=labels)
plt.title('Confusion Matrix')
plt.xlabel('Predicted Label')
plt.ylabel('True Label')
plt.show()
print("Confusion Matrix:")

# ============================================================
# 3-FOLD CROSS VALIDATION
# ============================================================

cv = StratifiedKFold(
    n_splits=3,
    shuffle=True,
    random_state=42
)

cv_scores = cross_val_score(
    model,
    X,
    y,
    cv=cv,
    scoring="accuracy"
)


print("\nCross-validation scores:")

for index, score in enumerate(
    cv_scores,
    start=1
):
    print(
        f"Fold {index}: {score * 100:.2f}%"
    )

print(
    f"Average CV accuracy: "
    f"{cv_scores.mean() * 100:.2f}%"
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

importance = pd.DataFrame({
    "feature": FEATURE_COLUMNS,
    "importance": model.feature_importances_,
})

importance = importance.sort_values(
    "importance",
    ascending=False
)


print("\nMost important features:")

print(
    importance.head(15).to_string(
        index=False
    )
)


# ============================================================
# TRAIN FINAL MODEL USING ALL DATA
# ============================================================

print("\nTraining final model on all data...")

final_model = DecisionTreeClassifier(
    criterion="gini",
    max_depth=6,
    min_samples_split=4,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
)

final_model.fit(
    X,
    y
)


# ============================================================
# SAVE MODEL
# ============================================================

joblib.dump(
    final_model,
    MODEL_PATH
)


# ============================================================
# SAVE FEATURE ORDER
# ============================================================

with open(
    COLUMNS_PATH,
    "w",
    encoding="utf-8"
) as file:
    json.dump(
        FEATURE_COLUMNS,
        file,
        indent=2
    )


# ============================================================
# SAVE TRAINING METRICS
# ============================================================

metrics = {
    "dataset_rows": len(df),
    "feature_count": len(FEATURE_COLUMNS),
    "accuracy": float(accuracy),
    "cross_validation_accuracy": float(
        cv_scores.mean()
    ),
    "classes": sorted(
        y.unique().tolist()
    ),
}

with open(
    METRICS_PATH,
    "w",
    encoding="utf-8"
) as file:
    json.dump(
        metrics,
        file,
        indent=2
    )


print("\n==============================")
print("TRAINING COMPLETE")
print("==============================")

print(f"\nModel saved:")
print(MODEL_PATH)

print("\nFeature columns saved:")
print(COLUMNS_PATH)

print("\nMetrics saved:")
print(METRICS_PATH)

print("\nDecision Tree model is ready.")