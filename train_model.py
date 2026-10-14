import argparse
import os
import sys
import tempfile
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


PROJECT_DIR = Path(__file__).resolve().parent
CSV_PATH = PROJECT_DIR / "dataset" / "emails.csv"
MODEL_PATH = PROJECT_DIR / "models" / "email_spam_model.joblib"
REQUIRED_COLUMNS = {"subject", "body", "label", "source_file"}
EXPECTED_LABELS = {0, 1}


def combine_text(data: pd.DataFrame) -> pd.Series:
    subject = data["subject"].fillna("").astype(str)
    body = data["body"].fillna("").astype(str)
    return (subject + " " + body).str.strip()


def save_model(pipeline: Pipeline, overwrite: bool) -> None:
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".email-spam-model-",
            suffix=".joblib.tmp",
            dir=MODEL_PATH.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            joblib.dump(pipeline, temporary)

        if overwrite:
            os.replace(temporary_path, MODEL_PATH)
        else:
            os.rename(temporary_path, MODEL_PATH)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train a TF-IDF and logistic-regression SpamAssassin classifier."
    )
    parser.add_argument(
        "--overwrite-model",
        action="store_true",
        help="replace models/email_spam_model.joblib if it already exists",
    )
    args = parser.parse_args()

    if not CSV_PATH.is_file():
        print(f"Error: training CSV not found: {CSV_PATH}", file=sys.stderr)
        return 1
    if MODEL_PATH.exists() and not args.overwrite_model:
        print(
            f"Error: refusing to overwrite existing model: {MODEL_PATH}\n"
            "Use --overwrite-model only when you intend to replace it.",
            file=sys.stderr,
        )
        return 1

    try:
        data = pd.read_csv(CSV_PATH, encoding="utf-8")
    except (OSError, UnicodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as error:
        print(f"Error reading CSV: {type(error).__name__}: {error}", file=sys.stderr)
        return 1

    missing_columns = REQUIRED_COLUMNS - set(data.columns)
    if missing_columns:
        print(
            f"Error: CSV is missing required columns: {sorted(missing_columns)}",
            file=sys.stderr,
        )
        return 1
    if data.empty:
        print("Error: CSV contains no rows.", file=sys.stderr)
        return 1
    if data["label"].isna().any():
        print("Error: label column contains missing values.", file=sys.stderr)
        return 1

    try:
        labels = data["label"].astype(int)
    except (TypeError, ValueError, OverflowError) as error:
        print(f"Error: labels must be integers 0 or 1: {error}", file=sys.stderr)
        return 1

    label_values = set(labels.unique())
    if label_values != EXPECTED_LABELS:
        print(
            f"Error: expected labels {sorted(EXPECTED_LABELS)}, found {sorted(label_values)}.",
            file=sys.stderr,
        )
        return 1

    missing_values = data[list(REQUIRED_COLUMNS)].isna().sum()
    class_distribution = labels.value_counts().sort_index()
    print("Dataset inspection")
    print(f"  Rows: {len(data)}")
    print(f"  Columns: {', '.join(data.columns)}")
    print("  Missing values:")
    for column, count in missing_values.items():
        print(f"    {column}: {count}")
    print("  Class distribution:")
    print(f"    ham (0): {int(class_distribution.get(0, 0))}")
    print(f"    spam (1): {int(class_distribution.get(1, 0))}")
    print(f"  Empty subjects: {int(data['subject'].fillna('').astype(str).str.strip().eq('').sum())}")
    print(f"  Empty bodies: {int(data['body'].fillna('').astype(str).str.strip().eq('').sum())}")

    texts = combine_text(data)
    if texts.str.len().eq(0).all():
        print("Error: all combined subject/body text is empty.", file=sys.stderr)
        return 1

    try:
        train_texts, test_texts, train_labels, test_labels = train_test_split(
            texts,
            labels,
            test_size=0.20,
            stratify=labels,
            random_state=42,
        )
    except ValueError as error:
        print(f"Error creating stratified train/test split: {error}", file=sys.stderr)
        return 1

    pipeline = Pipeline(
        steps=[
            ("tfidf", TfidfVectorizer()),
            ("classifier", LogisticRegression(class_weight="balanced", max_iter=1000)),
        ]
    )

    try:
        pipeline.fit(train_texts, train_labels)
        predictions = pipeline.predict(test_texts)
    except (ValueError, RuntimeError) as error:
        print(f"Error while fitting or evaluating the model: {error}", file=sys.stderr)
        return 1

    accuracy = accuracy_score(test_labels, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        test_labels,
        predictions,
        average="binary",
        pos_label=1,
        zero_division=0,
    )
    matrix = confusion_matrix(test_labels, predictions, labels=[0, 1])

    print("\nHeld-out test results (20%, stratified; random_state=42)")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision (spam=1): {precision:.4f}")
    print(f"  Recall (spam=1):    {recall:.4f}")
    print(f"  F1-score (spam=1):  {f1:.4f}")
    print("  Confusion matrix (rows=actual [ham, spam], columns=predicted [ham, spam]):")
    print(matrix)
    print("  Per-class scores:")
    print(
        classification_report(
            test_labels,
            predictions,
            labels=[0, 1],
            target_names=["ham (0)", "spam (1)"],
            zero_division=0,
            digits=4,
        )
    )

    false_positives = int(matrix[0, 1])
    false_negatives = int(matrix[1, 0])
    print("  Error meaning:")
    print(f"    False positives: {false_positives} legitimate emails predicted as spam.")
    print(
        f"    False negatives: {false_negatives} spam emails predicted as legitimate; "
        "these are spam that would pass this classifier."
    )

    try:
        save_model(pipeline, overwrite=args.overwrite_model)
        loaded_pipeline = joblib.load(MODEL_PATH)
        sample_emails = [
            "Subject: Meeting notes\nHi team, attached are the notes from our project meeting.",
            "Subject: Claim your free prize now\nClick here to claim your limited-time cash reward.",
        ]
        sample_predictions = loaded_pipeline.predict(sample_emails)
        if len(sample_predictions) != len(sample_emails) or not set(
            sample_predictions
        ).issubset(EXPECTED_LABELS):
            raise ValueError("Saved pipeline returned invalid sample predictions.")
    except (OSError, ValueError, EOFError, ImportError) as error:
        print(f"Error saving or testing the model: {type(error).__name__}: {error}", file=sys.stderr)
        return 1

    print(f"  Saved fitted pipeline: {MODEL_PATH}")
    print(
        "  Reload test: passed "
        f"({len(sample_predictions)} sample predictions: {sample_predictions.tolist()})"
    )
    print(
        "\nThis evaluation measures SpamAssassin spam-versus-ham classification only; "
        "it does not establish phishing, business email compromise, or impersonation detection."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
