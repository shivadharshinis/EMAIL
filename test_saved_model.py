import unittest
from pathlib import Path

import joblib
from sklearn.pipeline import Pipeline


MODEL_PATH = Path(__file__).resolve().parent / "models" / "email_spam_model.joblib"
SAMPLE_EMAILS = [
    "Subject: Meeting notes\nHi team, attached are the notes from our project meeting.",
    "Subject: Claim your free prize now\nClick here to claim your limited-time cash reward.",
]


class SavedEmailSpamModelTests(unittest.TestCase):
    def test_saved_pipeline_loads_and_predicts_sample_emails(self) -> None:
        self.assertTrue(MODEL_PATH.is_file(), f"Model not found: {MODEL_PATH}")

        pipeline = joblib.load(MODEL_PATH)
        self.assertIsInstance(pipeline, Pipeline)
        self.assertEqual([step for step, _ in pipeline.steps], ["tfidf", "classifier"])

        predictions = pipeline.predict(SAMPLE_EMAILS)
        self.assertEqual(len(predictions), len(SAMPLE_EMAILS))
        self.assertTrue(set(predictions).issubset({0, 1}))


if __name__ == "__main__":
    unittest.main()
