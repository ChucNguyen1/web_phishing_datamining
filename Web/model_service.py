from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import numpy as np
import joblib


@dataclass
class PredictionResult:
    predicted_label: int
    phishing_probability: float
    legitimate_probability: float


class PhishingModelService:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root
        self.models_dir = self.project_root / "Models"
        self.model_path = self.models_dir / "phishing_rf_model.pkl"
        self.scaler_path = self.models_dir / "scaler.pkl"

        self.model = None
        self.scaler = None
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        if not self.model_path.exists():
            raise FileNotFoundError(f"Missing model file: {self.model_path}")
        if not self.scaler_path.exists():
            raise FileNotFoundError(f"Missing scaler file: {self.scaler_path}")

        self.model = joblib.load(self.model_path)
        self.scaler = joblib.load(self.scaler_path)

    def _probability_of_label(self, probabilities: np.ndarray, label: int) -> float:
        classes = list(self.model.classes_)
        if label not in classes:
            return 0.0
        index = classes.index(label)
        return float(probabilities[index])

    def predict(self, features: List[float]) -> PredictionResult:
        if len(features) != 30:
            raise ValueError("Expected exactly 30 features for prediction.")

        feature_array = np.array(features, dtype=float).reshape(1, -1)
        scaled = self.scaler.transform(feature_array)

        predicted_label = int(self.model.predict(scaled)[0])
        probabilities = self.model.predict_proba(scaled)[0]

        phishing_prob = self._probability_of_label(probabilities, -1)
        legit_prob = self._probability_of_label(probabilities, 1)

        return PredictionResult(
            predicted_label=predicted_label,
            phishing_probability=phishing_prob,
            legitimate_probability=legit_prob,
        )


def parse_features(raw_input: str) -> Tuple[List[float], str]:
    values = [chunk.strip() for chunk in raw_input.replace("\n", ",").split(",") if chunk.strip()]
    if len(values) != 30:
        raise ValueError(f"Expected 30 values, received {len(values)}.")

    try:
        features = [float(v) for v in values]
    except ValueError as exc:
        raise ValueError("All 30 values must be numeric.") from exc

    normalized_input = ", ".join(str(int(v) if v.is_integer() else v) for v in features)
    return features, normalized_input
