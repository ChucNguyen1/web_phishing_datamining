from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
from flask import Flask, jsonify, render_template, request

from extractor import extract_features


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = PROJECT_ROOT / "Models"
MODEL_PATH = MODELS_DIR / "phishing_rf_model.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"

app = Flask(__name__)

model = None
scaler = None
startup_error = None
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except Exception as exc:  # pragma: no cover
    startup_error = str(exc)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", error=startup_error)


def _validate_request_payload(payload: Any) -> str:
    if payload is None:
        raise ValueError("Request body must be valid JSON.")
    if not isinstance(payload, dict):
        raise ValueError("JSON payload must be an object.")

    url = (payload.get("url") or "").strip()
    if not url:
        raise ValueError("Field 'url' is required.")
    return url


@app.route("/predict", methods=["POST"])
def predict():
    try:
        if startup_error:
            return jsonify({"error": f"Model startup failed: {startup_error}"}), 500

        url = _validate_request_payload(request.get_json(silent=True))

        X = extract_features(url)
        if X.shape != (1, 30):
            raise ValueError(f"Feature shape mismatch. Expected (1, 30), got {X.shape}.")

        X_scaled = scaler.transform(X)
        if X_scaled.shape != (1, 30):
            raise ValueError(f"Scaled feature shape mismatch. Expected (1, 30), got {X_scaled.shape}.")

        pred = int(model.predict(X_scaled)[0])
        proba = model.predict_proba(X_scaled)[0]

        # Per requirement: classes are [-1, 1] and index 0/1 map to phishing/safe.
        phishing_prob = float(proba[0])
        safe_prob = float(proba[1])

        return jsonify(
            {
                "status": pred,
                "phishing_prob": phishing_prob,
                "safe_prob": safe_prob,
            }
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover
        return jsonify({"error": f"Internal server error: {str(exc)}"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
