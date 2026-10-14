# ml_model.py
import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

_model = None   # cache: load the file only once


def _load_model():
    global _model
    if _model is None and os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
    return _model


def ml_scam_probability(text):
    """Return scam probability 0.0–1.0, or None if no model is trained yet."""
    model = _load_model()
    if model is None:
        return None                       # app still works without the model 👍
    return float(model.predict_proba([text])[0][1])   # column 1 = label "1" = scam