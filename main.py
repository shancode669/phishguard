"""
main.py
FastAPI backend for Phishing Website Detector.
Run with: uvicorn main:app --reload
"""

import pickle
import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from features import get_features, features_to_list

app = FastAPI(title="Phishing Detector API")

# Load model on startup
MODEL_PATH = "model/model.pkl"
model = None

@app.on_event("startup")
def load_model():
    global model
    if not os.path.exists(MODEL_PATH):
        raise RuntimeError("Model not found. Run train.py first.")
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    print("✅ Model loaded.")

# Serve static files (the web UI)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def root():
    return FileResponse("static/index.html")

# ── API ────────────────────────────────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    url: str
    result: str          # "Phishing" or "Legitimate"
    confidence: float    # 0.0 to 1.0
    features: dict
    risk_score: int      # 0-100

@app.post("/predict", response_model=PredictionResponse)
def predict(req: URLRequest):
    url = req.url.strip()

    # Add scheme if missing so urlparse works correctly
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Extract features
    feats = get_features(url)

    # Use DataFrame to preserve feature names and avoid sklearn warning
    import pandas as pd
    feat_df = pd.DataFrame([feats])

    # Predict
    prediction = model.predict(feat_df)[0]
    proba = model.predict_proba(feat_df)[0]

    # model classes: -1 = phishing, 1 = legitimate
    classes = list(model.classes_)
    phishing_idx = classes.index(-1)
    legit_idx = classes.index(1)

    phishing_prob = proba[phishing_idx]
    legit_prob = proba[legit_idx]

    result = "Phishing" if prediction == -1 else "Legitimate"
    confidence = phishing_prob if result == "Phishing" else legit_prob
    risk_score = int(phishing_prob * 100)

    return PredictionResponse(
        url=req.url,
        result=result,
        confidence=round(confidence, 4),
        features=feats,
        risk_score=risk_score
    )

@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": model is not None}
