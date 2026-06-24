# 🛡️ PhishGuard

**Phishing URL detector — Random Forest ML model with FastAPI backend and retro pixel UI.**

🔗 **Live Demo:** [phishguard-pgwl.onrender.com](https://phishguard-pgwl.onrender.com)

---

## What it does

Paste any URL and PhishGuard instantly analyzes it across **17 structural and lexical features** to produce a **0–100 threat score**. Scores above 50 are flagged as phishing. No external APIs, no data sent anywhere — fully self-contained.

---

## How it works

```
URL Input → Feature Extraction (17 vectors) → Random Forest (100 trees) → Risk Score + Breakdown
```

**Feature vectors include:** IP address usage, URL length, shortening services, `@` symbol, dash in domain, subdomain depth, HTTPS presence, non-standard ports, suspicious keywords, digit ratio, special character count, and more.

**Model:** Trained on 2,000 labeled URLs (phishing + legitimate) using scikit-learn's `RandomForestClassifier`.

---

## Tech Stack

| Layer | Tech |
|-------|------|
| ML Model | scikit-learn (Random Forest) |
| Backend | FastAPI + Python |
| Frontend | HTML, CSS (retro pixel UI) |
| Deployment | Render |

---

## Project Structure

```
phishguard/
├── features.py       # 17 URL feature extraction functions
├── train.py          # Model training script
├── main.py           # FastAPI app + prediction endpoint
├── static/           # Frontend (HTML/CSS)
├── model/            # Saved trained model
└── data/             # Training dataset
```

---

## Run locally

```bash
git clone https://github.com/shancode669/phishguard
cd phishguard
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://localhost:8000`

---

## Author

**Shanthan Sai M** — [LinkedIn](https://linkedin.com/in/shanthan-sai-m) · [GitHub](https://github.com/shancode669)
