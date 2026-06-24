"""
train.py
Trains a Random Forest model on the phishing dataset and saves it to model/model.pkl
Run this once before starting the FastAPI server.
"""

import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

def train():
    print("📂 Loading dataset...")
    df = pd.read_csv("data/dataset.csv")

    X = df.drop("label", axis=1)
    y = df["label"]

    print(f"   Total samples : {len(df)}")
    print(f"   Features      : {X.shape[1]}")
    print(f"   Phishing      : {(y == -1).sum()}")
    print(f"   Legitimate    : {(y == 1).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n🌲 Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"\n✅ Accuracy : {acc * 100:.2f}%")
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Phishing", "Legitimate"]))

    print("💾 Saving model to model/model.pkl...")
    with open("model/model.pkl", "wb") as f:
        pickle.dump(model, f)

    print("✅ Done. Model ready.")

if __name__ == "__main__":
    train()
