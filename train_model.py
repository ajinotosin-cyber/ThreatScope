"""
train_model.py
---------------
STANDALONE OFFLINE SCRIPT. NOT imported or run by app.py / the Streamlit
app in any way.

Status (audited): this trains a RandomForestClassifier on CIC-IDS2017-style
network-flow records (78 CICFlowMeter features such as flow duration,
packet timing, and byte-rate statistics extracted from raw pcap captures).

Why it is NOT integrated into the ThreatScope app:
    ThreatScope's inputs are a single IOC string (IP/domain/URL/hash), a
    text/CSV/JSON log file, or an uploaded file for hashing/YARA. None of
    these are, or can be trivially converted into, the 78 CICFlowMeter flow
    features this model requires (e.g. "Flow IAT Std", "Fwd Packets/s").
    Producing those features needs a pcap-to-flow feature-extraction
    pipeline (e.g. CICFlowMeter) that does not exist anywhere in this
    repository. Feeding the model anything else would silently produce a
    meaningless prediction — worse than not having the feature at all.

This script is kept in the repo, isolated and clearly labeled, purely as a
documented, reproducible record of how models/model.pkl was produced. It
requires the original CIC-IDS2017 "Friday-WorkingHours-Afternoon-DDos" CSV,
which is present (zipped) under Dataset/ in this repo.

Usage:
    python train_model.py --dataset Dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.zip --output models/model.pkl
"""

from __future__ import annotations

import argparse
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import joblib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset", required=True,
        help="Path to the CIC-IDS2017 CSV (or a .zip containing exactly one CSV).",
    )
    parser.add_argument(
        "--output", default="models/model.pkl",
        help="Where to save the trained model (default: models/model.pkl).",
    )
    parser.add_argument(
        "--n-estimators", type=int, default=100,
        help="Number of trees for the RandomForestClassifier (default: 100).",
    )
    args = parser.parse_args()

    print(f"Loading dataset from {args.dataset} ...")
    df = pd.read_csv(args.dataset)

    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    if "Label" not in df.columns:
        print("ERROR: expected a 'Label' column in the dataset.", file=sys.stderr)
        sys.exit(1)

    label_encoder = LabelEncoder()
    df["Label"] = label_encoder.fit_transform(df["Label"])

    X = df.drop("Label", axis=1)
    y = df["Label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print(f"Training RandomForestClassifier (n_estimators={args.n_estimators}) ...")
    model = RandomForestClassifier(n_estimators=args.n_estimators, random_state=42)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"Holdout accuracy: {accuracy:.4f}")

    joblib.dump(model, args.output)
    print(f"Model saved to {args.output}")


if __name__ == "__main__":
    main()
