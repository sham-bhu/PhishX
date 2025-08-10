# model_train.py

import pandas as pd
import joblib
from tqdm import tqdm
from feature_extraction import extract_all_features
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import numpy as np

# Add common real-world suffixes
common_suffixes = [
    "", "/", "/login", "/signin", "/account", "/dashboard", "/home", "/profile",
    "/auth", "/user", "/users", "/settings", "/secure", "/index", "/welcome",
    "/admin", "/portal", "/client", "/customer", "/myaccount", "/update", "/reset"
]

def augment_urls(urls):
    augmented = []
    for url in urls:
        url = url.strip().rstrip('/')
        for suffix in common_suffixes:
            full_url = url + suffix
            if not full_url.startswith("http"):
                full_url = "https://" + full_url
            augmented.append(full_url)
    return augmented

def process_urls(urls, label):
    features_list = []
    for url in tqdm(urls, desc=f"Extracting {'Phishing' if label==1 else 'Legitimate'} URLs"):
        features = extract_all_features(url, for_training=True)
        if features:
            features["label"] = label
            features_list.append(features)
    return features_list

def main():
    print("🔁 Loading datasets...")

    phish_df = pd.read_csv("online-valid.csv")
    phish_urls = phish_df["url"].dropna().tolist()

    legit_df = pd.read_csv("top-1m.csv", usecols=[1], names=["url"], header=0)
    legit_urls = legit_df["url"].dropna().tolist()
    legit_augmented = augment_urls(legit_urls[:1000])  # limit for speed

    print("🔍 Extracting features...")
    phish_data = process_urls(phish_urls, 1)
    legit_data = process_urls(legit_augmented, 0)

    combined_data = phish_data + legit_data
    df = pd.DataFrame(combined_data)
    df = df.select_dtypes(include=[np.number])

    X = df.drop("label", axis=1)
    y = df["label"]

    print("🧠 Training model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"✅ Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred))

    joblib.dump(model, "phishing_model.joblib")
    joblib.dump(list(X.columns), "features.joblib")
    print("💾 Model & features saved.")

if __name__ == "__main__":
    main()
