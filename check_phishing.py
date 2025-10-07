import joblib
import pandas as pd
import sqlite3
import json
from feature_extractor import extract_features
from phish_list import lookup_url, init_db  # custom functions
from urllib.parse import urlparse

with open("safe_domains.json") as f:
    safe_domains = json.load(f)["top_safe_domains"]

def is_safe(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname.lower()
        return any(hostname.endswith(domain) for domain in safe_domains)
    except:
        return False

def check_url(url):
    print(f"\n🔗 Checking URL: {url}")
    if is_safe(url):
        print("✅ URL is in safe list")
        return {
        "url": url,
        "status": "Safe(Pre-Check)",
        "score": 100,
        "phish_probability": 0,
        "benign_probability": 1,
        "features": {}
    }


    # 1️⃣ Initialize DB and check in phishing list
    conn = init_db()
    try:
        list_result = lookup_url(conn, url)

        if list_result and list_result.get("matched"):
            print("\n Confirmed Phishing URL (found in threat database)")
            if list_result.get("match"):
                print(f"Source: {list_result['match'][1]}")
                print(f"Last seen: {list_result['match'][2]}")
            print("Confidence: 100% 🚨")
            return {
                "url": url,
                "status": "Phishing (Pre-Check)",
                "score": 100,
                "source": list_result.get("match", [None, "Unknown"])[1],
                "last_seen": list_result.get("match", [None, None, "Unknown"])[2],
            }

        print("\n Running ML model...")
        url_features = extract_features(url)

        loaded_model = joblib.load("phishing_model.pkl")
        feature_cols = joblib.load("feature_columns.pkl")
        feature_cols = [col for col in feature_cols if col != "id"]

        check_df = pd.DataFrame([url_features])[feature_cols]

        prediction = loaded_model.predict(check_df)[0]
        probabilities = loaded_model.predict_proba(check_df)[0]
        prob_benign = probabilities[0]
        prob_phish = probabilities[1]

        if prediction == 1:
            print("Likely Phishing")
            print(f"Phishing Probability: {prob_phish:.2f}")
        else:
            print("Safe (Benign)")
            print(f"Benign Probability: {prob_benign:.2f}")

        print("\nFeature Summary:")
        for k, v in url_features.items():
            print(f"  {k}: {v}")

        return {
            "url": url,
            "status": "Phishing" if prediction == 1 else "Benign",
            "score": round(prob_phish * 100 if prediction == 1 else prob_benign * 100, 2),
            "phish_probability": round(prob_phish, 4),
            "benign_probability": round(prob_benign, 4),
            "features": url_features,
        }

    finally:
        conn.close()


if __name__ == "__main__":
    result = check_url("http://00000000883838383992929292222.ratingandreviews.in")
    print("\nFinal Result:", result)
