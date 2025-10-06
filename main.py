import joblib
import pandas as pd
import sqlite3
from feature_extractor import extract_features
from phish_list import lookup_url, init_db  # import your simplified lookup and DB init

def check_url(url):
    # 1️⃣ Initialize DB and check if the URL is in the phishing list
    conn = init_db()
    list_result = lookup_url(conn, url)

    if list_result["matched"]:
        print("⚠️  Confirmed Phishing URL (in threat database)")
        print(f"Source: {list_result['match'][1]}")
        print(f"Last seen: {list_result['match'][2]}")
        print("Confidence: 100%")
        conn.close()
        return

    # 2️⃣ If not in the list → use ML model
    url_features = extract_features(url)
    loaded_model = joblib.load("phishing_model.pkl")
    feature_cols = joblib.load("feature_columns.pkl")
    feature_cols = [col for col in feature_cols if col != "id"]

    # Build DataFrame for prediction
    check_df = pd.DataFrame([url_features])[feature_cols]

    prediction = loaded_model.predict(check_df)[0]
    probabilities = loaded_model.predict_proba(check_df)[0]
    prob_benign = probabilities[0]
    prob_phish = probabilities[1]

    print(f"\n🔍 URL: {url}")
    if prediction == 1:
        print("🚨 Likely Phishing")
        print(f"Phishing Probability: {prob_phish:.2f}")
    else:
        print("✅ Safe (Benign)")
        print(f"Benign Probability: {prob_benign:.2f}")

    print("\nFeature Summary:")
    for k, v in url_features.items():
        print(f"  {k}: {v}")

    conn.close()

check_url("http://allegro.pl-oferta78524.sbs")
