import joblib
import pandas as pd

url_features = {
    'NumDots': 2, 'SubdomainLevel': 1, 'PathLevel': 1, 'UrlLength': 99, 'NumDash': 1, 'NumDashInHostname': 0, 'AtSymbol': 0, 'TildeSymbol': 0, 'NumUnderscore': 2, 'NumPercent': 0, 'NumQueryComponents': 3, 'NumAmpersand': 2, 'NumHash': 0, 'NumNumericChars': 10, 'NoHttps': 0, 'RandomString': 1, 'IpAddress': 0, 'DomainInSubdomains': 0, 'DomainInPaths': 0, 'HttpsInHostname': 0, 'HostnameLength': 14, 'PathLength': 7, 'QueryLength': 69, 'DoubleSlashInPath': 0 }

loaded_model = joblib.load('phishing_model.pkl')
feature_cols = joblib.load('feature_columns.pkl')
feature_cols = [col for col in feature_cols if col != 'id']

check_url = pd.DataFrame([url_features])[feature_cols]

prediction = loaded_model.predict(check_url)[0]
probabilities = loaded_model.predict_proba(check_url)[0]
prob_benign = probabilities[0]
prob_phish = probabilities[1]

print("Prediction:", "Phishing" if prediction==1 else "Benign")
print("Probability of Phishing:", prob_phish)
print("Probability of Benign:", prob_benign)
