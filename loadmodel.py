import joblib
import pandas as pd

url_features = {'PctExtHyperlinks': 1.0, 'PctExtResourceUrls': 0.5555555555555556, 'PctNullSelfRedirectHyperlinks': 0.07936507936507936, 'PctExtNullSelfRedirectHyperlinksRT': 1.0793650793650793, 'NumNumericChars': 0, 'FrequentDomainNameMismatch': 0, 'ExtMetaScriptLinkRT': 0.5, 'NumDash': 0, 'SubmitInfoToEmail': 0, 'NumDots': 4, 'PathLength': 19, 'QueryLength': 17, 'PathLevel': 1, 'InsecureForms': 0, 'UrlLength': 64, 'NumSensitiveWords': 5, 'NumQueryComponents': 1, 'PctExtResourceUrlsRT': 0.5555555555555556, 'IframeOrFrame': 1, 'HostnameLength': 19, 'NumAmpersand': 0, 'AbnormalExtFormActionR': 3, 'UrlLengthRT': 3.2, 'NumDashInHostname': 0, 'IpAddress': 0, 'AbnormalFormAction': 1, 'EmbeddedBrandName': False, 'NumUnderscore': 1, 'MissingTitle': 0, 'DomainInPaths': 0, 'SubdomainLevel': 1, 'ExtFormAction': 1}

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
