import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

pd.set_option('display.max_columns', None)
plt.rcParams['figure.figsize'] = (12,6)

data = pd.read_csv('phishing_dataset.csv')
data = data.drop(columns=['id'])


float_cols = data.select_dtypes('float64').columns
for c in float_cols:
    data[c] = data[c].astype('float32')

int_cols = data.select_dtypes('int64').columns
for c in int_cols:
    data[c] = data[c].astype('int32')

# data.info()

# print (data.columns[:25])


def train_model(data, n_features):
    feature_cols = data.drop(columns=['CLASS_LABEL']).columns[:n_features]
    X=data[feature_cols]
    y=data['CLASS_LABEL']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, shuffle=True)

    lr = LogisticRegression(max_iter=10000)
    lr.fit(X_train, y_train)

    y_pred = lr.predict(X_test)

    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    accuracy = accuracy_score(y_test, y_pred)

    print("Precision:", precision, "Recall:", recall, "F1:", f1, "Accuracy:", accuracy)

    return lr, feature_cols

model, feature_cols = train_model(data, n_features=24)
joblib.dump(model, 'phishing_model.pkl')
joblib.dump(feature_cols, 'feature_columns.pkl')
