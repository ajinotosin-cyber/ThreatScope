import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
df = pd.read_csv(r"C:\Users\OLUWATOSIN\Desktop\ThreatScope\Dataset\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.zip")

# Clean dataset
df.columns = df.columns.str.strip()

import numpy as np

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)



# Encode labels
label_encoder = LabelEncoder()
df['Label'] = label_encoder.fit_transform(df['Label'])

# Features and target
X = df.drop('Label', axis=1)
y = df['Label']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = RandomForestClassifier(n_estimators=100)

model.fit(X_train, y_train)

# Predictions
predictions = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, predictions)

print(f"Model Accuracy: {accuracy}")

# Save model
joblib.dump(model, "models/model.pkl")

print("Model saved successfully.")