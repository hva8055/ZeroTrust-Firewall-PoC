import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

DATASET_PATH = "malware_dataset.csv"
MODEL_PATH = "firewall_ai_model.pkl"

print("1. Loading Dataset...")
df = pd.read_csv(DATASET_PATH)


features = ['id.resp_p', 'proto', 'service', 'conn_state', 'orig_bytes', 'resp_bytes']
target = 'label'

df[features] = df[features].fillna(0)
df['orig_bytes'] = df['orig_bytes'].astype(float) # Ensure numbers are floats
df['resp_bytes'] = df['resp_bytes'].astype(float)   

print("2. Encoding Categorical Data...") 
encoders = {} 
for col in ['proto', 'service', 'conn_state']:
    le = LabelEncoder()
    df[col] = df[col].astype(str)
    df[col] = le.fit_transform(df[col])
    encoders[col] = le # Save the encoder to use later!

X = df[features]
y = df[target]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print(f"   Training on {len(X_train)} rows, Testing on {len(X_test)} rows.")

print("3. Training Random Forest Model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print("4. Evaluating Model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n   Model Accuracy: {accuracy * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

data_to_save = {
    "model": model,
    "encoders": encoders
}

with open(MODEL_PATH, "wb") as f:
    pickle.dump(data_to_save, f)

print(f"\n5. Success! Model saved to {MODEL_PATH}")
