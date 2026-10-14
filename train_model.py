# train_model.py
import csv
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
from sklearn.pipeline import make_pipeline

# 1️⃣ Load the CSV
texts, labels = [], []
with open("data/training_data.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        texts.append(row["text"])
        labels.append(int(row["label"]))

print(f"📚 Loaded {len(texts)} examples")

# 2️⃣ Build the pipeline: text → numbers → classifier
model = make_pipeline(
    TfidfVectorizer(lowercase=True, ngram_range=(1, 2)),   # single words + word pairs
    LogisticRegression(max_iter=1000),
)

# 3️⃣ Estimate accuracy (3-fold cross-validation)
scores = cross_val_score(model, texts, labels, cv=3)
print(f"✅ Estimated accuracy: {scores.mean():.0%}")

# 4️⃣ Train on ALL data and save
model.fit(texts, labels)
joblib.dump(model, "model.pkl")
print("💾 Saved model.pkl")