from sklearn.ensemble import RandomForestClassifier
import numpy as np
from joblib import dump

# Sample placeholder data: 0 = Normal, 1 = Intrusion
X = np.array([[10, 5, 3, 2], [50, 20, 15, 10]])  
y = np.array([0,1])

model = RandomForestClassifier()
model.fit(X, y)
dump(model, "model.pkl")