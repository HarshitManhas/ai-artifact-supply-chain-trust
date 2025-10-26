#!/usr/bin/env python3
"""
Example ML model script for testing the AI Artifact Supply Chain Trust Framework
"""

import pickle
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.datasets import make_classification

def train_model():
    """Train a simple logistic regression model."""
    X, y = make_classification(n_samples=1000, n_features=20, random_state=42)
    
    model = LogisticRegression(random_state=42)
    model.fit(X, y)
    
    return model

def save_model(model, path):
    """Save model to pickle file."""
    with open(path, 'wb') as f:
        pickle.dump(model, f)

if __name__ == "__main__":
    model = train_model()
    save_model(model, "examples/artifacts/model.pkl")
    print("Model saved to examples/artifacts/model.pkl")
