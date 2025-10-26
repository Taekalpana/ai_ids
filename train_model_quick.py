# ids/train_model_quick.py
import numpy as np
from tensorflow import keras
from tensorflow.keras import layers
import os

# Create a tiny dummy dataset
# WARNING: this is only for demo/testing so the app can load a model.h5
X = np.random.rand(1000, 6).astype("float32")
y = (np.sum(X, axis=1) > 3).astype("float32")

model = keras.Sequential([
    layers.Input(shape=(6,)),
    layers.Dense(16, activation="relu"),
    layers.Dense(8, activation="relu"),
    layers.Dense(1, activation="sigmoid")
])

model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
model.fit(X, y, epochs=5, batch_size=32)

os.makedirs("..", exist_ok=True)
model.save("model.h5")
print("Saved toy model to model.h5 (repo root). Replace this with your real trained model.")
