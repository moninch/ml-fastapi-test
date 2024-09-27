import tensorflow as tf
import numpy as np
import pandas as pd
from app.extracting import extract_features
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt

df = pd.read_csv("C:\Learning\ml-fastapi-test\\trafic\\traffic_dataset.csv")

X = df.drop('Label', axis=1)
y = df['Label']
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2)


model = tf.keras.models.Sequential([
    tf.keras.layers.Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
    tf.keras.layers.Dropout(0.2),
    tf.keras.layers.Dense(64, activation='relu'),
    tf.keras.layers.Dropout(0.2),
    tf.keras.layers.Dense(1, activation='sigmoid')  # Выходной слой для бинарной классификации
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

t = model.fit(X_train, y_train, epochs=20, validation_data=(X_test, y_test))


plt.plot(t.history['accuracy'], label='Точность на обучении')
plt.plot(t.history['val_accuracy'], label='Точность на проверке')
plt.xlabel('Эпохи')
plt.ylabel('Точность')
plt.legend()
plt.show()

model.save("packet_classifier_model.h5")
