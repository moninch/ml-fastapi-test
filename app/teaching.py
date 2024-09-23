import tensorflow as tf
import numpy as np
from app.extracting import extract_features
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Пример подготовленных данных
X = [...]  # Данные (фичи)
y = [...]  # Метки (целевые значения: 0 — бенинный трафик, 1 — DDoS трафик)

# Разделение данных на тренировочные и тестовые (80% — обучение, 20% — тест)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Создание модели
model = tf.keras.Sequential([
    tf.keras.layers.InputLayer(input_shape=(X_train.shape[1],)),
    tf.keras.layers.Dense(64, activation='relu'),
    tf.keras.layers.Dense(1, activation='sigmoid')  # Выходной слой для бинарной классификации
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Обучение модели
model.fit(X_train, y_train, epochs=10, validation_data=(X_test, y_test))

# Сохранение модели после обучения
model.save("packet_classifier_model.h5")
