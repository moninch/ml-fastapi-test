from fastapi import FastAPI
from pydantic import BaseModel
import tensorflow as tf
import numpy as np
from app.teaching import scaler

app = FastAPI()

model = tf.keras.models.load_model("packet_classifier_model.h5")

class PacketData(BaseModel):
    protocol: str
    length: int
    time: float

def preprocess_data(features):

    features = np.array(features).reshape(1, -1)
    return features


@app.post('/classify_packet')
async def classify_packet(data: PacketData):

    protocol_encoded = [1, 0] if data.protocol == 'TCP' else [0, 1]

    data  = [data.length, data.time] + protocol_encoded

    data = scaler.transform([data])
    prediction = model.predict(data)
    
    return {"result": "accept" if prediction[0] == 0 else "drop"}


