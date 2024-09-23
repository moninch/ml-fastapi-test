from typing import List
from fastapi import FastAPI
from pydantic import BaseModel, constr, conint, condecimal
import tensorflow as tf
import numpy as np
from app.teaching import scaler

app = FastAPI()

model = tf.keras.models.load_model("packet_classifier_model.h5")

class PacketData(BaseModel):
    protocol: constr(regex='^(TCP|UDP|ICMP)$')  # Протокол может быть только TCP, UDP или ICMP
    length: conint(gt=0)  # Длина пакета должна быть больше 0
    time: condecimal(gt=0)  # Временная метка должна быть положительным числом
    src_ip: constr(regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')  # Проверка формата IP-адреса
    dst_ip: constr(regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    src_port: conint(ge=0, le=65535)  # Порт должен быть в диапазоне от 0 до 65535
    dst_port: conint(ge=0, le=65535)  # Порт назначения



@app.post('/classify_packet')
async def classify_packet(data: List[PacketData]):
    results = []

    for packet in data:
        protocol_encoded = [1, 0] if packet.protocol == 'TCP' else [0, 1]

        packet  = [packet.length, packet.time] + protocol_encoded

        packet = scaler.transform([packet])
        prediction = model.predict(packet)
        result = {"protocol": packet.protocol, "action": "accept" if prediction[0] == 0 else "drop"}
        results.append(result)
    
    return {"results": results}


