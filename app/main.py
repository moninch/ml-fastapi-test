from typing import List
from fastapi import FastAPI
from pydantic import BaseModel, constr, conint, condecimal
import tensorflow as tf
import numpy as np
from app.teaching import scaler

app = FastAPI()

model = tf.keras.models.load_model("packet_classifier_model.h5")

class PacketData(BaseModel):
    protocol: constr(regex='^(TCP|UDP|ICMP)$')
    length: conint(gt=0)
    time: condecimal(gt=0)
    src_ip: constr(regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    dst_ip: constr(regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    src_port: conint(ge=0, le=65535)
    dst_port: conint(ge=0, le=65535)
    syn_flag: conint(ge=0, le=1)  
    ack_flag: conint(ge=0, le=1)
    
@app.post('/classify_packet')
async def classify_packet(data: List[PacketData]):
    results = []
    
    for packet in data:
        protocol_encoded = [1, 0] if packet.protocol == 'TCP' else [0, 1]
        packet_data = [packet.length, packet.time, packet.syn_flag, packet.ack_flag] + protocol_encoded

        packet_data = scaler.transform([packet_data])
        prediction = model.predict(packet_data)
        result = {"protocol": packet.protocol, "action": "accept" if prediction[0][0] < 0.5 else "drop"}
        results.append(result)

    return {"results": results}
