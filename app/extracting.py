import pyshark
import pandas as pd

def extract_features(pcap_file, label):
    capture = pyshark.FileCapture(pcap_file)
    features = []
    for packet in capture:
        try:
            protocol = packet.transport_layer  # Протокол (TCP, UDP)
            length = int(packet.length)        # Длина пакета
            time = float(packet.sniff_time.timestamp())  # Временная метка
            src_ip = packet.ip.src if hasattr(packet, 'ip') else None  # IP-адрес источника
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None  # IP-адрес назначения
            src_port = packet[packet.transport_layer].srcport if hasattr(packet, packet.transport_layer) else None  # Порт источника
            dst_port = packet[packet.transport_layer].dstport if hasattr(packet, packet.transport_layer) else None  # Порт назначения
            
            features.append([protocol, length, time, src_ip, dst_ip, src_port, dst_port, label])
        except AttributeError:
            continue
    capture.close()
    return features



benign_features = extract_features("benign.pcap", 0)
benign_pc_features = extract_features("benign-pc.pcapng", 0)
cic_benign_features = extract_features("CIC-DDoS-2019-Benign.pcap", 0)


syn_ack_features = extract_features("syn_ack_random.pcap", 1)
syn_flood_features = extract_features("syn_flood_25.pcap", 1)
all_features = benign_features + benign_pc_features + cic_benign_features + syn_ack_features + syn_flood_features

df = pd.DataFrame(all_features, columns=['Protocol', 'Length', 'Time', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port', 'Label'])
df = pd.get_dummies(df, columns=['Protocol'])

df.to_csv("traffic_dataset.csv", index=False)

