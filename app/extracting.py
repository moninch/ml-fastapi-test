import pyshark
import pandas as pd

def extract_features(pcap_file, label=0):
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    features = []
    for packet in capture:
        try:
            protocol = str(packet.transport_layer)  # Протокол (TCP, UDP)
            length = int(packet.length)        # Длина пакета
            time = float(packet.sniff_time.timestamp())  # Временная метка
            src_ip = packet.ip.src if hasattr(packet, 'ip') else None  # IP-адрес источника
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None  # IP-адрес назначения
            src_port = packet[packet.transport_layer].srcport if hasattr(packet, protocol) else None  # Порт источника
            dst_port = packet[packet.transport_layer].dstport if hasattr(packet, protocol) else None  # Порт назначения
            syn_flag = None
            ack_flag = None
            if protocol == 'TCP':
                syn_flag = 1 if packet.tcp.flags_syn == 'True' else 0
                ack_flag = 1 if packet.tcp.flags_ack == 'True' else 0

            features.append([protocol, length, time, src_ip, dst_ip, src_port, dst_port, syn_flag, ack_flag, label])
        except AttributeError:
            continue
    capture.close()
    return features

# def label_ddos_attack(row, syn_threshold=100, ack_threshold=100):
#     if (row['SYN_Flag'] == 1) & (row['ACK_Flag'] == 0):
#         if (df[(df['Src_IP'] == row['Src_IP']) & (df['SYN_Flag'] == 1)].shape[0] > syn_threshold):
#             return 1  # Обнаружена атака SYN-флуд

#     # Проверка на ACK-флуд
#     elif (row['ACK_Flag'] == 1) & (row['SYN_Flag'] == 0):
#         if (df[(df['Src_IP'] == row['Src_IP']) & (df['ACK_Flag'] == 1)].shape[0] > ack_threshold):
#             return 1  # Обнаружена атака ACK-флуд
    
#     return 0  # Нет атаки


benign_features = extract_features("C:\Learning\ml-fastapi-test\\trafic\\benign-pc.pcapng")
# benign_pc_features = extract_features("C:\Learning\ml-fastapi-test\\trafic\\benign-pc.pcapng")
# cic_benign_features = extract_features("C:\Learning\ml-fastapi-test\\trafic\\CIC-DDoS-2019-Benign.pcap")

# syn_ack_features = extract_features("C:\Learning\ml-fastapi-test\\trafic\\syn_ack_random.pcap", label=1)
# syn_flood_features = extract_features("C:\Learning\ml-fastapi-test\\trafic\\syn_flood_25.pcap", label=1)

# all_features = benign_features + benign_pc_features + cic_benign_features + syn_ack_features + syn_flood_features
all_features = benign_features

df = pd.DataFrame(all_features, columns=['Protocol', 'Length', 'Time', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port', 'SYN_Flag', 'ACK_Flag', 'Label'])

# df['Label'] = df.apply(label_ddos_attack, axis=1)

df = pd.get_dummies(df, columns=['Protocol'])

df.to_csv("traffic_dataset.csv", index=False)
