import pyshark
import pandas as pd

def extract_features(pcap_file, label=0):
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
            syn_flag = None
            ack_flag = None

            if protocol == 'TCP':
                syn_flag = int(packet.tcp.flags_syn)
                ack_flag = int(packet.tcp.flags_ack)

            features.append([protocol, length, time, src_ip, dst_ip, src_port, dst_port, syn_flag, ack_flag, label])
        except AttributeError:
            continue
    capture.close()
    return features

def label_ddos_attack(df, syn_threshold=10, ack_threshold=10):
    for index, row in df.iterrows():
        if row['SYN_Flag'] == 1 and row['ACK_Flag'] == 0:
            if (df[(df['Src_IP'] == row['Src_IP']) & (df['SYN_Flag'] == 1)].shape[0] > syn_threshold):
                df.at[index, 'Label'] = 1  #SYN-flood

        elif row['ACK_Flag'] == 1 and row['SYN_Flag'] == 0:
            if (df[(df['Src_IP'] == row['Src_IP']) & (df['ACK_Flag'] == 1)].shape[0] > ack_threshold):
                df.at[index, 'Label'] = 1  #ACK-flood
    
    return df


benign_features = extract_features("benign.pcap")
benign_pc_features = extract_features("benign-pc.pcapng")
cic_benign_features = extract_features("CIC-DDoS-2019-Benign.pcap")

syn_ack_features = extract_features("syn_ack_random.pcap", label=1)
syn_flood_features = extract_features("syn_flood_25.pcap", label=1)

all_features = benign_features + benign_pc_features + cic_benign_features + syn_ack_features + syn_flood_features

df = pd.DataFrame(all_features, columns=['Protocol', 'Length', 'Time', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port', 'SYN_Flag', 'ACK_Flag', 'Label'])

df = pd.get_dummies(df, columns=['Protocol'])

df = label_ddos_attack(df)

df.to_csv("traffic_dataset.csv", index=False)
