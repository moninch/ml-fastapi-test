import pyshark

def extract_features(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    
    features = []
    for packet in capture:
        try:
            protocol = packet.transport_layer  # Протокол (TCP, UDP)
            length = int(packet.length)        # Размер пакета
            time = float(packet.sniff_time.timestamp())  # Время захвата
            
            features.append([protocol, length, time])
        except AttributeError:
            pass
    
    return features

#test
features = extract_features("C:\\Learning\\ml-fastapi-test\\trafic\\benign.pcap")
print(features)
