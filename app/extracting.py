import pandas as pd
# tshark -r CIC-DDoS-2019-Benign.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags.syn -e tcp.flags.ack -e frame.len -e frame.time_epoch -e _ws.col.Protocol -E header=y -E separator=, >CIC-DDoS-2019-Benign.csv
def label_ddos(df, syn_threshold=100, ack_threshold=100):

    syn_counts = df[df['SYN_Flag'] == 1].groupby('Src_IP').size()
    ack_counts = df[df['ACK_Flag'] == 1].groupby('Src_IP').size()

    df['Label'] = 0
    df.loc[df['SYN_Flag'] == 1, 'Label'] = df['Src_IP'].map(syn_counts) > syn_threshold
    df.loc[df['ACK_Flag'] == 1, 'Label'] = df['Src_IP'].map(ack_counts) > ack_threshold

    df['Label'] = df['Label'].astype(int)
    return df

def load_tshark_csv(csv_file, label):
    df = pd.read_csv(csv_file, dtype={'SYN_Flag': 'int', 'ACK_Flag': 'int', 'Src_IP': 'str'}, low_memory=False)
    df['Label'] = label
    return df



benign_features = load_tshark_csv("C:/Learning/ml-fastapi-test/trafic/benign-pc.csv", 0)
benign_pc_features = load_tshark_csv("C:/Learning/ml-fastapi-test/trafic/benign-pc.csv", 0)
cic_benign_features = load_tshark_csv("C:/Learning/ml-fastapi-test/trafic/CIC-DDoS-2019-Benign.csv", 0)

syn_ack_features = load_tshark_csv("C:/Learning/ml-fastapi-test/trafic/syn_ack_random.csv", 1)
syn_flood_features = load_tshark_csv("C:/Learning/ml-fastapi-test/trafic/syn_flood_25.csv", 1)

all_features = pd.concat([benign_features, benign_pc_features, cic_benign_features, syn_ack_features, syn_flood_features], ignore_index=True)

all_features.rename(columns={
    'tcp.flags.syn': 'SYN_Flag',
    'tcp.flags.ack': 'ACK_Flag',
    'ip.src': 'Src_IP',
    'ip.dst': 'Dst_IP',
    'tcp.srcport': 'Src_Port',
    'tcp.dstport': 'Dst_Port'
}, inplace=True)

df = label_ddos(all_features)

df.to_csv("trafic/traffic_dataset.csv", index=False)

print('Обработка завершена')
