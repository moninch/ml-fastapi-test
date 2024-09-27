import pandas as pd

# tshark -r benign.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags -e frame.len -e frame.time_epoch -e _ws.col.Protocol -E header=y -E separator=, > benign.csv
def extract_flags(df):
    df['tcp.flags'] = df['tcp.flags'].fillna('0').apply(lambda x: int(str(x), 16))

    df['tcp.flags.syn'] = df['tcp.flags'].apply(lambda x: int(x) & 0x02 > 0)
    df['tcp.flags.ack'] = df['tcp.flags'].apply(lambda x: int(x) & 0x10 > 0)
    df['tcp.flags.fin'] = df['tcp.flags'].apply(lambda x: int(x) & 0x01 > 0)
    df['tcp.flags.rst'] = df['tcp.flags'].apply(lambda x: int(x) & 0x04 > 0)
    return df

def aggregate_traffic(df):
    if 'tcp.flags.fin' not in df.columns:
        df['tcp.flags.fin'] = 0
    if 'tcp.flags.rst' not in df.columns:
        df['tcp.flags.rst'] = 0

    aggregation = df.groupby(['ip.src', 'ip.dst', '_ws.col.protocol']).agg(
        syn_count=pd.NamedAgg(column='tcp.flags.syn', aggfunc='sum'),
        ack_count=pd.NamedAgg(column='tcp.flags.ack', aggfunc='sum'),
        fin_count=pd.NamedAgg(column='tcp.flags.fin', aggfunc='sum'),
        rst_count=pd.NamedAgg(column='tcp.flags.rst', aggfunc='sum'),
        total_bytes=pd.NamedAgg(column='frame.len', aggfunc='sum'),
        packet_count=pd.NamedAgg(column='ip.src', aggfunc='size'),
        label= pd.NamedAgg(column='Label', aggfunc='max')
    ).reset_index()

    return aggregation


def load_tshark_csv(benign_files, malicious_files):
    benign_dfs = [pd.read_csv(file, low_memory=False) for file in benign_files]
    benign_data = pd.concat(benign_dfs, ignore_index=True)
    benign_data['Label'] = 0  

    malicious_dfs = [pd.read_csv(file, low_memory=False) for file in malicious_files]
    malicious_data = pd.concat(malicious_dfs, ignore_index=True)
    malicious_data['Label'] = 1  

    all_data = pd.concat([benign_data, malicious_data], ignore_index=True)

    return all_data

benign_files = [
    "C:/Learning/ml-fastapi-test/trafic/benign-pc.csv",
    "C:/Learning/ml-fastapi-test/trafic/benign.csv"
]

malicious_files = [
    "C:/Learning/ml-fastapi-test/trafic/syn_ack_random.csv", 
    "C:/Learning/ml-fastapi-test/trafic/syn_flood_25.csv",
    "C:/Learning/ml-fastapi-test/trafic/CIC-DDoS-2019-Benign.csv"
]

df = load_tshark_csv(benign_files, malicious_files)
df = extract_flags(df)
df = aggregate_traffic(df)
df.to_csv("trafic/traffic_dataset.csv", index=False)

print('Обработка завершена')
