import pandas as pd
import time
from model import LSTMClassifier
import torch
import torch.nn.functional as F
def calculate_inter_packet_time(df_group, packet_type):
    if df_group.empty:
        return 0
    df_group = df_group.sort_values(by='TIMESTAMP')
    inter_packet_time = (df_group['TIMESTAMP'] - df_group['TIMESTAMP'].shift()).dropna().abs().mean()
    return inter_packet_time.total_seconds() * 1e3 if inter_packet_time is not pd.NaT else 0

def preprocess_data(df):
    df['TIMESTAMP'] = pd.to_datetime(df['TIMESTAMP'])
    grouped = df.groupby(['SADDR', 'DADDR', 'PROTOCOL'])
    
    network_flows = grouped.agg({'I-COUNT': 'sum', 'O-COUNT': 'sum', 'PROTOCOL': 'first'})  # Include 'PROTOCOL' aggregation
    network_flows.rename(columns={'PROTOCOL': 'proto'}, inplace=True)
    network_flows['spkts'] = network_flows['I-COUNT']
    network_flows['dpkts'] = network_flows['O-COUNT']
    network_flows['dur'] = grouped.apply(lambda x: (x['TIMESTAMP'].max() - x['TIMESTAMP'].min()).total_seconds())
    network_flows['sbytes'] = grouped.apply(lambda x: x[x['TYPE'] == 'IN']['BYTES'].sum())
    network_flows['dbytes'] = grouped.apply(lambda x: x[x['TYPE'] == 'OUT']['BYTES'].sum())
    network_flows['smean'] = grouped.apply(lambda x: x[x['TYPE'] == 'IN']['BYTES'].mean())
    network_flows['dmean'] = grouped.apply(lambda x: x[x['TYPE'] == 'OUT']['BYTES'].mean())
    network_flows['sinpkt'] = grouped.apply(lambda x: calculate_inter_packet_time(x[x['TYPE'] == 'IN'], 'IN'))
    network_flows['dinpkt'] = grouped.apply(lambda x: calculate_inter_packet_time(x[x['TYPE'] == 'OUT'], 'OUT'))
    
    network_flows.drop(columns=['I-COUNT', 'O-COUNT' ], inplace=True)
    network_flows.reset_index(inplace=True)

    network_flows.fillna(0, inplace=True)

    return network_flows


def apply_model(csv_file):
    data = pd.read_csv(csv_file)
    data.drop(columns=['SADDR','DADDR','PROTOCOL'], inplace=True)
    protocol_mapping = {'TCP': 1, 'UDP': 2, 'ICMP': 3 , 'OSPF' : 4}
    data['proto'] = data['proto'].map(protocol_mapping)
    data['proto'] = data['proto'].map(protocol_mapping.get).fillna(0)
    data_tensor = torch.tensor(data.values, dtype=torch.float32)
    input_size = data.shape[1]
    model = LSTMClassifier(input_size,128,2,2) 
    
    model.load_state_dict(torch.load('model.pth'))
    
    model.eval()
    
    data_tensor = torch.tensor(data.values, dtype=torch.float32)
    
    with torch.no_grad():
        predictions = model(data_tensor)

    predictions = F.softmax(predictions, dim=1)

    _, predicted = torch.max(predictions, 1)
    
    return predicted

def main():
    df = pd.read_csv('packet_info.csv')
    preprocessed_data= preprocess_data(df)
    preprocessed_data.to_csv('csv_file.csv', index=False)
    predictions = apply_model('csv_file.csv')
    predictions = apply_model('csv_file.csv')
    predictions_array = predictions.numpy()

    with open('output.txt', 'w') as f:
        if 1 in predictions_array:
            f.write("ANOMALY DETECTED IN THE TRAFFIC!\n")
        else:
            f.write("normal traffic\n")
        

if __name__ == "__main__":
    main()
