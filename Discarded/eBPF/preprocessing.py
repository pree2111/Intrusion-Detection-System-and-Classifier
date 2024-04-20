import pandas as pd
import time

def calculate_inter_packet_time(df_group, packet_type):
    if df_group.empty:
        return 0
    df_group = df_group.sort_values(by='TIMESTAMP')
    inter_packet_time = (df_group['TIMESTAMP'] - df_group['TIMESTAMP'].shift()).dropna().abs().mean()
    return inter_packet_time.total_seconds() * 1e3 if inter_packet_time is not pd.NaT else 0

def preprocess_data(df):
    df['TIMESTAMP'] = pd.to_datetime(df['TIMESTAMP'])
    grouped = df.groupby(['SADDR', 'DADDR', 'PROTOCOL'])

    network_flows = grouped.agg({'I-COUNT': 'sum', 'O-COUNT': 'sum'})
    network_flows['spkts'] = network_flows['I-COUNT']
    network_flows['dpkts'] = network_flows['O-COUNT']
    network_flows['sbytes'] = grouped.apply(lambda x: x[x['TYPE'] == 'IN']['BYTES'].sum())
    network_flows['dbytes'] = grouped.apply(lambda x: x[x['TYPE'] == 'OUT']['BYTES'].sum())
    network_flows['smean'] = grouped.apply(lambda x: x[x['TYPE'] == 'IN']['BYTES'].mean())
    network_flows['dmean'] = grouped.apply(lambda x: x[x['TYPE'] == 'OUT']['BYTES'].mean())
    network_flows['sinkpt'] = grouped.apply(lambda x: calculate_inter_packet_time(x[x['TYPE'] == 'IN'], 'IN'))
    network_flows['dinkpt'] = grouped.apply(lambda x: calculate_inter_packet_time(x[x['TYPE'] == 'OUT'], 'OUT'))
    
    network_flows.drop(columns=['I-COUNT' , 'O-COUNT'], inplace=True)
    network_flows.rename(columns={'PROTOCOL': 'proto'}, inplace=True)

    network_flows['id'] = range(1, len(network_flows) + 1)

    cols = list(network_flows.columns)
    cols = [cols[-1]] + cols[:-1]
    network_flows = network_flows[cols]

    network_flows.reset_index(drop=True, inplace=True)

    return network_flows

def apply_model(csv_file):
    

def main():
    while True:
        df = pd.read_csv('room_1min.csv')

        preprocessed_data= preprocess_data(df)
        preprocessed_data.to_csv('csv_file.csv', index=False)

        predictions = apply_model('csv_file.csv')

        predictions.to_csv('output.csv', index=False)

        time.sleep(30)

if __name__ == "__main__":
    main()
