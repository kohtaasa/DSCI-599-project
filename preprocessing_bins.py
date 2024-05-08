"""
This script reads a CSV file containing packet data and generates features for each client IP address in the file.
Each session is divided into 10-second bins and generated data is used in the second part of the project (Bayesian Network).

Note: input_csv_path and output_pickle_path are hardcoded for simplicity. In a real-world scenario, these would be
passed as arguments to the script. The number of clients is also hardcoded for simplicity.
"""


import numpy as np
import pandas as pd
import pickle

# Set file paths
input_csv_path = 'data/csv_files/hdumb_3_false1.csv'
output_pickle_path = 'data/pickle_files/hdumb_3_false_bins1.pkl'

# Set the number of clients
number_of_clients = 3

# Load the data
df = pd.read_csv(input_csv_path)

# Generate client IPs based on the number of clients
client_ips = [f'10.0.{i}.1' for i in range(1, number_of_clients + 1)]

features = {client_ip: {} for client_ip in client_ips}

# Dictionary to keep track of the last packet's timestamp for inter-arrival time calculations
last_packet_time = {client_ip: {'incoming': None, 'outgoing': None} for client_ip in client_ips}

for index, row in df.iterrows():
    src_ip = row['src_ip']
    dst_ip = row['dst_ip']
    timestamp = row['timestamp']
    udp_payload_length = row['udp_payload_length']

    if src_ip in client_ips:
        client_ip = src_ip
        direction = 'outgoing'
    elif dst_ip in client_ips:
        client_ip = dst_ip
        direction = 'incoming'

    bin_index = int((timestamp - df['timestamp'].min()) // 10)

    if bin_index not in features[client_ip]:
        features[client_ip][bin_index] = {
            'incoming_bytes': [],
            'outgoing_bytes': [],
            'total_bytes_incoming': 0,
            'total_bytes_outgoing': 0,
            'incoming_packets': 0,
            'outgoing_packets': 0,
            'sum_inter_arrival_incoming': 0,
            'count_inter_arrival_incoming': 0,
            'sum_inter_arrival_outgoing': 0,
            'count_inter_arrival_outgoing': 0
        }

    # Packet length recording for statistics
    features[client_ip][bin_index][f'{direction}_bytes'].append(udp_payload_length)
    features[client_ip][bin_index][f'total_bytes_{direction}'] += udp_payload_length
    features[client_ip][bin_index][f'{direction}_packets'] += 1

    # Inter-arrival time calculation
    if last_packet_time[client_ip][direction] is not None:
        inter_arrival_time = timestamp - last_packet_time[client_ip][direction]
        features[client_ip][bin_index][f'sum_inter_arrival_{direction}'] += inter_arrival_time
        features[client_ip][bin_index][f'count_inter_arrival_{direction}'] += 1
    last_packet_time[client_ip][direction] = timestamp

# Calculate the metrics for each bin after processing all packets
for client_ip in features:
    for bin_index in features[client_ip]:
        for direction in ['incoming', 'outgoing']:
            byte_list = features[client_ip][bin_index][f'{direction}_bytes']
            packet_count = features[client_ip][bin_index][f'{direction}_packets']
            inter_arrival_sum = features[client_ip][bin_index][f'sum_inter_arrival_{direction}']
            inter_arrival_count = features[client_ip][bin_index][f'count_inter_arrival_{direction}']

            # Calculate metrics if there are packets
            if packet_count > 0:
                features[client_ip][bin_index][f'average_{direction}_bytes'] = np.mean(byte_list)
                features[client_ip][bin_index][f'std_{direction}_bytes'] = np.std(byte_list, ddof=1)
                features[client_ip][bin_index][f'median_{direction}_bytes'] = np.median(byte_list)
                features[client_ip][bin_index][f'packet_frequency_{direction}'] = packet_count / 10  # 10 seconds bin size
                if inter_arrival_count > 0:
                    features[client_ip][bin_index][f'average_inter_arrival_{direction}'] = inter_arrival_sum / inter_arrival_count
                else:
                    features[client_ip][bin_index][f'average_inter_arrival_{direction}'] = None
            else:  # No packets
                features[client_ip][bin_index][f'average_{direction}_bytes'] = 0
                features[client_ip][bin_index][f'std_{direction}_bytes'] = 0
                features[client_ip][bin_index][f'median_{direction}_bytes'] = 0
                features[client_ip][bin_index][f'packet_frequency_{direction}'] = 0
                features[client_ip][bin_index][f'average_inter_arrival_{direction}'] = None

            # Free up memory
            del features[client_ip][bin_index][f'{direction}_bytes']

# Save the features dictionary to a pickle file
with open(output_pickle_path, 'wb') as file:
    pickle.dump(features, file)
