import sqlite3
import requests
import pandas as pd
import csv
import os

from scapy.all import *

database_path = '../data/datasets.db'
temp_dir = '../temp_downloads'
os.makedirs(temp_dir, exist_ok=True)
final_csv_path = '../data/samples/preprocessed_data2.csv'


def append_to_csv(file_path, data):
    mode = 'a' if os.path.exists(file_path) else 'w'
    with open(file_path, mode, newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=data.keys())
        if mode == 'w':
            writer.writeheader()
        writer.writerow(data)


def convert_pcap_to_csv(pcap_file):
    temp_csv_file = f"{pcap_file}.csv"

    with open(temp_csv_file, mode='w') as file:
        field_names = ['timestamp', 'src_port', 'dst_port', 'payload_length']
        writer = csv.DictWriter(file, fieldnames=field_names)
        writer.writeheader()

        packets = rdpcap(pcap_file)

        for packet in packets:
            if IP in packet:
                if UDP in packet:
                    timestamp = packet.time
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport

                    udp_header_length = 8  # UDP header is always 8 bytes
                    # UDP length field includes the header and payload
                    # udp_total_length = len(packet[UDP])
                    # udp_payload_length = udp_total_length - udp_header_length
                    ip_payload_length = len(packet[IP].payload)

                    writer.writerow({'timestamp': timestamp,
                                     'src_port': src_port,
                                     'dst_port': dst_port,
                                     'payload_length': ip_payload_length})

    print(f"Preprocessed {pcap_file} and saved to {temp_csv_file}.")
    return temp_csv_file


def preprocess_pcap(csv_file):
    df = pd.read_csv(csv_file)
    # Extract total statistics
    total_packets = len(df)
    total_bytes = df['payload_length'].sum()
    avg_bytes = df['payload_length'].mean()
    std_bytes = df['payload_length'].std()
    median_bytes = df['payload_length'].median()
    max_bytes = df['payload_length'].max()

    # Extract statistics for incoming packets
    df_in = df[df['dst_port'] == 10000].copy()
    total_packets_in = len(df_in)
    total_bytes_in = df_in['payload_length'].sum()
    avg_bytes_in = df_in['payload_length'].mean()
    std_bytes_in = df_in['payload_length'].std()
    median_bytes_in = df_in['payload_length'].median()
    max_bytes_in = df_in['payload_length'].max()

    # Extract statistics for outgoing packets
    df_out = df[df['src_port'] == 10000].copy()
    total_packets_out = len(df_out)
    total_bytes_out = df_out['payload_length'].sum()
    avg_bytes_out = df_out['payload_length'].mean()
    std_bytes_out = df_out['payload_length'].std()
    median_bytes_out = df_out['payload_length'].median()
    max_bytes_out = df_out['payload_length'].max()

    # Inter-arrival time
    df_in.sort_values(by='timestamp', inplace=True)
    df_in['inter_arrival_time'] = df_in['timestamp'].diff()
    avg_inter_arr = df_in['inter_arrival_time'].mean()
    std_inter_arr = df_in['inter_arrival_time'].std()
    median_inter_arr = df_in['inter_arrival_time'].median()
    max_inter_arr = df_in['inter_arrival_time'].max()

    # Delete the temporary csv file after processing
    os.remove(csv_file)

    return {
        'total_packets': total_packets,
        'total_bytes': total_bytes,
        'avg_bytes': avg_bytes,
        'std_bytes': std_bytes,
        'median_bytes': median_bytes,
        'max_bytes': max_bytes,
        'total_packets_in': total_packets_in,
        'total_bytes_in': total_bytes_in,
        'avg_bytes_in': avg_bytes_in,
        'std_bytes_in': std_bytes_in,
        'median_bytes_in': median_bytes_in,
        'max_bytes_in': max_bytes_in,
        'total_packets_out': total_packets_out,
        'total_bytes_out': total_bytes_out,
        'avg_bytes_out': avg_bytes_out,
        'std_bytes_out': std_bytes_out,
        'median_bytes_out': median_bytes_out,
        'max_bytes_out': max_bytes_out,
        'avg_inter_arr': avg_inter_arr,
        'std_inter_arr': std_inter_arr,
        'median_inter_arr': median_inter_arr,
        'max_inter_arr': max_inter_arr
    }


def extract_video_status(metadata_dict, url):
    # Check if video status is indicated in the metadata dictionary
    if 'vtc' in metadata_dict:
        video_status = metadata_dict['vtc'].lower()
        if video_status == 'video-true':
            return True
        elif video_status == 'video-false':
            return False
        else:
            print(f"Unknown video status in metadata: {metadata_dict['vtc']}")

    # Extract video status from the URL if not found in metadata
    filename = url.split('/')[-1]
    segments = filename.split('.')
    # Attempt to find a segment indicating video status before the file extension
    video_status_segment = segments[-2].lower()
    if 'true' in video_status_segment:
        return True
    elif 'false' in video_status_segment:
        return False

    # Handle cases where video status is part of a different URL segment
    # Looking for segments like 'exp-a-False'
    for segment in url.split('/'):
        if 'false' in segment.lower():
            return False
        elif 'true' in segment.lower():
            return True

    print(f"Unknown video status in URL: {url}")
    return None  # Indicate that the video status could not be determined


def extract_metadata(metadata, url):
    metadata_dict = {}
    parts = metadata.split()
    current_key = None
    for part in parts:
        if ':' in part:
            current_key, value = part.split(':')
            metadata_dict[current_key] = value
        else:
            if current_key:
                metadata_dict[current_key] = part
                current_key = None

    refined_metadata = {}
    refined_metadata['video_on'] = extract_video_status(metadata_dict, url)
    refined_metadata['num_clients'] = int(metadata_dict['num-clients'])
    refined_metadata['topology'] = metadata_dict.get('topology')
    # refined_metadata['vpn'] = metadata_dict.get('vpn')
    # refined_metadata['vpn_topology'] = metadata_dict.get('vpn-topology')

    return refined_metadata


# Fetch url and metadata from the database
conn = sqlite3.connect(database_path)
cur = conn.cursor()
cur.execute('SELECT url, metadata FROM row_data WHERE metadata NOT LIKE "%vpn%"')
rows = cur.fetchall()


for url, metadata in rows:
    print(f"Downloading data from {url} with metadata: {metadata}")
    try:
        response = requests.get(url)
        file_name = os.path.join(temp_dir, f"temp_{hash(url)}.pcap")
        with open(file_name, 'wb') as file:
            file.write(response.content)

        metadata_dict = extract_metadata(metadata, url)

        csv_file = convert_pcap_to_csv(file_name)
        stats = preprocess_pcap(csv_file)
        # print(stats)

        combined_data = {**metadata_dict, **stats}  # Combine metadata and stats
        append_to_csv(final_csv_path, combined_data)

        os.remove(file_name)
        print(f"Deleted {file_name} after preprocessing.")

    except Exception as e:
        print(f"Failed to preprocess data from {url}. Error: {e}")

# Close the connection after all operations are done
conn.close()
