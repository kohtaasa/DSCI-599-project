"""
This script reads a pcap file and writes the relevant data to a CSV file.
The relevant data includes the timestamp, source IP, destination IP, source port, destination port, UDP payload length,
and IP payload length.
This transformation allows for easier processing of the data in the future.

Note: pcap_file and csv_file are hardcoded for simplicity. In a real-world scenario, these would be passed as arguments
to the script.
"""

from scapy.all import *
import csv

pcap_file = 'data/pcap_files/hdumb_8_false6.pcap'
csv_file = 'data/csv_files/hdumb_8_false6.csv'

with open(csv_file, mode='w') as file:
    field_names = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'udp_payload_length', 'ip_payload_length']
    writer = csv.DictWriter(file, fieldnames=field_names)
    writer.writeheader()

    packets = rdpcap(pcap_file)

    for packet in packets:
        if IP in packet:
            if UDP in packet:
                timestamp = packet.time
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

                udp_header_length = 8  # UDP header is always 8 bytes
                # UDP length field includes the header and payload
                udp_total_length = len(packet[UDP])
                udp_payload_length = udp_total_length - udp_header_length
                ip_total_length = len(packet[IP])

                writer.writerow({'timestamp': timestamp,
                                 'src_ip': src_ip,
                                 'dst_ip': dst_ip,
                                 'src_port': src_port,
                                 'dst_port': dst_port,
                                 'udp_payload_length': udp_payload_length,
                                 'ip_payload_length': ip_total_length})

# with open(csv_file, mode='w') as file:
#     field_names = ['timestamp', 'src_port', 'dst_port', 'payload_length']
#     writer = csv.DictWriter(file, fieldnames=field_names)
#     writer.writeheader()
#
#     packets = rdpcap(pcap_file)
#
#     for packet in packets:
#         if IP in packet:
#             if ESP in packet:
#                 timestamp = packet.time
#                 src_port = 0
#                 dst_port = 0
#                 payload_length = len(packet[IP].payload)
#
#                 writer.writerow({'timestamp': timestamp,
#                                  'src_port': src_port,
#                                  'dst_port': dst_port,
#                                  'payload_length': payload_length})