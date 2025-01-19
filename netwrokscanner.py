from scapy.all import *
from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd

# Initialize variables for traffic statistics
traffic_stats = defaultdict(int)

def packet_callback(packet):
    global traffic_stats
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if packet.haslayer(TCP):
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = 'ICMP'
            src_port = 'N/A'
            dst_port = 'N/A'
        else:
            protocol = 'Other'
            src_port = 'N/A'
            dst_port = 'N/A'
        
        print(f"Protocol: {protocol} | Source IP: {src_ip}:{src_port} -> Destination IP: {dst_ip}:{dst_port}")
        
        # Update traffic statistics
        traffic_stats[protocol] += 1

def display_traffic_stats(filter_criteria=None):
    filtered_stats = {k: v for k, v in traffic_stats.items() if filter_criteria is None or k == filter_criteria}
    
    print("\nTraffic Statistics:")
    for protocol, count in filtered_stats.items():
        print(f"{protocol}: {count} packets")
    
    # Convert filtered_stats to DataFrame
    df = pd.DataFrame(list(filtered_stats.items()), columns=['Protocol', 'Packets'])
    
    # Plotting the graph
    df.plot(kind='bar', x='Protocol', y='Packets', legend=False)
    plt.title('Network Traffic Statistics')
    plt.xlabel('Protocol')
    plt.ylabel('Packets')
    plt.show()

def save_traffic_data(filename):
    with open(filename, 'w') as file:
        file.write("Traffic Analysis Report\n")
        file.write("=======================\n\n")
        
        file.write("Captured Traffic Statistics:\n")
        for protocol, count in traffic_stats.items():
            file.write(f"{protocol}: {count} packets\n")
        
        file.write("\nCaptured Packets:\n")
        # Implement packet logging here if needed

def interactive_mode():
    print("\nInteractive Mode (Type 'exit' to quit)")
    
    while True:
        filter_criteria = input("Enter filter criteria (e.g., 'TCP', 'UDP', 'ICMP', 'IP', 'Other', or leave blank for all): ").upper()
        
        if filter_criteria == 'EXIT':
            break
        
        display_traffic_stats(filter_criteria)

# Start the packet sniffer
print("Starting packet capture...")
sniff(prn=packet_callback, count=100)  # Capture 100 packets

# Display traffic statistics and plot graph
display_traffic_stats()

# Save traffic data to a file
save_traffic_data('traffic_report.txt')

# Enable interactive mode
interactive_mode()
