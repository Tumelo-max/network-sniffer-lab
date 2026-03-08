from scapy.all import sniff, ICMP, IP
from datetime import datetime

packet_count = 0  # Counter for packets

def packet_callback(packet):
    global packet_count
    if ICMP in packet and IP in packet:
        packet_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src = packet[IP].src
        dst = packet[IP].dst
        print(f"[{timestamp}] ICMP Packet #{packet_count}: {src} -> {dst}")

print("Starting ICMP packet capture...")
sniff(filter="icmp", prn=packet_callback, count=10)  # Change count=None for continuous capture
print(f"Captured {packet_count} ICMP packets.")
