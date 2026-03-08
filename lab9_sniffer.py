from scapy.all import sniff, ICMP, IP

def packet_callback(packet):
    if packet.haslayer(ICMP):
        ip_layer = packet.getlayer(IP)
        print(f"ICMP Packet: {ip_layer.src} -> {ip_layer.dst}")

print("Starting ICMP packet capture...")

sniff(filter="icmp", prn=packet_callback, count=10)