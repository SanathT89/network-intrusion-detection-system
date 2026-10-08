#Code intent to generate test pcap files 
from pathlib import Path
from scapy.all import IP, TCP, Ether, wrpcap

capture_dir = Path("captures")
capture_dir.mkdir(exist_ok=True)

source_ip = "192.0.2.10"
target_ip = "192.0.2.20"
# Reserved documentation addresses,nothing is sent to IP

normal_packets = []

# Normal traffic: Three ports 80, 443,8080
for i, port in enumerate([80, 443, 8080]):
    packet = (
        Ether()
        / IP(src=source_ip, dst=target_ip)
        / TCP(sport=50000 + i, dport=port, flags="S")
    )
    packet.time = 1000.0 + i
    normal_packets.append(packet)

wrpcap(
    str(capture_dir / "normal_traffic.pcap"),
    normal_packets
)

print("Normal traffic PCAP created.")

# Simulated port scan: 20 destination ports
scan_packets = []

for i, port in enumerate(range(1, 21)):
    packet = (
        Ether()
        / IP(src=source_ip, dst=target_ip)
        / TCP(sport=50000, dport=port, flags="S")
    )
    packet.time = 2000.0 + i
    #connections made in 20 seconds
    scan_packets.append(packet)

wrpcap(
    str(capture_dir / "scan_test.pcap"),
    scan_packets
)
print("Port scan simulation PCAP created.")
