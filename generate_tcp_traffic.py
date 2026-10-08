from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

folder = Path("captures")
folder.mkdir(exist_ok=True)

source = "192.0.2.10"
destination = "192.0.2.20"


def make_packets(ports, interval=1):
    packets = []

    for i, port in enumerate(ports):
        packet = (
            Ether()
            / IP(src=source, dst=destination)
            / TCP(
                sport=50000 + i,
                dport=port,
                flags="S"
            )
        )

        packet.time = 1700000000.0 + i * interval
        packets.append(packet)

    return packets


# Test 1: Three attempts to port 22
wrpcap(
    str(folder / "tcp_normal.pcap"),
    make_packets([22] * 3)
)

# Test 2: Twenty attempts to port 22
wrpcap(
    str(folder / "tcp_spike.pcap"),
    make_packets([22] * 20)
)

# Test 3: Twenty attempts, 70 seconds apart
wrpcap(
    str(folder / "tcp_slow.pcap"),
    make_packets([22] * 20, interval=70)
)

# Test 4: Twenty attempts across different ports
wrpcap(
    str(folder / "tcp_many_ports.pcap"),
    make_packets(range(1, 21))
)

print("TCP test PCAP files created successfully!")
