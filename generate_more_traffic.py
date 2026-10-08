
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

folder = Path("captures")
folder.mkdir(exist_ok=True)

source = "192.0.2.10"
destination = "192.0.2.20"


def make_packets(ports, interval):
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

        packet.time = 1000.0 + i * interval
        packets.append(packet)

    return packets


# TEST 1: Exactly 10 unique ports in 10 seconds
wrpcap(
    str(folder / "threshold_scan.pcap"),
    make_packets(range(1, 11), 1)
)


# TEST 2: 20 unique ports, 65 seconds apart
wrpcap(
    str(folder / "slow_scan.pcap"),
    make_packets(range(1, 21), 65)
)


# TEST 3: 20 attempts to the same port
wrpcap(
    str(folder / "repeated_port.pcap"),
    make_packets([80] * 20, 1)
)


print("Three additional PCAP files created!")
