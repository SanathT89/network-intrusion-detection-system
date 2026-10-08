#Generate packets directly using Scapy and save them to disk.
from pathlib import Path
from scapy.all import Ether, IP, ICMP, wrpcap

folder = Path("captures")
folder.mkdir(exist_ok=True)

source_ip = "192.0.2.10"
destination_ip = "192.0.2.20"


def create_icmp_packets(count, interval=1, icmp_type=8):
    packets = []

    for i in range(count):
        packet = (
            Ether()
            / IP(src=source_ip, dst=destination_ip)
            / ICMP(
                type=icmp_type,
                code=0,
                id=100,
                seq=i + 1
            )
        )

        packet.time = 1700000000.0 + (i * interval)
        packets.append(packet)

    return packets


#TEST 1: Normal ping activity
#3 requests, 1 second apart
wrpcap(
    str(folder / "icmp_normal.pcap"),
    create_icmp_packets(count=3, interval=1)
)


#TEST 2: High-volume ICMP activity
#20 requests, 1 second apart
wrpcap(
    str(folder / "icmp_spike.pcap"),
    create_icmp_packets(count=20, interval=1)
)


#TEST 3: Slow ICMP activity
#20 requests, 70 seconds apart
wrpcap(
    str(folder / "icmp_slow.pcap"),
    create_icmp_packets(count=20, interval=70)
)


#TEST 4: Echo replies rather than requests
#The detector should ignore these
wrpcap(
    str(folder / "icmp_replies.pcap"),
    create_icmp_packets(count=20, interval=1, icmp_type=0)
)


print("All four ICMP test PCAP files created!")
