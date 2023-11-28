from datetime import datetime

from scapy.all import IP, UDP, Ether, send, sniff
from scapy.layers.ntp import NTP

import sys

response_date = datetime(year=2023, month=12, day=1, hour=13)


def packet_callback(packet: Ether):
    # Get details
    source_port = packet[UDP].sport
    source_ip = packet[IP].src

    # Create the NTP reply
    reply_packet = (IP(dst=source_ip) /
                    UDP(sport=123, dport=source_port) /
                    NTP(
                        mode=4,
                        ref=response_date,
                        orig=response_date,
                        recv=response_date,
                        sent=response_date))

    # Send the NTP reply
    print(f'Sending NTP reply to: {source_ip}')
    send(reply_packet)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        response_date = datetime(year=2023,
                                 month=12,
                                 day=int(sys.argv[1]),
                                 hour=13)
    print(response_date)

    # Start sniffing for NTP traffic
    sniff(
        count=1000,
        prn=packet_callback,
        filter='udp dst port 123 and src host 10.8.0.48'
    )
