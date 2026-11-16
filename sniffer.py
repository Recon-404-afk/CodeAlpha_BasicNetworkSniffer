#!/usr/bin/env python3
"""Basic network sniffer for authorized educational use."""

import argparse
from datetime import datetime

from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, get_if_list, sniff


def analyze_packet(packet):
    """Display the headers and a bounded payload preview."""
    timestamp = datetime.fromtimestamp(float(packet.time))
    source = destination = "N/A"
    protocol = packet.name
    payload = b""

    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        protocol = f"IPv4 protocol {packet[IP].proto}"

    elif IPv6 in packet:
        source = packet[IPv6].src
        destination = packet[IPv6].dst
        protocol = f"IPv6 next header {packet[IPv6].nh}"

    if TCP in packet:
        tcp = packet[TCP]
        source = f"[{source}]:{tcp.sport}"
        destination = f"[{destination}]:{tcp.dport}"
        protocol = f"TCP | Flags: {tcp.flags}"
        payload = bytes(tcp.payload)

    elif UDP in packet:
        udp = packet[UDP]
        source = f"[{source}]:{udp.sport}"
        destination = f"[{destination}]:{udp.dport}"
        protocol = "UDP"
        payload = bytes(udp.payload)

    elif ICMP in packet:
        icmp = packet[ICMP]
        protocol = f"ICMP | Type: {icmp.type} | Code: {icmp.code}"
        payload = bytes(icmp.payload)

    elif ARP in packet:
        arp = packet[ARP]
        source = f"{arp.psrc} ({arp.hwsrc})"
        destination = f"{arp.pdst} ({arp.hwdst})"
        protocol = f"ARP | Operation: {arp.op}"

    print("\n" + "=" * 65)
    print(f"Time        : {timestamp:%Y-%m-%d %H:%M:%S}")
    print(f"Source      : {source}")
    print(f"Destination : {destination}")
    print(f"Protocol    : {protocol}")
    print(f"Size        : {len(packet)} bytes")
    print(f"Layers      : {packet.summary()}")

    if payload:
        preview = payload[:120]

        # repr escapes control characters before displaying captured bytes.
        print(f"Payload     : {len(payload)} bytes")
        print(f"Text preview: {preview!r}")
        print(f"Hex preview : {preview.hex(' ')}")
    else:
        print("Payload     : No payload preview for this packet")


def nonnegative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("Must be zero or greater.")
    return number


def main():
    parser = argparse.ArgumentParser(
        description="Capture and inspect network packets with Scapy."
    )
    parser.add_argument(
        "-i", "--interface", help="Interface to capture on, e.g. eth0 or lo"
    )
    parser.add_argument(
        "-f", "--filter", default="", help="BPF filter, e.g. 'tcp' or 'port 8000'"
    )
    parser.add_argument(
        "-c", "--count", type=nonnegative_int, default=0,
        help="Packets to capture; 0 means capture until Ctrl+C"
    )
    parser.add_argument(
        "--list", action="store_true", help="List available interfaces"
    )
    args = parser.parse_args()

    if args.list:
        print("Available interfaces:")
        for interface in get_if_list():
            print(f"  {interface}")
        return

    if not args.interface:
        parser.error("Select an interface with -i, or list interfaces with --list.")

    print(f"Listening on: {args.interface}")
    print(f"Filter: {args.filter or 'all traffic'}")
    print("Press Ctrl+C to stop.")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=analyze_packet,
            store=False,
            count=args.count,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except PermissionError:
        parser.exit(1, "Permission denied. Run capture using sudo.\n")
    except Exception as error:
        parser.exit(1, f"Capture failed: {error}\n")


if __name__ == "__main__":
    main()
