# Basic Network Sniffer

A Python network sniffer built using Scapy for my CodeAlpha cybersecurity internship.

## Features
- Capture packets on a selected network interface.
- Display source and destination IP addresses and ports.
- Identify TCP, UDP, ICMP and ARP traffic.
- Display packet size, layer summary and payload previews.
- Filter traffic using BPF filters.
- Set a packet capture limit.

## Requirements
- Linux
- Python 3
- Scapy
- libpcap for capture filters
- Root privileges for packet capture

## Installation

```bash
sudo apt update
sudo apt install python3-venv python3-pip libpcap-dev -y
git clone https://github.com/Recon-404-afk/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

## Usage

List interfaces:

```bash
.venv/bin/python sniffer.py --list
```

Capture 20 packets, replacing eth0 with your interface:

```bash
sudo .venv/bin/python sniffer.py -i eth0 -c 20
```

Capture local ICMP traffic:

```bash
sudo .venv/bin/python sniffer.py -i lo -f "icmp"
```

Capture local HTTP test traffic:

```bash
sudo .venv/bin/python sniffer.py -i lo -f "tcp port 8000"
```

Press Ctrl+C to stop capturing.

## Testing
- Verified ICMP capture using ping on the loopback interface.
- Verified TCP and HTTP payload capture using a local Python HTTP server and curl.

## Limitations
- Captures only traffic visible to the selected interface.
- Does not decrypt HTTPS traffic.
- Inspects individual packets without reconstructing complete TCP streams.
- Payload previews are limited to the first 120 bytes.

## Responsible Use
Use only on your own devices or networks where you have permission to capture traffic.
