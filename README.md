# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

## Overview

This project is an educational Python packet sniffer created using Scapy with assistance from GitHub Copilot. The purpose of the project is to demonstrate basic packet capture and protocol decoding while following ethical cybersecurity practices.

The packet sniffer is intended only for authorized lab traffic, traffic on my own computer, loopback traffic, or instructor-provided PCAP files.

## Requirements

- Python 3.10 or newer
- Scapy
- pytest
- Administrative/root privileges may be required for live packet capture

Install the required Python packages using:

```bash
pip install -r requirements.txt
```

## Running the Packet Sniffer

Display the available command-line options:

```bash
python sniffer.py --help
```

Example of capturing authorized loopback TCP traffic:

```bash
sudo .venv/bin/python sniffer.py --interface lo0 --filter "tcp port 8000" --count 10
```

The `--count` option controls the number of packets captured. The `--interface` option selects the network interface, and `--filter` applies a BPF filter.

The program can also safely analyze an instructor-provided PCAP file instead of performing live capture.

## Supported Decoding

The program can identify and decode information from:

- IPv4
- TCP
- UDP
- DNS queries
- Unencrypted HTTP request information

The program does not attempt to decrypt HTTPS traffic.

## Ethical Safeguards and Redaction

This packet sniffer should only be used on systems and networks where the user has authorization to capture traffic.

Before information is displayed, the program applies safeguards to reduce the exposure of sensitive information. These include:

- Partial masking of IPv4 addresses
- Email address redaction
- Authorization header redaction
- Cookie and session information redaction
- Sensitive URL query parameter redaction
- No credential extraction
- No HTTPS decryption
- No stealth or persistence features

For example, an IPv4 address such as `192.168.1.42` is displayed as `192.168.1.xxx`.

## Testing

Unit tests are included in the `tests/` directory. The tests use synthetic packets rather than real network traffic.

Run the tests with:

```bash
python -m pytest -q
```

The tests verify packet decoding, IP masking, sensitive-data redaction, DNS parsing, HTTP parsing, and safe handling of unknown packet types.

## AI Use Policy

GitHub Copilot may be used for:

- Boilerplate code
- CLI parsing
- JSON formatting
- Unit test scaffolds

GitHub Copilot must not be used for:

- Capturing other people's traffic
- Bypassing operating-system permissions
- Creating stealth features
- Creating persistence mechanisms
- Hiding packet-sniffer activity

The project must always:

- Use an interface or PCAP allowlist
- Include redaction of sensitive information
- Default to PCAP mode if capture privileges are unavailable

## Ethical Use

This project is for educational and authorized cybersecurity use only. Packet capture should only be performed on my own machine, loopback traffic, an instructor-provided lab environment, or instructor-provided PCAP files. The tool should never be used to monitor another person's network traffic without authorization.