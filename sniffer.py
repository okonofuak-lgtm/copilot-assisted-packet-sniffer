"""A small packet sniffer for an authorized cybersecurity lab."""

import argparse
import errno
import re

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, rdpcap, sniff


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
SENSITIVE_PARAMETER_NAMES = r"password|token|api_key|session"
ALLOWED_INTERFACES = {"lo0", "lo"}


def is_allowed_interface(interface: str | None) -> bool:
	"""Return whether an interface is explicitly approved for live capture."""
	return interface in ALLOWED_INTERFACES


def mask_ip(address: str) -> str:
	"""Mask the last octet of an IPv4 address."""
	parts = address.split(".")
	if len(parts) == 4 and all(part.isdigit() and int(part) <= 255 for part in parts):
		return ".".join(parts[:3] + ["xxx"])
	return address


def redact_sensitive_data(text: str) -> str:
	"""Redact common sensitive values before they are displayed."""
	text = re.sub(
		r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
		"[REDACTED_EMAIL]",
		text,
	)
	text = re.sub(
		r"(?im)(\bAuthorization\s*:\s*)[^\r\n]*",
		r"\1[REDACTED]",
		text,
	)
	text = re.sub(
		r"(?im)(\bCookie\s*:\s*)[^\r\n]*",
		r"\1[REDACTED]",
		text,
	)
	return re.sub(
		fr"(?i)([?&](?:{SENSITIVE_PARAMETER_NAMES})=)[^&#\s]*",
		r"\1[REDACTED]",
		text,
	)


def positive_count(value: str) -> int:
	"""Convert a command-line count to a positive integer."""
	count = int(value)
	if count < 1:
		raise argparse.ArgumentTypeError("count must be at least 1")
	return count


def build_parser() -> argparse.ArgumentParser:
	"""Build the command-line argument parser."""
	parser = argparse.ArgumentParser(
		description="Capture or read packets for an authorized cybersecurity lab."
	)
	parser.add_argument(
		"-c",
		"--count",
		type=positive_count,
		default=25,
		help="number of packets to read (default: 25)",
	)
	parser.add_argument(
		"-i",
		"--interface",
		help="network interface to sniff on (live capture only)",
	)
	parser.add_argument(
		"-f",
		"--filter",
		dest="bpf_filter",
		help="BPF filter for live capture, such as 'tcp port 80'",
	)
	parser.add_argument(
		"-r",
		"--pcap",
		help="read packets from a .pcap file instead of live capture",
	)
	return parser


def decode_packet(packet) -> list[str]:
	"""Return safe, beginner-friendly details about one packet."""
	details = []

	if packet.haslayer(IP):
		ip_packet = packet[IP]
		details.append(
			f"IPv4: {mask_ip(ip_packet.src)} -> {mask_ip(ip_packet.dst)}"
		)

	if packet.haslayer(TCP):
		tcp_packet = packet[TCP]
		details.append(f"TCP: {tcp_packet.sport} -> {tcp_packet.dport}")

		# Only inspect clear-text HTTP requests sent to the usual HTTP port.
		if tcp_packet.dport == 80 and packet.haslayer(Raw):
			payload = packet[Raw].load.decode("latin-1", errors="replace")
			request_lines = payload.split("\r\n")
			request_parts = request_lines[0].split(" ", 2)
			if (
				len(request_parts) == 3
				and request_parts[0] in HTTP_METHODS
				and request_parts[2].startswith("HTTP/")
			):
				safe_request = redact_sensitive_data(
					f"{request_parts[0]} {request_parts[1]}"
				)
				details.append(
					f"HTTP request: {safe_request}"
				)
				for header in request_lines[1:]:
					if header.lower().startswith("host:"):
						safe_host = redact_sensitive_data(header[5:].strip())
						details.append(f"HTTP Host: {safe_host}")
						break

	if packet.haslayer(UDP):
		udp_packet = packet[UDP]
		details.append(f"UDP: {udp_packet.sport} -> {udp_packet.dport}")

	if packet.haslayer(DNS) and packet.haslayer(DNSQR):
		dns_packet = packet[DNS]
		if dns_packet.qr == 0:
			query_name = packet[DNSQR].qname
			if isinstance(query_name, bytes):
				query_name = query_name.decode("utf-8", errors="replace")
			details.append(f"DNS query: {query_name.rstrip('.')}")

	return details or ["Other packet type"]


def main(argv=None) -> None:
	parser = build_parser()
	args = parser.parse_args(argv)

	print("Authorized lab traffic only. Use this tool only with permission.")

	if args.pcap:
		packets = rdpcap(args.pcap, count=args.count)
	else:
		if not is_allowed_interface(args.interface):
			allowed = ", ".join(sorted(ALLOWED_INTERFACES))
			parser.error(
				f"live capture requires an allowlisted interface ({allowed}); "
				"use --pcap for a file"
			)
		try:
			packets = sniff(
				count=args.count,
				iface=args.interface,
				filter=args.bpf_filter,
			)
		except PermissionError:
			parser.error(
				"live capture permission was denied; use --pcap with an "
				"authorized PCAP file for safe offline analysis"
			)
		except OSError as error:
			if error.errno not in {errno.EACCES, errno.EPERM}:
				raise
			parser.error(
				"live capture permission was denied; use --pcap with an "
				"authorized PCAP file for safe offline analysis"
			)

	for packet in packets:
		for detail in decode_packet(packet):
			print(detail)


if __name__ == "__main__":
	main()
