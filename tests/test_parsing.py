from scapy.all import ARP, DNS, DNSQR, IP, Raw, TCP, UDP

import pytest

import sniffer
from sniffer import decode_packet, is_allowed_interface


def test_permission_error_recommends_pcap_mode(monkeypatch, capsys):
	def deny_live_capture(**kwargs):
		raise PermissionError("capture requires permission")

	monkeypatch.setattr(sniffer, "sniff", deny_live_capture)

	with pytest.raises(SystemExit):
		sniffer.main(["--interface", "lo0", "--count", "1"])

	error_output = capsys.readouterr().err
	assert "permission was denied" in error_output
	assert "--pcap" in error_output


def test_mac_loopback_interface_is_allowlisted():
	assert is_allowed_interface("lo0")


def test_linux_loopback_interface_is_allowlisted():
	assert is_allowed_interface("lo")


def test_non_loopback_interface_is_not_allowlisted():
	assert not is_allowed_interface("en0")


def test_missing_interface_is_not_allowed_for_live_capture():
	assert not is_allowed_interface(None)


def test_ipv4_addresses_are_decoded_and_masked():
	packet = IP(src="192.168.1.42", dst="10.0.0.8")

	details = decode_packet(packet)

	assert "IPv4: 192.168.1.xxx -> 10.0.0.xxx" in details


def test_tcp_ports_are_decoded():
	packet = IP() / TCP(sport=12345, dport=80)

	details = decode_packet(packet)

	assert "TCP: 12345 -> 80" in details


def test_udp_ports_are_decoded():
	packet = IP() / UDP(sport=53000, dport=53)

	details = decode_packet(packet)

	assert "UDP: 53000 -> 53" in details


def test_dns_query_name_is_decoded():
	packet = IP() / UDP(sport=53000, dport=53) / DNS(
		rd=1,
		qd=DNSQR(qname="example.test"),
	)

	details = decode_packet(packet)

	assert "DNS query: example.test" in details


def test_http_method_path_and_host_are_decoded():
	http_request = b"GET /lab HTTP/1.1\r\nHost: example.test\r\n\r\n"
	packet = IP() / TCP(sport=12345, dport=80) / Raw(load=http_request)

	details = decode_packet(packet)

	assert "HTTP request: GET /lab" in details
	assert "HTTP Host: example.test" in details


def test_http_sensitive_query_parameter_is_redacted():
	http_request = (
		b"GET /login?token=example-value HTTP/1.1\r\n"
		b"Host: example.test\r\n\r\n"
	)
	packet = IP() / TCP(dport=80) / Raw(load=http_request)

	details = decode_packet(packet)

	assert "HTTP request: GET /login?token=[REDACTED]" in details
	assert "example-value" not in " ".join(details)


def test_unknown_packet_uses_safe_message():
	details = decode_packet(ARP())

	assert details == ["Other packet type"]
