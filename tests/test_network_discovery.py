"""
ACDS Layered Network Discovery Test Suite
Validates Subnet Detection, Layer-2 ARP Discovery, ICMP Sweeps, TCP Probing,
Host Merging, Multi-Factor Fingerprinting, Gateway Recognition, and Asset Model Creation.
"""

import pytest
import networkx as nx

from acds.discovery.subnet import detect_active_subnet, _mask_to_cidr, SubnetInfo
from acds.discovery.arp import parse_arp_table, ip_in_subnet
from acds.discovery.icmp import ping_single
from acds.discovery.tcp_probe import quick_tcp_probe
from acds.discovery.fingerprint import (
    mac_vendor,
    is_mobile_device,
    classify_device,
    infer_os_type,
    calculate_criticality,
)
from acds.discovery.scanner import scan_network, assess_device_security
from acds.core.graph import build_dynamic_graph


def test_subnet_detection_and_cidr_calculation():
    """Verify subnet detection returns valid CIDR notation and bounded usable IPs."""
    sub = detect_active_subnet()
    assert isinstance(sub, SubnetInfo)
    assert sub.cidr_prefix > 0 and sub.cidr_prefix <= 32
    assert "/" in sub.cidr_notation
    assert not sub.cidr_notation.endswith("/100")
    assert len(sub.usable_ips) > 0
    assert len(sub.usable_ips) <= 254
    assert sub.default_gateway is not None

    # Test netmask conversion
    assert _mask_to_cidr("255.255.255.0") == 24
    assert _mask_to_cidr("255.255.0.0") == 16
    assert _mask_to_cidr("255.255.255.128") == 25


def test_arp_table_parsing():
    """Verify ARP cache parsing correctly extracts IP-to-MAC associations."""
    sample_arp_output = """
Interface: 192.168.1.7 --- 0x10
  Internet Address      Physical Address      Type
  192.168.1.1           c0-2e-5f-c4-8e-61     dynamic
  192.168.1.3           f6-d0-23-fb-8b-e4     dynamic
  192.168.1.4           e4-e3-3d-8f-33-10     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
    """
    arp_map = parse_arp_table(sample_arp_output, "192.168.1.")
    assert "192.168.1.1" in arp_map
    assert arp_map["192.168.1.1"] == "C0:2E:5F:C4:8E:61"
    assert arp_map["192.168.1.3"] == "F6:D0:23:FB:8B:E4"
    assert "192.168.1.255" not in arp_map  # Broadcast filtered
    assert "224.0.0.22" not in arp_map  # Multicast filtered


def test_mac_vendor_resolution():
    """Verify MAC OUI vendor resolution for routers, mobiles, TVs, and IoT."""
    assert "TP-Link" in (mac_vendor("C0:2E:5F:11:22:33") or "")
    assert "Apple" in (mac_vendor("F0:18:98:AA:BB:CC") or "")
    assert "Samsung" in (mac_vendor("5C:0A:5B:01:02:03") or "")
    assert "Xiaomi" in (mac_vendor("64:09:80:11:22:33") or "")
    assert "Espressif" in (mac_vendor("24:0A:C4:AA:BB:CC") or "")
    assert "Roku" in (mac_vendor("B8:3E:59:AA:BB:CC") or "")


def test_gateway_device_classification():
    """Verify default gateway is classified as Router / Gateway even if web ports exist."""
    res = classify_device(
        hostname="router.local",
        os_type="linux",
        os_confidence=0.70,
        is_mobile=False,
        services=["HTTP", "HTTPS", "DNS"],
        open_ports=[80, 443, 53],
        mac="C0:2E:5F:C4:8E:61",
        is_gateway=True,
        mac_vendor_name="TP-Link",
        ip="192.168.1.1",
    )
    assert res["device_type"] == "Router / Gateway"
    assert res["confidence"] >= 0.90
    assert any("Default Gateway" in ev for ev in res["evidence"])


def test_no_port_arp_host_retained_and_classified():
    """
    Verify a host discovered via Layer-2 ARP that drops ping and has 0 open ports
    is preserved as a valid network asset.
    """
    res = classify_device(
        hostname="realme-phone",
        os_type="unknown",
        os_confidence=0.0,
        is_mobile=True,
        services=[],
        open_ports=[],
        mac="7C:6B:9C:24:62:D9",
        is_gateway=False,
        mac_vendor_name="Realme",
        ip="192.168.1.10",
    )
    assert res["device_type"] == "Mobile Device"
    assert res["confidence"] >= 0.85

    # Check security assessment on 0-port device
    sec = assess_device_security([], "unknown", "Mobile Device", [], "Workstation", ip="192.168.1.10")
    assert sec["vulnerability_component"] == 0.0
    assert sec["service_component"] == 0.0
    assert sec["exposure_level"] == "LOW"


def test_dynamic_graph_creation_with_diverse_devices():
    """Verify build_dynamic_graph includes all devices and creates reachability edges."""
    sample_devices = [
        ("192.168.1.1", "gateway.lan", "linux", 0.7, ["Gateway"], False, "C0:2E:5F:C4:8E:61", "TP-Link", [53, 80], ["DNS", "HTTP"], {}, {}, "Router / Gateway", "gateway.lan (Router)", 0.95, ["Gateway"]),
        ("192.168.1.4", "samsung-phone", "linux", 0.6, ["Android"], True, "E4:E3:3D:8F:33:10", "Samsung", [], [], {}, {}, "Mobile Device", "samsung-phone (Mobile)", 0.90, ["Mobile"]),
        ("192.168.1.7", "DEV-PC", "windows", 0.9, ["Windows"], False, "D4:E9:8A:75:04:8B", "Intel", [135, 445, 3306], ["RPC", "SMB", "MySQL"], {"MySQL": "MySQL 5.7"}, {}, "Database Server", "DEV-PC (Database)", 0.95, ["MySQL"]),
        ("192.168.1.10", "realme-1", "unknown", 0.0, ["ARP"], True, "7C:6B:9C:24:62:D9", "Realme", [], [], {}, {}, "Mobile Device", "realme-1 (Mobile)", 0.85, ["ARP only"]),
    ]
    G = build_dynamic_graph(sample_devices)
    assert len(G.nodes) == 4
    # Ensure every device has a node
    ips_in_graph = {data["ip"] for _, data in G.nodes(data=True)}
    assert ips_in_graph == {"192.168.1.1", "192.168.1.4", "192.168.1.7", "192.168.1.10"}
    # Ensure graph has reachability edges connecting client devices
    assert len(G.edges) > 0
