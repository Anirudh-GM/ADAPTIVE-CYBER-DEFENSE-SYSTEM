import unittest
from core import device_fingerprinting
from core.device_fingerprinting import (
    is_randomized_mac,
    resolve_mac_vendor_extended,
    _build_mdns_query,
    fingerprint_asset_realtime,
)


class TestDeviceFingerprinting(unittest.TestCase):

    def test_randomized_mac_detection(self):
        # 62:7C:48:72:FE:77 has 0x62 (bit 1 is set) -> True
        self.assertTrue(is_randomized_mac("62:7C:48:72:FE:77"))
        self.assertTrue(is_randomized_mac("DA:A1:19:00:11:22"))
        self.assertTrue(is_randomized_mac("02:00:00:00:00:00"))
        self.assertTrue(is_randomized_mac("AE:12:34:56:78:9A"))

        # Real hardware OUIs (bit 1 is 0) -> False
        self.assertFalse(is_randomized_mac("00:1A:2B:3C:4D:5E"))  # Intel
        self.assertFalse(is_randomized_mac("F0:18:98:11:22:33"))  # Apple
        self.assertFalse(is_randomized_mac("B8:27:EB:AA:BB:CC"))  # Raspberry Pi
        self.assertFalse(is_randomized_mac(""))
        self.assertFalse(is_randomized_mac(None))

    def test_extended_mac_vendor_resolution(self):
        # Known Apple OUI
        res = resolve_mac_vendor_extended("F0:18:98:AA:BB:CC")
        self.assertEqual(res["vendor"], "Apple")
        self.assertFalse(res["is_randomized"])

        # Known Samsung OUI
        res = resolve_mac_vendor_extended("00:07:AB:12:34:56")
        self.assertEqual(res["vendor"], "Samsung")
        self.assertFalse(res["is_randomized"])

        # Randomized / Private MAC
        res = resolve_mac_vendor_extended("62:7C:48:72:FE:77")
        self.assertTrue(res["is_randomized"])
        self.assertEqual(res["vendor"], "Private / Randomized MAC")

    def test_mdns_query_packet_builder(self):
        pkt = _build_mdns_query("_apple-mobdev2._tcp.local")
        self.assertIsInstance(pkt, bytes)
        self.assertIn(b"_apple-mobdev2", pkt)
        self.assertIn(b"_tcp", pkt)
        self.assertIn(b"local", pkt)

    def test_fingerprint_asset_with_randomized_mac(self):
        # 10.192.177.54 with MAC 62:7C:48:72:FE:77 and port 53
        res = fingerprint_asset_realtime(
            "10.192.177.54",
            mac="62:7C:48:72:FE:77",
            current_hostname="Unknown",
            open_ports=[53],
            services=["DNS"]
        )
        self.assertTrue(res["is_randomized_mac"])
        self.assertTrue(res["is_mobile"])
        self.assertIn("Mobile", res["inferred_device"])
        self.assertTrue(any("Randomized/Private MAC" in ev for ev in res["evidence"]))


if __name__ == "__main__":
    unittest.main()
