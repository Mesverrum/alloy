"""IF-MIB hot/cold split: walk lookups, ifHighSpeed gauge, ifAlias typing."""
from __future__ import annotations

import unittest

from convert import (
    IF_HIGHSPEED_OID,
    IF_HIGHSPEED_METRIC,
    IF_PHYSADDRESS_OID,
    apply_if_admin_up_filter,
    inject_ip_addr_into_cold_lists,
    ip_addr_module,
    lookup_type,
    partition_module_chain,
    split_if_mib_family,
)

IF_NAME_OID = "1.3.6.1.2.1.31.1.1.1.1"
IF_IN_OCTETS_OID = "1.3.6.1.2.1.31.1.1.1.6"
IF_ALIAS_OID = "1.3.6.1.2.1.31.1.1.1.18"


def _octets_metric() -> dict:
    return {
        "name": "snmp_ifHCInOctets",
        "oid": IF_IN_OCTETS_OID,
        "type": "counter",
        "indexes": [{"labelname": "ifIndex", "type": "gauge"}],
        "lookups": [
            {
                "labels": ["ifIndex"],
                "labelname": "if_interface_name",
                "oid": IF_NAME_OID,
                "type": "DisplayString",
            },
            {
                "labels": ["ifIndex"],
                "labelname": "if_Speed",
                "oid": IF_HIGHSPEED_OID,
                "type": "DisplayString",
            },
            {
                "labels": ["ifIndex"],
                "labelname": "if_Alias",
                "oid": IF_ALIAS_OID,
                "type": "gauge",
            },
        ],
    }


class LookupTypeAlias(unittest.TestCase):
    def test_if_alias_is_display_string(self):
        self.assertEqual(lookup_type("ifAlias", "if_Alias"), "DisplayString")
        self.assertEqual(lookup_type("ifAlias", "ifAlias"), "DisplayString")

    def test_peer_as_still_gauge(self):
        self.assertEqual(lookup_type("bgpPeerRemoteAs", "peer_as"), "gauge")


class AdminUpWalkIncludesLookups(unittest.TestCase):
    def test_lookup_oids_in_walk_and_filter_targets(self):
        module = apply_if_admin_up_filter({"metrics": [_octets_metric()]}, force=True)
        self.assertIn(IF_IN_OCTETS_OID, module["walk"])
        self.assertIn(IF_NAME_OID, module["walk"])
        self.assertIn(IF_NAME_OID, module["filters"][0]["targets"])
        self.assertIn(IF_HIGHSPEED_OID, module["walk"])


class SplitIfMibFamily(unittest.TestCase):
    def test_promotes_if_highspeed_hot_gauge(self):
        module = {
            "metrics": [
                _octets_metric(),
                {
                    "name": "snmp_ifAdminStatus",
                    "oid": "1.3.6.1.2.1.2.2.1.7",
                    "type": "gauge",
                    "indexes": [{"labelname": "ifIndex", "type": "gauge"}],
                    "lookups": _octets_metric()["lookups"],
                },
                {
                    "name": "snmp_ifHCInUcastPkts",
                    "oid": "1.3.6.1.2.1.31.1.1.1.7",
                    "type": "counter",
                    "indexes": [{"labelname": "ifIndex", "type": "gauge"}],
                    "lookups": _octets_metric()["lookups"],
                },
            ]
        }
        parts = split_if_mib_family("if_mib", module)
        hot = parts["if_mib"]
        cold = parts["if_mib_meta"]
        hot_names = [m["name"] for m in hot["metrics"]]
        self.assertIn("snmp_ifHCInOctets", hot_names)
        self.assertIn(IF_HIGHSPEED_METRIC, hot_names)
        hs = next(m for m in hot["metrics"] if m["name"] == IF_HIGHSPEED_METRIC)
        self.assertEqual(hs["type"], "gauge")
        self.assertEqual(hs["oid"], IF_HIGHSPEED_OID)
        self.assertIn(IF_HIGHSPEED_OID, hot["walk"])
        self.assertIn(IF_NAME_OID, hot["walk"])
        self.assertIn(IF_NAME_OID, hot["filters"][0]["targets"])

        cold_lookups = []
        for m in cold["metrics"]:
            cold_lookups.extend(m.get("lookups") or [])
        self.assertFalse(any(lk.get("labelname") == "if_Speed" for lk in cold_lookups))
        self.assertIn(IF_ALIAS_OID, cold["walk"])
        self.assertNotIn(IF_HIGHSPEED_OID, cold["walk"])
        self.assertIn("snmp_ifAdminStatus", [m["name"] for m in cold["metrics"]])
        self.assertIn(IF_PHYSADDRESS_OID, cold["walk"])
        self.assertNotIn(IF_PHYSADDRESS_OID, hot["walk"])
        mac = [
            lk
            for m in cold["metrics"]
            for lk in (m.get("lookups") or [])
            if lk.get("labelname") == "if_MAC"
        ]
        self.assertTrue(mac)
        self.assertEqual(mac[0]["type"], "PhysAddress")
        self.assertEqual(mac[0]["oid"], IF_PHYSADDRESS_OID)


class IpAddrModule(unittest.TestCase):
    def test_address_tables_carry_ifindex_labels(self):
        mod = ip_addr_module()
        names = [m["name"] for m in mod["metrics"]]
        self.assertEqual(names, ["snmp_ipAdEntIfIndex", "snmp_ipAddressIfIndex"])
        self.assertNotIn("filters", mod)
        self.assertNotIn("1.3.6.1.2.1.4.20", mod["walk"])
        self.assertNotIn("1.3.6.1.2.1.4.34", mod["walk"])
        v4 = mod["metrics"][0]
        self.assertEqual(v4["indexes"][0]["labelname"], "ipAdEntAddr")
        self.assertEqual(v4["indexes"][0]["type"], "InetAddressIPv4")
        v4_labels = {lk["labelname"]: lk for lk in v4["lookups"]}
        self.assertEqual(v4_labels["ifIndex"]["oid"], "1.3.6.1.2.1.4.20.1.2")
        self.assertEqual(v4_labels["ipAdEntNetMask"]["type"], "InetAddressIPv4")
        self.assertEqual(v4_labels["if_interface_name"]["oid"], IF_NAME_OID)
        v6 = mod["metrics"][1]
        self.assertEqual(
            [x["labelname"] for x in v6["indexes"]],
            ["ipAddressAddrType", "ipAddressAddr"],
        )
        v6_labels = {lk["labelname"]: lk for lk in v6["lookups"]}
        self.assertEqual(v6_labels["ifIndex"]["oid"], "1.3.6.1.2.1.4.34.1.3")
        self.assertEqual(v6_labels["ipAddressType"]["type"], "EnumAsInfo")
        self.assertEqual(v6_labels["ipAddressOrigin"]["enum_values"][4], "dhcp")

    def test_partition_adds_ip_addr_with_if_mib(self):
        tiers = partition_module_chain(["device_base", "if_mib"])
        self.assertEqual(tiers["hot"], ["device_base", "if_mib"])
        self.assertEqual(tiers["cold"], ["if_mib_meta", "ip_addr"])

    def test_fingerprinter_inject_is_idempotent(self):
        src = (
            "    default_modules_cold:\n"
            "    - if_mib_meta\n"
            "      modules_cold: &id002\n"
            "      - if_mib_meta\n"
            "      - ospf_mib\n"
            "      modules_cold: *id002\n"
        )
        once = inject_ip_addr_into_cold_lists(src)
        self.assertIn("      - ip_addr\n", once)
        self.assertEqual(once.count("- ip_addr"), 2)
        self.assertEqual(inject_ip_addr_into_cold_lists(once), once)


if __name__ == "__main__":
    unittest.main()
