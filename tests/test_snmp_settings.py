"""The window's SNMP page model: reading, checking and saving the snmp: section."""
import copy
import os
import unittest
from pathlib import Path
from unittest import mock

import yaml

from snmp2opcua import snmp_settings as s
from snmp2opcua.gui_controller import GatewayController
from snmp2opcua.yaml_edit import set_list

SAMPLE = (Path(__file__).resolve().parent.parent / "config.yaml").read_text()
ENV = {"SNMP_AUTH_KEY": "authpass123", "SNMP_PRIV_KEY": "privpass123"}


def user(**kw):
    values = {"name": "ups", "auth_protocol": "SHA", "auth_key": "upsauth123", "priv_protocol": "AES",
              "priv_key": "upspriv123", "engine_ids": ""}
    values.update(kw)
    return values


class LoadTests(unittest.TestCase):
    def test_defaults_when_section_missing(self):
        st = s.load_settings("traps: {queue_size: 10}\n")
        self.assertEqual([(x.address, x.port) for x in st.listeners], [("0.0.0.0", 162)])
        self.assertEqual((st.communities, st.accept_all_hosts, st.allowed_sources), (["public"], True, []))
        self.assertEqual((st.versions, st.respond_to_informs, st.engine_id, st.replay_protection, st.users),
                         (["v1", "v2c", "v3"], True, "", True, []))

    def test_sample_config(self):
        st = s.load_settings(SAMPLE)
        self.assertEqual([(x.address, x.port) for x in st.listeners], [("0.0.0.0", 162)])
        self.assertFalse(st.uses_interfaces)
        self.assertEqual([(u.name, u.level, u.auth_key) for u in st.users], [("opcgw", "authPriv", "${SNMP_AUTH_KEY}")])
        self.assertEqual(s.save_settings(SAMPLE, copy.deepcopy(st), st), SAMPLE)     # nothing changed

    def test_accept_all_follows_host_list_when_not_set(self):
        self.assertFalse(s.load_settings("snmp: {allowed_sources: [10.0.0.1]}\n").accept_all_hosts)
        self.assertTrue(s.load_settings("snmp: {allowed_sources: []}\n").accept_all_hosts)

    def test_unreadable(self):
        with self.assertRaises(ValueError):
            s.load_settings("snmp: [unclosed\n")
        with self.assertRaises(ValueError):
            s.load_settings("snmp: {network_interfaces: [{address: 1.2.3.4, port: x}]}\n")


class CheckTests(unittest.TestCase):
    def test_listener(self):
        existing = [s.Listener("0.0.0.0", 162)]
        self.assertEqual(s.check_listener("", "1162", existing)[0], s.Listener("0.0.0.0", 1162))
        self.assertEqual(s.check_listener("10.0.0.5", "162", existing)[0], s.Listener("10.0.0.5", 162))
        self.assertIn("already been added", s.check_listener("0.0.0.0", "162", existing)[1])
        self.assertIn("1 to 65535", s.check_listener("0.0.0.0", "70000", existing)[1])
        self.assertIn("whole number", s.check_listener("0.0.0.0", "x", existing)[1])
        self.assertIn("Invalid IP address", s.check_listener("10.0.0.300", "162", existing)[1])

    def test_community_and_host(self):
        self.assertEqual(s.check_community("scada", ["public"]), ("scada", ""))
        self.assertIn("already been added", s.check_community("public", ["public"])[1])
        self.assertIn("space", s.check_community(" public", [])[1])
        self.assertIsNone(s.check_community("", [])[0])
        self.assertEqual(s.check_host("10.10.3.4/16", [])[0], "10.10.0.0/16")
        self.assertEqual(s.check_host(" 192.168.1.20 ", [])[0], "192.168.1.20")
        self.assertIn("already been added", s.check_host("192.168.1.20", ["192.168.1.20"])[1])
        self.assertIn("Invalid IP address", s.check_host("printer", [])[1])

    def test_user(self):
        u, probs = s.check_user(user(engine_ids="80:00:00:09:03:00:aa:bb:cc:dd:ee:ff, 0x800000090300112233445566"),
                                [], None)
        self.assertEqual(probs, [])
        self.assertEqual((u.level, u.engine_ids), ("authPriv", ["800000090300aabbccddeeff", "800000090300112233445566"]))
        cases = [(user(auth_protocol="NONE"), "Privacy needs authentication"),
                 (user(auth_key="short"), "at least 8 characters"),
                 (user(priv_key=""), "Privacy key is required"),
                 (user(name=""), "needs a name"),
                 (user(engine_ids="abc"), "isn't hexadecimal"),
                 (user(engine_ids="0011"), "5 to 32 octets")]
        for values, expected in cases:
            got, probs = s.check_user(values, [], None)
            self.assertIsNone(got)
            self.assertIn(expected, " ".join(probs))
        existing = [s.V3User("ups")]
        self.assertIn("already been added", " ".join(s.check_user(user(), existing, None)[1]))
        self.assertEqual(s.check_user(user(), existing, existing[0])[1], [])              # editing itself
        none, probs = s.check_user(user(auth_protocol="NONE", priv_protocol="NONE"), [], None)
        self.assertEqual((none.level, none.auth_key, none.priv_key), ("noAuthNoPriv", "", ""))

    def test_user_keys_from_environment(self):
        values = user(auth_key="${SNMP_AUTH_KEY}", priv_key="${SNMP_PRIV_KEY}")
        with mock.patch.dict(os.environ, {}, clear=True):
            u, probs = s.check_user(values, [], None)
            self.assertEqual(probs, [])
            self.assertEqual(u.missing_variables(), ["SNMP_AUTH_KEY", "SNMP_PRIV_KEY"])
        with mock.patch.dict(os.environ, {"SNMP_AUTH_KEY": "short", "SNMP_PRIV_KEY": "privpass123"}):
            self.assertIn("at least 8 characters", " ".join(s.check_user(values, [], None)[1]))

    def test_settings(self):
        st = s.load_settings(SAMPLE)
        st.listeners, st.versions, st.accept_all_hosts, st.allowed_sources = [], [], False, []
        st.engine_id = "zz"
        problems, _ = s.check_settings(st)
        self.assertEqual([f for f, _ in problems], ["listeners", "versions", "hosts", "engine_id"])
        st = s.load_settings(SAMPLE)
        st.users, st.communities = [], []
        _, warnings = s.check_settings(st)
        self.assertIn("no users", " ".join(warnings))
        self.assertIn("any community", " ".join(warnings))
        with mock.patch.dict(os.environ, {}, clear=True):
            _, warnings = s.check_settings(s.load_settings(SAMPLE))
            self.assertIn("SNMP_AUTH_KEY, SNMP_PRIV_KEY isn't set", " ".join(warnings))


@mock.patch.dict(os.environ, ENV)
class SaveTests(unittest.TestCase):
    def test_edits_are_minimal_and_valid(self):
        orig = s.load_settings(SAMPLE)
        st = copy.deepcopy(orig)
        st.listeners.append(s.Listener("0.0.0.0", 1162))
        st.uses_interfaces = True
        st.communities.append("scada")
        st.accept_all_hosts, st.allowed_sources = False, ["10.10.0.0/16"]
        st.versions, st.replay_protection, st.engine_id = ["v2c", "v3"], False, "800000090300aabbccddeeff"
        new = s.save_settings(SAMPLE, st, orig)
        cfg = GatewayController.validate_text(new)["snmp"]
        self.assertEqual(cfg["network_interfaces"], [{"address": "0.0.0.0", "port": 162},
                                                     {"address": "0.0.0.0", "port": 1162}])
        self.assertEqual((cfg["communities"], cfg["accept_all_hosts"], cfg["allowed_sources"], cfg["versions"]),
                         (["public", "scada"], False, ["10.10.0.0/16"], ["v2c", "v3"]))
        self.assertEqual((cfg["v3"]["replay_protection"], cfg["v3"]["engine_id"]), (False, "800000090300aabbccddeeff"))
        self.assertIn("  communities: [public, scada]         # accepted v1/v2c communities", new)   # one line, comment kept
        self.assertIn("  versions: [v2c, v3]       # e.g. [v3]", new)
        changed = [a for a, b in zip(SAMPLE.splitlines(), new.splitlines()) if a != b]
        self.assertLessEqual(len(changed), 8)
        back = s.load_settings(new)
        self.assertEqual([(x.address, x.port) for x in back.listeners], [("0.0.0.0", 162), ("0.0.0.0", 1162)])
        self.assertEqual(s.save_settings(new, copy.deepcopy(back), back), new)

    def test_single_listener_keeps_listen_host_and_port(self):
        orig = s.load_settings(SAMPLE)
        st = copy.deepcopy(orig)
        st.listeners = [s.Listener("10.0.0.5", 1162)]
        new = s.save_settings(SAMPLE, st, orig)
        cfg = GatewayController.validate_text(new)["snmp"]
        self.assertEqual((cfg["listen_host"], cfg["listen_port"], cfg["network_interfaces"]), ("10.0.0.5", 1162, []))
        self.assertIn("  listen_port: 1162              # needs root/admin", new)

    def test_users_add_edit_remove(self):
        orig = s.load_settings(SAMPLE)
        st = copy.deepcopy(orig)
        st.users.append(s.check_user(user(engine_ids="800000090300aabbccddeeff"), st.users, None)[0])
        st.users.append(s.check_user(user(name="noauth", auth_protocol="NONE", priv_protocol="NONE"), st.users, None)[0])
        text = s.save_settings(SAMPLE, st, orig)
        cfg = GatewayController.validate_text(text)
        self.assertEqual([u["name"] for u in cfg["snmp"]["v3"]["users"]], ["opcgw", "ups", "noauth"])
        self.assertIn("# auth_protocol: MD5, SHA, SHA224", text)                  # comments survive

        orig = s.load_settings(text)
        st = copy.deepcopy(orig)
        st.users = [u for u in st.users if u.name != "opcgw"]                     # remove the first
        ups = next(u for u in st.users if u.name == "ups")
        edited = s.check_user(user(auth_protocol="SHA256", priv_protocol="NONE", engine_ids=""), st.users, ups)[0]
        st.users[st.users.index(ups)] = edited
        text = s.save_settings(text, st, orig)
        users = yaml.safe_load(text)["snmp"]["v3"]["users"]
        self.assertEqual(users, [{"name": "ups", "auth_protocol": "SHA256", "auth_key": "upsauth123"},
                                 {"name": "noauth"}])
        GatewayController.validate_text(text)

        orig = s.load_settings(text)
        st = copy.deepcopy(orig)
        st.users = []
        text = s.save_settings(text, st, orig)
        self.assertEqual(yaml.safe_load(text)["snmp"]["v3"]["users"], [])
        GatewayController.validate_text(text)


class SetListTests(unittest.TestCase):
    def test_flow_block_missing_and_null(self):
        self.assertEqual(set_list("a:\n  b: [x]   # c\n", ["a", "b"], ["x", "y"]), "a:\n  b: [x, y]   # c\n")
        self.assertEqual(set_list("a:\n  b:\n    - x\n  c: 1\n", ["a", "b"], ["x", "y"]),
                         "a:\n  b:\n    - x\n    - y\n  c: 1\n")
        self.assertEqual(yaml.safe_load(set_list("a:\n  c: 1\n", ["a", "b"], ["x"])), {"a": {"c": 1, "b": ["x"]}})
        self.assertIn("b: [x]", set_list("a:\n  c: 1\n", ["a", "b"], ["x"]))
        self.assertEqual(set_list("a:\n  b: null\n", ["a", "b"], ["x"]), "a:\n  b: [x]\n")


if __name__ == "__main__":
    unittest.main()
