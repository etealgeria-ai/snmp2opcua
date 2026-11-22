"""SNMP polling: client, GE MDS Orbit remote RSSI, poller, config and gateway integration."""
import asyncio
import contextlib
import io
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_agent import ORBIT_TABLE, orbit_mib, start_agent  # noqa: E402

from snmp2opcua.config import load_config
from snmp2opcua.gateway import Gateway
from snmp2opcua.ge_orbit import Remote, format_report, ip_text, read_remotes, rssi_value, split_index
from snmp2opcua.ge_orbit import main as orbit_main
from snmp2opcua.poller import DevicePoller, convert
from snmp2opcua.snmp_client import SnmpClient, SnmpErrorStatus, SnmpTimeout
from snmp2opcua.snmp_driver import DriverConfigError, build_devices
from snmp2opcua.trap import VarBind

REMOTES = [("00:06:3D:12:34:56", "10.10.1.21", -72), ("00:06:3D:12:34:57", "10.10.1.22", -97),
           ("00:06:3D:AB:CD:EF", "10.10.1.23", -64)]


def master_device(port, **poll):
    p = {"community": "public", "port": port, "scan_rate_ms": 200, "timeout_ms": 300, "retries": 0,
         "ge_orbit_remotes": True}
    p.update(poll)
    return {"name": "Master_LN4", "ip": "127.0.0.1", "auto_create_tags": False, "polling": p,
            "tags": [{"name": "SysName", "address": ".1.3.6.1.2.1.1.5.0"},
                     {"name": "Uptime", "address": ".1.3.6.1.2.1.1.3.0", "data_type": "DWord"}]}


def by_rest(updates):
    return {u.path.split(".", 2)[2]: (u.value, u.good) for u in updates}


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.remotes = [(f"00:06:3D:00:00:{i:02X}", f"10.1.1.{i}", -60 - i) for i in range(1, 31)]
        self.agent, self.tr, self.port = await start_agent(orbit_mib(self.remotes), max_bulk=8)

    async def asyncTearDown(self):
        self.tr.close()

    async def test_get_walk_and_bulk_backoff(self):
        c = SnmpClient("127.0.0.1", "public", "2c", self.port, timeout=0.5)
        try:
            vbs = await c.get(["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.9.0"])
            self.assertEqual([(v.value, v.type) for v in vbs], [("LN4-MASTER", "Octet String"), (None, "NoSuchObject")])
            rows = await c.walk(f"{ORBIT_TABLE}.6", max_repetitions=20)
            self.assertEqual(len(rows), 30)                        # stops at the end of the column
            self.assertTrue(all(r.oid.startswith(f"{ORBIT_TABLE}.6.") for r in rows))
            reps = [r[2] for r in self.agent.requests if r[0] == 0xA5]
            self.assertEqual(reps[:3], [20, 10, 5])                  # tooBig -> fewer repetitions
        finally:
            c.close()

    async def test_v1_getnext_and_errors(self):
        c = SnmpClient("127.0.0.1", "public", "1", self.port, timeout=0.5)
        try:
            self.assertEqual(len(await c.walk(f"{ORBIT_TABLE}.2")), 30)
            with self.assertRaises(SnmpErrorStatus) as ctx:
                await c.get(["1.3.6.1.2.1.1.9.0"])
            self.assertEqual((ctx.exception.name, ctx.exception.oid), ("noSuchName", "1.3.6.1.2.1.1.9.0"))
            with self.assertRaises(ValueError):
                await c.getbulk(["1.3"])
        finally:
            c.close()

    async def test_timeouts_and_retries(self):
        wrong = SnmpClient("127.0.0.1", "secret", "2c", self.port, timeout=0.2, retries=1)
        with self.assertRaisesRegex(SnmpTimeout, "after 2 attempt"):
            await wrong.get(["1.3.6.1.2.1.1.5.0"])
        wrong.close()
        self.agent.drop = 1
        c = SnmpClient("127.0.0.1", "public", "2c", self.port, timeout=0.2, retries=1)
        self.assertEqual((await c.get(["1.3.6.1.2.1.1.5.0"]))[0].value, "LN4-MASTER")
        self.assertEqual(c.timeouts, 1)
        c.close()
        with self.assertRaises(ValueError):
            SnmpClient("127.0.0.1", version="3")


class OrbitTests(unittest.IsolatedAsyncioTestCase):
    def test_index_ip_and_rssi_parsing(self):
        self.assertEqual(split_index("3.0.6.61.18.52.86"), (3, "00:06:3D:12:34:56"))
        self.assertIsNone(split_index("3.0.6.61"))
        self.assertIsNone(split_index("3.0.6.61.18.52.999"))
        self.assertEqual(ip_text(VarBind("x", "x", "IpAddress", "10.0.0.5", b"\x0a\x00\x00\x05")), "10.0.0.5")
        self.assertEqual(ip_text(VarBind("x", "x", "Octet String", "0a:00:00:05", b"\x0a\x00\x00\x05")), "10.0.0.5")
        self.assertEqual(ip_text(VarBind("x", "x", "Octet String", "10.0.0.5", b"10.0.0.5")), "10.0.0.5")
        self.assertEqual(ip_text(None), "N/A")
        self.assertEqual(rssi_value(VarBind("x", "x", "Integer32", -72)), -72)
        self.assertEqual(rssi_value(VarBind("x", "x", "Octet String", "-81 dBm")), -81)
        self.assertIsNone(rssi_value(VarBind("x", "x", "Octet String", "n/a")))

    async def test_read_remotes_matches_original_script(self):
        agent, tr, port = await start_agent(orbit_mib(REMOTES, ip_as_octets=True))
        c = SnmpClient("127.0.0.1", "public", "2c", port, timeout=0.5)
        try:
            remotes = await read_remotes(c)
        finally:
            c.close()
            tr.close()
        self.assertEqual([(r.mac, r.ip, r.rssi, r.if_index) for r in remotes],
                         [(m, ip, rssi, 3) for m, ip, rssi in REMOTES])

        # the original script's output, line for line
        expected = [f"{'REMOTE_MAC':<18} {'REMOTE_IP':<16} {'RSSI (dBm)':<12} {'IF_INDEX'}", "-" * 58]
        for mac, ip, rssi in REMOTES:
            expected.append(f"{mac:<18} {ip:<16} {str(rssi):<12} {3}")
        self.assertEqual(format_report(remotes), "\n".join(expected))
        self.assertIn("N/A", format_report([Remote("00:00:00:00:00:01", 1, "N/A", None)]))

    def test_command_line(self):
        ready, info = threading.Event(), {}

        def serve():
            async def run():
                agent, tr, port = await start_agent(orbit_mib(REMOTES))
                info["port"] = port
                ready.set()
                await asyncio.sleep(3)
                tr.close()
            asyncio.run(run())
        threading.Thread(target=serve, daemon=True).start()
        ready.wait(3)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(orbit_main(["--ip", "127.0.0.1", "--port", str(info["port"])]), 0)
        self.assertIn("00:06:3D:12:34:56  10.10.1.21       -72          3", out.getvalue())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(orbit_main(["--ip", "127.0.0.1", "--port", str(info["port"]), "--community", "x",
                                         "--timeout", "0.2", "--retries", "0"]), 1)
        self.assertIn("Couldn't read 127.0.0.1", err.getvalue())


class ConvertTests(unittest.TestCase):
    def test_conversions(self):
        vb = lambda t, v, raw=b"": VarBind("1.3.6.1", "x", t, v, raw)  # noqa: E731
        self.assertEqual(convert(vb("Integer32", -72), "Long"), -72)
        self.assertEqual(convert(vb("Gauge32", 4294967295), "DWord"), 4294967295)
        self.assertEqual(convert(vb("Octet String", " 42 "), "Long"), 42)
        self.assertEqual(convert(vb("Integer32", 3), "Float"), 3.0)
        self.assertIs(convert(vb("Integer32", 0), "Boolean"), False)
        self.assertIs(convert(vb("Octet String", "up"), "Boolean"), True)
        self.assertEqual(convert(vb("IpAddress", "10.0.0.5", b"\x0a\x00\x00\x05"), "String"), "10.0.0.5")
        self.assertEqual(convert(vb("IpAddress", "10.0.0.5", b"\x0a\x00\x00\x05"), "DWord"), 0x0A000005)
        for bad, dt in [(vb("Integer32", -1), "DWord"), (vb("Counter64", 2**40), "Long"),
                        (vb("NoSuchObject", None), "Long"), (vb("Octet String", "abc"), "Long")]:
            with self.assertRaises(ValueError):
                convert(bad, dt)


class PollerTests(unittest.IsolatedAsyncioTestCase):
    async def test_poll_cycle(self):
        agent, tr, port = await start_agent(orbit_mib(REMOTES))
        dev = build_devices([{"name": "Radios", "devices": [master_device(port, rssi_warning_dbm=-95)]}])[0]
        p = DevicePoller(dev)
        try:
            v = by_rest(await p.poll_once())
            self.assertEqual(v["SysName"], ("LN4-MASTER", True))
            self.assertEqual(v["Uptime"], (123456, True))
            self.assertEqual(v["Remotes.00063D123456.RSSI"], (-72, True))
            self.assertEqual(v["Remotes.00063D123457.IP"], ("10.10.1.22", True))
            self.assertEqual(v["Remotes.00063DABCDEF.MAC"], ("00:06:3D:AB:CD:EF", True))
            self.assertEqual((v["Remotes.Count"], v["Remotes.OnlineCount"], v["_Polling.OK"]),
                             ((3, True), (3, True), (True, True)))
            self.assertEqual({r["mac"]: r["weak"] for r in p.radios()},
                             {"00:06:3D:12:34:56": False, "00:06:3D:12:34:57": True, "00:06:3D:AB:CD:EF": False})

            agent.mib = orbit_mib(REMOTES[:2])                 # one remote drops out
            v = by_rest(await p.poll_once())
            self.assertEqual(v["Remotes.00063DABCDEF.Online"], (False, True))
            self.assertEqual(v["Remotes.00063DABCDEF.RSSI"], (-64, True))   # last value kept
            self.assertEqual(v["Remotes.OnlineCount"], (2, True))

            tr.close()                                          # master stops answering
            v = by_rest(await p.poll_once())
            self.assertEqual(v["_Polling.OK"], (False, True))
            self.assertTrue(v["_Polling.Error"][0])
            self.assertEqual(v["SysName"], ("LN4-MASTER", False))            # Bad quality, last value
            self.assertEqual(v["Remotes.00063D123456.RSSI"], (-72, False))
            self.assertEqual(p.stats.failures, 1)
            self.assertFalse(p.radios()[0]["poll_ok"])
            self.assertEqual([t[0].split(".", 2)[2] for t in p.static_tags()],
                             ["_Polling.OK", "_Polling.Error", "_Polling.LastPoll", "_Polling.DurationMs",
                              "_Polling.Failures", "Remotes.Count", "Remotes.OnlineCount"])
        finally:
            p.close()

    async def test_v1_bad_oid_in_batch(self):
        agent, tr, port = await start_agent(orbit_mib(REMOTES))
        dev = build_devices([{"name": "C", "devices": [{
            "name": "D", "ip": "127.0.0.1", "snmp_version": 1, "auto_create_tags": False,
            "polling": {"port": port, "timeout_ms": 300},
            "tags": [{"name": "A", "address": ".1.3.6.1.2.1.1.5.0"},
                     {"name": "Missing", "address": ".1.3.6.1.2.1.1.9.0", "data_type": "Long"},
                     {"name": "B", "address": ".1.3.6.1.2.1.1.3.0", "data_type": "Long"}]}]}])[0]
        p = DevicePoller(dev)
        try:
            v = by_rest(await p.poll_once())
        finally:
            p.close()
            tr.close()
        self.assertEqual((v["A"], v["Missing"], v["B"], v["_Polling.OK"]),
                         (("LN4-MASTER", True), (0, False), (123456, True), (True, True)))


class PollConfigTests(unittest.TestCase):
    def err(self, **dev):
        base = {"name": "D", "ip": "10.0.0.1"}
        base.update(dev)
        with self.assertRaises(DriverConfigError) as ctx:
            build_devices([{"name": "C", "devices": [base]}])
        return str(ctx.exception)

    def test_validation(self):
        self.assertIn("the rate must be within the range of 10 milliseconds and 49 days.",
                      self.err(polling={"scan_rate_ms": 5}))
        self.assertIn("polling supports SNMP version 1 or 2c",
                      self.err(snmp_version=3, v3={"username": "u"}, polling={"community": "public"}))
        self.assertIn("has no polling settings", self.err(tags=[{"name": "T", "address": ".1.3.6.1.2.1.1.5.0"}]))
        self.assertIn("not supported for polled OIDs",
                      self.err(polling={}, tags=[{"name": "T", "address": ".1.3.6.1.2.1.1.5.0",
                                                  "data_type": "Date"}]))
        dev = build_devices([{"name": "C", "devices": [{"name": "D", "ip": "10.0.0.1", "snmp_version": 3,
                                                       "v3": {"username": "u"},
                                                       "polling": {"snmp_version": "2c",
                                                                   "ge_orbit_remotes": True}}]}])[0]
        self.assertEqual((dev.poll.version, dev.poll.port, dev.poll.scan_rate_ms, dev.poll.ge_orbit_remotes),
                         ("2c", 161, 10000, True))


class RecordingPublisher:
    def __init__(self):
        self.updates = []

    async def start(self):
        pass

    async def publish(self, trap):
        pass

    async def update_status(self, stats):
        pass

    async def stop(self):
        pass

    async def apply_updates(self, updates):
        self.updates.extend(updates)


class GatewayPollingTests(unittest.IsolatedAsyncioTestCase):
    async def test_gateway_polls_and_reports(self):
        agent, tr, aport = await start_agent(orbit_mib(REMOTES))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.yaml"
            udp = 0
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(("127.0.0.1", 0))
                udp = s.getsockname()[1]
            p.write_text(f"snmp: {{listen_host: 127.0.0.1, listen_port: {udp}}}\n"
                         f"channels:\n  - name: Radios\n    devices:\n      - name: Master_LN4\n"
                         f"        ip: 127.0.0.1\n        auto_create_tags: false\n"
                         f"        polling: {{port: {aport}, scan_rate_ms: 150, timeout_ms: 300, "
                         f"ge_orbit_remotes: true}}\n")
            cfg = load_config(p)
        pub = RecordingPublisher()
        gw = Gateway(cfg, publisher=pub)
        seen = []
        gw.monitor = lambda kind, payload: seen.append((kind, payload))
        task = asyncio.create_task(gw.run())
        await asyncio.sleep(0.5)
        gw.stop()
        await asyncio.wait_for(task, 3)
        tr.close()
        self.assertGreaterEqual(sum(1 for r in agent.requests if r[0] == 0xA5), 4)    # polled repeatedly
        paths = {u.path for u in pub.updates}
        self.assertIn("Radios.Master_LN4.Remotes.00063D123456.RSSI", paths)
        self.assertIn("Radios.Master_LN4._Polling.OK", paths)
        radios = [pl for k, pl in seen if k == "radios"]
        self.assertTrue(radios and radios[-1]["ok"] and len(radios[-1]["rows"]) == 3)
        self.assertEqual(gw.engine.values["Radios.Master_LN4.Remotes.00063D123457.RSSI"][0], -97)
        tags = [pl for k, pl in seen if k == "tags"]
        self.assertTrue(any(len(t) == 4 and t[3] == "Long" for batch in tags for t in batch))


if __name__ == "__main__":
    unittest.main()
