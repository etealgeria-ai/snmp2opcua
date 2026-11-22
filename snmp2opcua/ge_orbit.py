"""GE MDS Orbit: read the remote radios' RSSI and IP from the master station.

The master station (e.g. an Orbit LN4 module in an MCR) lists its connected remotes in a
table under 1.3.6.1.4.1.4130.10.2.5.1.2.2.1. The row index is <ifIndex>.<6 MAC octets>:

    column .2  remote IP address
    column .6  RSSI in dBm

This is the same table, columns and index layout as the pysnmp script this module was
built from; only the transport is the gateway's own SNMP code. Run it on its own to print
the same report:

    python -m snmp2opcua.ge_orbit --ip 192.168.1.10 --community public
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import sys
from dataclasses import dataclass

from .snmp_client import SnmpClient, SnmpErrorStatus, SnmpTimeout
from .trap import VarBind

BASE_TABLE = "1.3.6.1.4.1.4130.10.2.5.1.2.2.1"
IP_COL = f"{BASE_TABLE}.2"
RSSI_COL = f"{BASE_TABLE}.6"


@dataclass
class Remote:
    mac: str              # "00:06:3D:12:34:56"
    if_index: int
    ip: str
    rssi: int | None      # dBm

    @property
    def key(self) -> str:
        """MAC without separators: a valid tag/folder name (e.g. 00063D123456)."""
        return self.mac.replace(":", "")


def split_index(suffix: str) -> tuple[int, str] | None:
    """'3.0.6.61.18.52.86' -> (3, '00:06:3D:12:34:56'); None if it isn't ifIndex + 6 octets."""
    parts = suffix.split(".")
    if len(parts) < 7:
        return None
    try:
        octets = [int(p) for p in parts[1:7]]
        if any(not 0 <= o <= 255 for o in octets):
            return None
        return int(parts[0]), ":".join(f"{o:02X}" for o in octets)
    except ValueError:
        return None


def ip_text(vb: VarBind | None) -> str:
    if vb is None or vb.value is None:
        return "N/A"
    if vb.type == "Octet String" and len(vb.raw) == 4:       # IP sent as 4 raw octets
        return str(ipaddress.IPv4Address(vb.raw))
    return str(vb.value)


def rssi_value(vb: VarBind) -> int | None:
    if isinstance(vb.value, (int, float)) and not isinstance(vb.value, bool):
        return int(vb.value)
    try:
        return int(str(vb.value).replace("dBm", "").strip())
    except (TypeError, ValueError):
        return None


def by_suffix(rows: list[VarBind], column: str) -> dict[str, VarBind]:
    prefix = column + "."
    return {vb.oid[len(prefix):]: vb for vb in rows if vb.oid.startswith(prefix)}


async def read_remotes(client: SnmpClient, max_repetitions: int = 20) -> list[Remote]:
    """Walk RSSI and IP columns and join them by row index, like the original script."""
    rssi_rows = by_suffix(await client.walk(RSSI_COL, max_repetitions), RSSI_COL)
    ip_rows = by_suffix(await client.walk(IP_COL, max_repetitions), IP_COL)
    remotes = []
    for suffix, vb in rssi_rows.items():
        idx = split_index(suffix)
        if idx is None:
            continue
        if_index, mac = idx
        remotes.append(Remote(mac, if_index, ip_text(ip_rows.get(suffix)), rssi_value(vb)))
    return remotes


def format_report(remotes: list[Remote]) -> str:
    lines = [f"{'REMOTE_MAC':<18} {'REMOTE_IP':<16} {'RSSI (dBm)':<12} {'IF_INDEX'}", "-" * 58]
    for r in remotes:
        rssi = "N/A" if r.rssi is None else str(r.rssi)
        lines.append(f"{r.mac:<18} {r.ip:<16} {rssi:<12} {r.if_index}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="snmp2opcua.ge_orbit",
                                 description="Print RSSI and IP of the remotes connected to a GE MDS Orbit master")
    ap.add_argument("--ip", default="192.168.1.10", help="master station address (default 192.168.1.10)")
    ap.add_argument("--community", default="public")
    ap.add_argument("--version", choices=["1", "2c"], default="2c")
    ap.add_argument("--port", type=int, default=161)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--retries", type=int, default=1)
    args = ap.parse_args(argv)

    async def run() -> list[Remote]:
        client = SnmpClient(args.ip, args.community, args.version, args.port, args.timeout, args.retries)
        try:
            return await read_remotes(client)
        finally:
            client.close()
    try:
        remotes = asyncio.run(run())
    except (SnmpTimeout, SnmpErrorStatus, OSError) as exc:
        print(f"Couldn't read {args.ip}: {exc}", file=sys.stderr)
        return 1
    print(format_report(remotes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
