"""Server mode: the gateway hosts its own OPC UA server (asyncua).

Address space (namespace index is usually 2):

  Objects/SNMPTrapGateway                       ns=2;s=Gateway   (emits SnmpTrapEventType events)
    Status/  TrapsReceived, TrapsPublished, TrapsDropped, TrapsRejected, MalformedPackets, StartTime
    LastTrap/ SourceIP, Version, PduType, SecurityName, TrapOID, TrapName, Uptime, ReceivedAt, VarBindsJson, Json
    RecentTrapsJson                             JSON array of the last N traps (newest first)
    Devices/<source-ip>/ TrapCount, LastTrapOID, LastTrapName, LastTrapTime, LastTrapJson
"""
from __future__ import annotations

import json
import logging
from collections import deque
from datetime import datetime, timezone

from asyncua import Server, ua

from .receiver import Stats
from .severity import SeverityMap
from .trap import Trap

log = logging.getLogger("snmp2opcua.opcua_server")

S = ua.VariantType.String
U32 = ua.VariantType.UInt32
U64 = ua.VariantType.UInt64
DT = ua.VariantType.DateTime


class OpcUaServerPublisher:
    def __init__(self, cfg: dict, severity: SeverityMap):
        self.cfg = cfg
        self.severity = severity
        self.server: Server | None = None
        self.idx = 2
        self.recent: deque[dict] = deque(maxlen=int(cfg.get("recent_traps", 50)))
        self.devices: dict[str, dict] = {}
        self.max_devices = int(cfg.get("max_devices", 1000))
        self.evgen = None
        self.nodes: dict[str, object] = {}

    # ------------------------------------------------------------------ helpers
    def _nid(self, path: str) -> ua.NodeId:
        return ua.NodeId(path, self.idx)

    def _qn(self, name: str) -> ua.QualifiedName:
        return ua.QualifiedName(name, self.idx)

    async def _obj(self, parent, path: str, name: str):
        return await parent.add_object(self._nid(path), self._qn(name))

    async def _var(self, parent, path: str, name: str, value, vtype):
        return await parent.add_variable(self._nid(f"{path}.{name}"), self._qn(name), value, varianttype=vtype)

    @staticmethod
    async def _write(node, value, vtype):
        await node.write_value(value, vtype)

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        cfg = self.cfg
        server = Server()
        await server.init()
        server.set_endpoint(cfg["endpoint"])
        server.set_server_name(cfg.get("server_name", "SNMP Trap Gateway"))

        policies = []
        for name in cfg.get("security_policies") or ["NoSecurity"]:
            try:
                policies.append(getattr(ua.SecurityPolicyType, name))
            except AttributeError:
                raise ValueError(f"Unknown OPC UA security policy {name!r}") from None
        server.set_security_policy(policies)
        if cfg.get("certificate") and cfg.get("private_key"):
            await server.load_certificate(cfg["certificate"])
            await server.load_private_key(cfg["private_key"])
        elif any(p != ua.SecurityPolicyType.NoSecurity for p in policies):
            raise ValueError("Secure OPC UA policies need 'certificate' and 'private_key' in config")

        self.idx = await server.register_namespace(cfg.get("namespace", "urn:snmp2opcua:gateway"))
        objects = server.nodes.objects

        gw = await self._obj(objects, "Gateway", "SNMPTrapGateway")
        status = await self._obj(gw, "Gateway.Status", "Status")
        now = datetime.now(timezone.utc)
        n = self.nodes
        n["received"] = await self._var(status, "Gateway.Status", "TrapsReceived", 0, U64)
        n["published"] = await self._var(status, "Gateway.Status", "TrapsPublished", 0, U64)
        n["dropped"] = await self._var(status, "Gateway.Status", "TrapsDropped", 0, U64)
        n["rejected"] = await self._var(status, "Gateway.Status", "TrapsRejected", 0, U64)
        n["malformed"] = await self._var(status, "Gateway.Status", "MalformedPackets", 0, U64)
        n["started"] = await self._var(status, "Gateway.Status", "StartTime", now, DT)

        last = await self._obj(gw, "Gateway.LastTrap", "LastTrap")
        p = "Gateway.LastTrap"
        n["source_ip"] = await self._var(last, p, "SourceIP", "", S)
        n["version"] = await self._var(last, p, "Version", "", S)
        n["pdu"] = await self._var(last, p, "PduType", "", S)
        n["security_name"] = await self._var(last, p, "SecurityName", "", S)
        n["trap_oid"] = await self._var(last, p, "TrapOID", "", S)
        n["trap_name"] = await self._var(last, p, "TrapName", "", S)
        n["uptime"] = await self._var(last, p, "Uptime", 0, U32)
        n["received_at"] = await self._var(last, p, "ReceivedAt", now, DT)
        n["varbinds"] = await self._var(last, p, "VarBindsJson", "[]", S)
        n["json"] = await self._var(last, p, "Json", "{}", S)
        n["recent"] = await self._var(gw, "Gateway", "RecentTrapsJson", "[]", S)

        self.devices_folder = await gw.add_folder(self._nid("Gateway.Devices"), self._qn("Devices"))

        if cfg.get("events", True):
            etype = await server.create_custom_event_type(
                self.idx, "SnmpTrapEventType", ua.ObjectIds.BaseEventType,
                [("SourceIP", S), ("SnmpVersion", S), ("SecurityName", S), ("TrapOID", S), ("TrapName", S),
                 ("VarBindsJson", S)],
            )
            self.evgen = await server.get_event_generator(etype, gw)

        self.server = server
        await server.start()
        log.info("OPC UA server running at %s (namespace index %d)", cfg["endpoint"], self.idx)

    async def stop(self) -> None:
        if self.server is not None:
            await self.server.stop()
            self.server = None

    # ------------------------------------------------------------------ publishing
    async def _device(self, ip: str) -> dict | None:
        key = ip.replace(":", "_").replace("%", "_")
        dev = self.devices.get(key)
        if dev is not None:
            return dev
        if len(self.devices) >= self.max_devices:
            return None
        path = f"Gateway.Devices.{key}"
        obj = await self._obj(self.devices_folder, path, key)
        dev = {
            "count": 0,
            "count_node": await self._var(obj, path, "TrapCount", 0, U64),
            "oid": await self._var(obj, path, "LastTrapOID", "", S),
            "name": await self._var(obj, path, "LastTrapName", "", S),
            "time": await self._var(obj, path, "LastTrapTime", datetime.now(timezone.utc), DT),
            "json": await self._var(obj, path, "LastTrapJson", "{}", S),
        }
        self.devices[key] = dev
        log.info("New device node %s", path)
        return dev

    async def publish(self, trap: Trap) -> None:
        n = self.nodes
        trap_json = trap.to_json()
        varbinds_json = trap.varbinds_json()

        await self._write(n["source_ip"], trap.source_ip, S)
        await self._write(n["version"], trap.version, S)
        await self._write(n["pdu"], trap.pdu, S)
        await self._write(n["security_name"], trap.security_name or "", S)
        await self._write(n["trap_oid"], trap.trap_oid, S)
        await self._write(n["trap_name"], trap.trap_name, S)
        await self._write(n["uptime"], (trap.uptime or 0) & 0xFFFFFFFF, U32)
        await self._write(n["received_at"], trap.received_at, DT)
        await self._write(n["varbinds"], varbinds_json, S)
        await self._write(n["json"], trap_json, S)  # written last: one atomic snapshot of the trap

        self.recent.appendleft(trap.to_dict())
        await self._write(n["recent"], json.dumps(list(self.recent), default=str, ensure_ascii=False), S)

        dev = await self._device(trap.source_ip)
        if dev is not None:
            dev["count"] += 1
            await self._write(dev["count_node"], dev["count"], U64)
            await self._write(dev["oid"], trap.trap_oid, S)
            await self._write(dev["name"], trap.trap_name, S)
            await self._write(dev["time"], trap.received_at, DT)
            await self._write(dev["json"], trap_json, S)

        if self.evgen is not None:
            ev = self.evgen.event
            ev.Severity = self.severity.for_trap(trap)
            ev.SourceName = trap.source_ip
            ev.SourceIP = trap.source_ip
            ev.SnmpVersion = trap.version
            ev.SecurityName = trap.security_name or ""
            ev.TrapOID = trap.trap_oid
            ev.TrapName = trap.trap_name
            ev.VarBindsJson = varbinds_json
            await self.evgen.trigger(message=trap.summary())

    async def update_status(self, stats: Stats) -> None:
        if self.server is None:
            return
        n = self.nodes
        await self._write(n["received"], stats.received, U64)
        await self._write(n["published"], stats.published, U64)
        await self._write(n["dropped"], stats.dropped, U64)
        await self._write(n["rejected"], stats.rejected, U64)
        await self._write(n["malformed"], stats.malformed, U64)
