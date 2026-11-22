"""Wire the SNMP listener to an OPC UA publisher."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from typing import Any, Callable

from .config import listen_endpoints
from .oids import OidResolver
from .receiver import ListenerError, Stats, TrapProtocol, start_listener
from .severity import SeverityMap
from .snmp_driver import TrapTagEngine
from .snmpv3 import SnmpV3Engine, load_engine_state

log = logging.getLogger("snmp2opcua")


def make_publisher(cfg: dict):
    severity = SeverityMap(cfg["traps"]["severity"])
    try:
        if cfg["opcua"]["mode"] == "client":
            from .opcua_client import OpcUaClientPublisher
            return OpcUaClientPublisher(cfg["opcua"]["client"], severity)
        from .opcua_server import OpcUaServerPublisher
        return OpcUaServerPublisher(cfg["opcua"]["server"], severity, devices=cfg.get("_devices") or [])
    except ImportError as exc:
        raise SystemExit(f"Missing dependency ({exc}). Run: pip install -r requirements.txt") from exc


class Gateway:
    def __init__(self, cfg: dict, publisher=None):
        self.cfg = cfg
        self.stats = Stats()
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=int(cfg["traps"]["queue_size"]))
        self.publisher = publisher if publisher is not None else make_publisher(cfg)
        self.resolver = OidResolver(cfg["traps"].get("oid_names"))
        self.transports: list = []
        self.v3: SnmpV3Engine | None = None
        self.engine = TrapTagEngine(cfg.get("_devices") or [])
        if hasattr(self.publisher, "engine"):
            self.publisher.engine = self.engine     # lets client resets (writing 0) reach the engine
        self.monitor: Callable[[str, Any], None] | None = None   # set by the desktop UI
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def _consume(self) -> None:
        while True:
            trap = await self.queue.get()
            try:
                trap.tag_updates = self.engine.process(trap)
                if trap.tag_updates:
                    self._notify("tags", [(u.path, self.engine.values[u.path][0], u.good)
                                          for u in trap.tag_updates if u.path in self.engine.values])
                await self.publisher.publish(trap)
                self.stats.published += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                self.stats.dropped += 1
                log.exception("Failed to publish trap from %s", trap.source_ip)
            finally:
                self.queue.task_done()
            await self._status()

    def _notify(self, kind: str, payload) -> None:
        """Tell the desktop UI; a failing UI callback must never cost a trap."""
        if self.monitor is None:
            return
        try:
            self.monitor(kind, payload)
        except Exception:
            log.debug("monitor callback failed", exc_info=True)

    async def _status(self) -> None:
        try:
            await self.publisher.update_status(self.stats)
        except Exception:
            log.debug("Status update failed", exc_info=True)

    async def _status_loop(self) -> None:
        while True:
            await asyncio.sleep(5)
            await self._status()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.add_signal_handler(sig, self.stop)   # not available on Windows

        snmp = self.cfg["snmp"]
        v3cfg = snmp["v3"]
        users = v3cfg.get("_users") or []
        if users and "v3" in snmp["versions"]:
            engine_id, boots = load_engine_state(v3cfg.get("state_file"), v3cfg.get("engine_id"))
            self.v3 = SnmpV3Engine(engine_id, boots, users, self.resolver, bool(v3cfg.get("replay_protection", True)))
            log.info("SNMPv3 enabled: engine ID %s, boots %d, users: %s", engine_id.hex(), boots,
                     ", ".join(f"{u.name} ({u.level})" for u in users))
        await self.publisher.start()
        tasks = []
        endpoints = listen_endpoints(self.cfg)       # computed now, so later overrides (--port, tests) apply
        try:
            core = TrapProtocol(self.queue, self.stats, self.resolver, snmp["communities"],
                                snmp["allowed_sources"], snmp["respond_to_informs"],
                                v3=self.v3, versions=snmp["versions"], monitor=self.monitor,
                                accept_all_hosts=snmp.get("accept_all_hosts"))
            for host, port, proto in endpoints:
                factory = (lambda c=core: c) if proto == "TCP" else (lambda: TrapProtocol(
                    self.queue, self.stats, self.resolver, snmp["communities"], snmp["allowed_sources"],
                    snmp["respond_to_informs"], v3=self.v3, versions=snmp["versions"], monitor=self.monitor,
                    accept_all_hosts=snmp.get("accept_all_hosts")))
                self.transports.append(await start_listener(loop, host, port, factory, proto))
            for st in self.engine.state.values():
                if st.error:
                    log.warning(st.error)
            tasks = [asyncio.create_task(self._consume()), asyncio.create_task(self._status_loop())]
            if self.monitor is not None:
                self._notify("started", {
                    "listen": [f"{proto} {host}:{port}" for host, port, proto in endpoints],
                    "versions": list(snmp["versions"]),
                    "engine_id": self.v3.engine_id.hex() if self.v3 else None,
                    "devices": len(self.engine.devices),
                })
            await self._stop.wait()
            log.info("Shutting down")
        except ListenerError as exc:
            log.error("%s", exc.strerror)
            raise
        finally:
            for t in self.transports:
                t.close()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.publisher.stop()
