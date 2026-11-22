"""Poll devices over SNMP and turn the answers into tag updates.

Per device (``polling:`` in the config):

* polled OID tags (address = numeric OID) are read with GET in batches;
* ``ge_orbit_remotes: true`` reads the GE MDS Orbit master's remote table and gives each
  remote radio its own tags (folder named after its MAC):

      <Channel>.<Device>.Remotes.<MAC>.MAC / IP / RSSI / IfIndex / Online / LastSeen
      <Channel>.<Device>.Remotes.Count / OnlineCount

* poll status tags (underscore prefix, like the server's system tags):

      <Channel>.<Device>._Polling.OK / Error / LastPoll / DurationMs / Failures

When a poll fails, polled tags keep their last value with Bad quality, as an OPC server does.
A remote that drops out of the master's table is marked Online = 0 and keeps its last RSSI.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import ge_orbit
from .oids import OidResolver
from .snmp_client import MISSING_TYPES, SnmpClient, SnmpErrorStatus, SnmpTimeout
from .snmp_driver import DeviceDef, PollAddress, TagDef, Update
from .trap import VarBind

log = logging.getLogger("snmp2opcua.poller")
GET_BATCH = 16


@dataclass
class RemoteState:
    remote: ge_orbit.Remote
    online: bool = True
    last_seen: datetime | None = None


@dataclass
class PollStats:
    polls: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    last_ok: datetime | None = None
    last_attempt: datetime | None = None
    last_error: str = ""
    duration_ms: int = 0
    remotes: dict[str, RemoteState] = field(default_factory=dict)


def convert(vb: VarBind, data_type: str):
    """SNMP value -> tag value. Raises ValueError when it doesn't fit the tag's type."""
    v = vb.value
    if vb.type in MISSING_TYPES or vb.type == "EndOfMibView" or (v is None and data_type != "String"):
        raise ValueError(f"{vb.oid}: {vb.type}")
    if data_type == "String":
        return ge_orbit.ip_text(vb) if vb.type == "IpAddress" else ("" if v is None else str(v))
    if data_type == "Boolean":
        if isinstance(v, (int, float)):
            return bool(v)
        return str(v).strip().lower() in ("1", "true", "on", "yes", "up")
    if data_type in ("Float", "Double"):
        return float(v) if isinstance(v, (int, float)) else float(str(v).strip())
    if vb.type == "IpAddress":
        n = int.from_bytes(vb.raw, "big")
    elif isinstance(v, (int, float)):
        n = int(v)
    else:
        n = int(str(v).strip())
    lo, hi = (-2**31, 2**31 - 1) if data_type == "Long" else (0, 2**32 - 1)
    if not lo <= n <= hi:
        raise ValueError(f"{vb.oid}: {n} is out of range for {data_type}")
    return n


class DevicePoller:
    def __init__(self, dev: DeviceDef, resolver: OidResolver | None = None, client: SnmpClient | None = None):
        assert dev.poll is not None
        self.dev = dev
        self.cfg = dev.poll
        self.stats = PollStats()
        self.tags: list[TagDef] = [t for t in dev.tags if isinstance(t.address, PollAddress)]
        self.last_values: dict[str, tuple[object, str]] = {}
        self.client = client or SnmpClient(dev.host, self.cfg.community, self.cfg.version, self.cfg.port,
                                           self.cfg.timeout_ms / 1000, self.cfg.retries, resolver)

    def p(self, rest: str) -> str:
        return f"{self.dev.path}.{rest}"

    def static_tags(self) -> list[tuple[str, str]]:
        """(path, data type) of tags that exist from the start (OPC UA nodes are created up front)."""
        out = [(self.p("_Polling.OK"), "Boolean"), (self.p("_Polling.Error"), "String"),
               (self.p("_Polling.LastPoll"), "Date"), (self.p("_Polling.DurationMs"), "DWord"),
               (self.p("_Polling.Failures"), "DWord")]
        if self.cfg.ge_orbit_remotes:
            out += [(self.p("Remotes.Count"), "DWord"), (self.p("Remotes.OnlineCount"), "DWord")]
        return out

    def _remote_updates(self, key: str, st: RemoteState, good: bool) -> list[Update]:
        r = st.remote
        base = self.p(f"Remotes.{key}")
        return [Update(f"{base}.MAC", r.mac, "String", good=good),
                Update(f"{base}.IP", r.ip, "String", good=good),
                Update(f"{base}.RSSI", r.rssi if r.rssi is not None else 0, "Long",
                       good=good and r.rssi is not None),
                Update(f"{base}.IfIndex", r.if_index, "Long", good=good),
                Update(f"{base}.Online", st.online, "Boolean", good=good),
                Update(f"{base}.LastSeen", st.last_seen, "Date", good=good and st.last_seen is not None)]

    async def _poll_tags(self) -> list[Update]:
        out: list[Update] = []
        for i in range(0, len(self.tags), GET_BATCH):
            batch = self.tags[i:i + GET_BATCH]
            oids = [t.address.oid for t in batch]  # type: ignore[union-attr]
            try:
                vbs = await self.client.get(oids)
            except SnmpErrorStatus as exc:
                if exc.name not in ("noSuchName", "tooBig") or len(batch) == 1:
                    raise
                vbs = []                      # SNMPv1: one bad OID fails the request; ask one by one
                for oid in oids:
                    try:
                        vbs += await self.client.get([oid])
                    except SnmpErrorStatus as one:
                        vbs.append(VarBind(oid, oid, "NoSuchObject", None))
                        log.debug("%s: %s", oid, one)
            if len(vbs) < len(batch):          # a short answer: treat the missing ones as absent
                vbs = list(vbs) + [VarBind(t.address.oid, t.address.oid, "NoSuchObject", None)  # type: ignore[union-attr]
                                   for t in batch[len(vbs):]]
            for tag, vb in zip(batch, vbs):  # noqa: B905 (lengths checked above; strict= needs Python 3.10)
                path = self.dev.tag_path(tag)
                try:
                    value = convert(vb, tag.data_type)
                    out.append(Update(path, value, tag.data_type))
                    self.last_values[path] = (value, tag.data_type)
                except ValueError as exc:
                    log.debug("%s: %s", path, exc)
                    old = self.last_values.get(path, (None, tag.data_type))[0]
                    out.append(Update(path, old if old is not None else _initial(tag.data_type), tag.data_type,
                                      good=False))
        return out

    async def _poll_orbit(self) -> list[Update]:
        remotes = await ge_orbit.read_remotes(self.client, self.cfg.max_repetitions)
        now = datetime.now(timezone.utc)
        seen = set()
        for r in remotes:
            seen.add(r.key)
            st = self.stats.remotes.get(r.key)
            if st is None:
                log.info("%s: remote %s (%s) is connected, RSSI %s dBm", self.dev.path, r.mac, r.ip, r.rssi)
                st = self.stats.remotes[r.key] = RemoteState(r)
            elif not st.online:
                log.info("%s: remote %s (%s) is back, RSSI %s dBm", self.dev.path, r.mac, r.ip, r.rssi)
            st.remote, st.online, st.last_seen = r, True, now
        out: list[Update] = []
        for key, st in self.stats.remotes.items():
            if key not in seen and st.online:
                st.online = False
                log.warning("%s: remote %s (%s) is no longer in the master's table", self.dev.path,
                            st.remote.mac, st.remote.ip)
            out += self._remote_updates(key, st, True)
        online = sum(st.online for st in self.stats.remotes.values())
        out += [Update(self.p("Remotes.Count"), len(self.stats.remotes), "DWord"),
                Update(self.p("Remotes.OnlineCount"), online, "DWord")]
        return out

    async def poll_once(self) -> list[Update]:
        st = self.stats
        st.polls += 1
        started = time.monotonic()
        st.last_attempt = datetime.now(timezone.utc)
        try:
            updates = await self._poll_tags() if self.tags else []
            if self.cfg.ge_orbit_remotes:
                updates += await self._poll_orbit()
            ok, error = True, ""
            st.last_ok = st.last_attempt
            st.consecutive_failures = 0
        except (SnmpTimeout, SnmpErrorStatus, OSError) as exc:
            if isinstance(exc, (SnmpTimeout, SnmpErrorStatus)):
                error = str(exc)
            else:
                error = f"{exc.strerror or exc} ({self.dev.host}:{self.cfg.port})"
            ok = False
            st.failures += 1
            st.consecutive_failures += 1
            if st.consecutive_failures == 1:
                log.warning("Polling %s (%s) failed: %s", self.dev.path, self.dev.host, error)
            updates = []
            for tag in self.tags:            # keep last values, quality Bad
                path = self.dev.tag_path(tag)
                value, dt = self.last_values.get(path, (_initial(tag.data_type), tag.data_type))
                updates.append(Update(path, value, dt, good=False))
            for key, rs in st.remotes.items():
                updates += self._remote_updates(key, rs, False)
        st.last_error = error
        st.duration_ms = int((time.monotonic() - started) * 1000)
        updates += [Update(self.p("_Polling.OK"), ok, "Boolean"),
                    Update(self.p("_Polling.Error"), error, "String"),
                    Update(self.p("_Polling.LastPoll"), st.last_attempt, "Date"),
                    Update(self.p("_Polling.DurationMs"), st.duration_ms, "DWord"),
                    Update(self.p("_Polling.Failures"), st.failures, "DWord")]
        return updates

    def radios(self) -> list[dict]:
        """Rows for the window's Radios tab."""
        warn = self.cfg.rssi_warning_dbm
        return [{"master": self.dev.path, "mac": s.remote.mac, "ip": s.remote.ip, "rssi": s.remote.rssi,
                 "if_index": s.remote.if_index, "online": s.online,
                 "weak": warn is not None and s.remote.rssi is not None and s.remote.rssi < warn,
                 "last_seen": s.last_seen.astimezone().strftime("%H:%M:%S") if s.last_seen else "",
                 "poll_ok": self.stats.consecutive_failures == 0}
                for s in self.stats.remotes.values()]

    async def run(self, on_updates, stop: asyncio.Event) -> None:
        interval = self.cfg.scan_rate_ms / 1000
        while not stop.is_set():
            started = time.monotonic()
            updates = await self.poll_once()
            try:
                await on_updates(self, updates)
            except Exception:
                log.exception("Publishing polled values of %s failed", self.dev.path)
            delay = max(0.0, interval - (time.monotonic() - started))
            try:
                await asyncio.wait_for(stop.wait(), delay)
            except asyncio.TimeoutError:
                pass

    def close(self) -> None:
        self.client.close()


def _initial(data_type: str):
    from .snmp_driver import INITIAL
    v = INITIAL[data_type]
    return v if v is not None else ""
