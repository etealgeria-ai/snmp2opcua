"""The ``snmp:`` section as edited by the window's SNMP page.

Covers what the gateway listens on and what it accepts: network interfaces (address and
port), communities, the host access list, SNMP versions, INFORM responses and SNMPv3
(engine ID, replay protection and users). Like the Stations page, a save is turned into
the smallest edit of config.yaml (via yaml_edit) so comments and layout survive, and the
controller validates the result the same way the gateway does before writing it.
No Tk here, so it is unit-tested directly.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field

import yaml

from .config import DEFAULTS
from .usm import AUTH_PROTOCOLS, PRIV_PROTOCOLS, UsmUser, normalize
from .yaml_edit import append_to, delete_in, remove_from, set_in, set_list

VERSIONS = ("v1", "v2c", "v3")
AUTH_CHOICES = ["NONE", *[p for p in AUTH_PROTOCOLS if p != "NONE"]]
PRIV_CHOICES = ["NONE", *[p for p in PRIV_PROTOCOLS if p != "NONE"]]
_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass
class Listener:
    address: str
    port: int

    @property
    def label(self) -> str:
        return f"{'all interfaces' if self.address in ('0.0.0.0', '::') else self.address}, UDP {self.port}"


@dataclass
class V3User:
    name: str
    auth_protocol: str = "NONE"
    auth_key: str = ""
    priv_protocol: str = "NONE"
    priv_key: str = ""
    engine_ids: list[str] = field(default_factory=list)
    index: int | None = None          # position under snmp.v3.users; None for a new user
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def level(self) -> str:
        if self.auth_protocol == "NONE":
            return "noAuthNoPriv"
        return "authNoPriv" if self.priv_protocol == "NONE" else "authPriv"

    def missing_variables(self) -> list[str]:
        """Environment variables named in the keys (${VAR}) that aren't set on this computer."""
        return [v for key in (self.auth_key, self.priv_key) for v in _ENV.findall(key or "") if v not in os.environ]

    def as_dict(self) -> dict:
        d: dict = {"name": self.name}
        if self.auth_protocol != "NONE":
            d["auth_protocol"] = self.auth_protocol
            d["auth_key"] = self.auth_key
        if self.priv_protocol != "NONE":
            d["priv_protocol"] = self.priv_protocol
            d["priv_key"] = self.priv_key
        if self.engine_ids:
            d["engine_ids"] = list(self.engine_ids)
        return d


@dataclass
class SnmpSettings:
    listeners: list[Listener]
    communities: list[str]
    accept_all_hosts: bool
    allowed_sources: list[str]
    versions: list[str]
    respond_to_informs: bool
    engine_id: str                    # hex; "" = generated once and kept in the state file
    replay_protection: bool
    users: list[V3User]
    uses_interfaces: bool = False     # the file lists network_interfaces (not just listen_host/port)
    raw: dict = field(default_factory=dict, repr=False)


def _protocol(value, choices: dict) -> str:
    text = normalize(value)
    return text if text == "NONE" or text in choices else str(value)


def load_settings(text: str) -> SnmpSettings:
    """The snmp: section of config.yaml text. Raises ValueError if it can't be read."""
    try:
        return _load_settings(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"the configuration isn't valid YAML: {exc}") from exc
    except (TypeError, AttributeError) as exc:
        raise ValueError(f"the snmp: section has an entry of the wrong kind ({exc})") from exc


def _load_settings(text: str) -> SnmpSettings:
    data = yaml.safe_load(text) or {}
    raw = data.get("snmp") or {}
    if not isinstance(raw, dict):
        raw = {}
    d = DEFAULTS["snmp"]
    interfaces = raw.get("network_interfaces") or []
    if interfaces:
        listeners = [Listener(str(ni.get("address", "0.0.0.0")), int(ni.get("port", 162)))
                     for ni in interfaces if isinstance(ni, dict)]
    else:
        listeners = [Listener(str(raw.get("listen_host", d["listen_host"])), int(raw.get("listen_port", d["listen_port"])))]
    allowed = [str(s) for s in (raw.get("allowed_sources") or [])]
    accept_all = raw.get("accept_all_hosts")
    v3 = raw.get("v3") or {}
    users = []
    for i, u in enumerate(v3.get("users") or []):
        if not isinstance(u, dict):
            continue
        users.append(V3User(
            name=str(u.get("name") or ""),
            auth_protocol=_protocol(u.get("auth_protocol"), AUTH_PROTOCOLS),
            auth_key="" if u.get("auth_key") is None else str(u.get("auth_key")),
            priv_protocol=_protocol(u.get("priv_protocol"), PRIV_PROTOCOLS),
            priv_key="" if u.get("priv_key") is None else str(u.get("priv_key")),
            engine_ids=[str(e) for e in (u.get("engine_ids") or [])],
            index=i, raw=u))
    return SnmpSettings(
        listeners=listeners,
        communities=[str(c) for c in (raw["communities"] if "communities" in raw else d["communities"]) or []],
        accept_all_hosts=(not allowed) if accept_all is None else bool(accept_all),
        allowed_sources=allowed,
        versions=[str(v) for v in (raw.get("versions") or d["versions"])],
        respond_to_informs=bool(raw.get("respond_to_informs", d["respond_to_informs"])),
        engine_id="" if v3.get("engine_id") in (None, "") else str(v3.get("engine_id")),
        replay_protection=bool(v3.get("replay_protection", d["v3"]["replay_protection"])),
        users=users,
        uses_interfaces=bool(interfaces),
        raw=raw,
    )


# ------------------------------------------------------------------ checks for single entries
def check_address(text: str) -> tuple[str | None, str]:
    text = text.strip()
    if text.lower() in ("", "all", "any", "*"):
        return "0.0.0.0", ""
    try:
        return str(ipaddress.ip_address(text)), ""
    except ValueError:
        return None, (f"Invalid IP address {text!r}. Enter a valid IPv4 address in quad-dotted notation, "
                      f"such as 127.0.0.1, or 0.0.0.0 for all interfaces.")


def check_listener(address: str, port: str, existing: list[Listener]) -> tuple[Listener | None, str]:
    addr, problem = check_address(address)
    if addr is None:
        return None, problem
    try:
        p = int(str(port).strip())
    except ValueError:
        return None, "The port must be a whole number from 1 to 65535."
    if not 0 < p < 65536:
        return None, "The port must be within the range of 1 to 65535."
    if any(x.address == addr and x.port == p for x in existing):
        return None, f"The network interface {addr}; Port: {p} has already been added."
    return Listener(addr, p), ""


def check_community(text: str, existing: list[str]) -> tuple[str | None, str]:
    if text == "":
        return None, "Type a community name first."
    if text != text.strip():
        return None, "A community can't start or end with a space."
    if len(text.encode()) > 255:
        return None, "A community can be at most 255 bytes."
    if text in existing:
        return None, f"The community {text} has already been added."
    return text, ""


def check_host(text: str, existing: list[str]) -> tuple[str | None, str]:
    text = text.strip()
    try:
        norm = str(ipaddress.ip_network(text, strict=False)) if "/" in text else str(ipaddress.ip_address(text))
    except ValueError:
        return None, (f"Invalid IP address {text!r}. Enter an IPv4 address such as 192.168.1.20, or a network "
                      f"such as 10.10.0.0/16.")
    if norm in existing:
        return None, f"The host IP {text} has already been added."
    return norm, ""


def _engine_hex(text: str) -> tuple[str | None, str]:
    clean = text.replace(":", "").replace(" ", "").lower()
    clean = clean.removeprefix("0x")
    try:
        raw = bytes.fromhex(clean)
    except ValueError:
        return None, f"Engine ID {text!r} isn't hexadecimal, e.g. 800000090300aabbccddeeff."
    if not 5 <= len(raw) <= 32:
        return None, f"Engine ID {text!r} must be 5 to 32 octets (10 to 64 hex digits)."
    return clean, ""


def check_user(values: dict, users: list[V3User], editing: V3User | None) -> tuple[V3User | None, list[str]]:
    """A user from the form fields: name, auth_protocol, auth_key, priv_protocol, priv_key, engine_ids."""
    problems: list[str] = []
    name = str(values.get("name", "")).strip()
    auth = normalize(values.get("auth_protocol"))
    priv = normalize(values.get("priv_protocol"))
    auth_key = str(values.get("auth_key") or "")
    priv_key = str(values.get("priv_key") or "")
    if not name:
        problems.append("The user needs a name.")
    elif any(u.name == name and u is not editing for u in users):
        problems.append(f"The user {name} has already been added.")
    if auth != "NONE" and auth not in AUTH_PROTOCOLS:
        problems.append(f"Unknown authentication protocol {auth}.")
    if priv != "NONE" and priv not in PRIV_PROTOCOLS:
        problems.append(f"Unknown privacy protocol {priv}.")
    if auth == "NONE" and priv != "NONE":
        problems.append("Privacy needs authentication: choose an authentication protocol, or set privacy to NONE.")
    for label, proto, key in (("Authentication", auth, auth_key), ("Privacy", priv, priv_key)):
        if proto == "NONE":
            continue
        if not key:
            problems.append(f"{label} key is required for {proto}.")
        elif not _ENV.fullmatch(key) and len(key) < 8:
            problems.append(f"{label} key must be at least 8 characters.")
    engine_ids = []
    for e in re.split(r"[,\s]+", str(values.get("engine_ids") or "").strip()):
        if not e:
            continue
        clean, problem = _engine_hex(e)
        if clean is None:
            problems.append(problem)
        else:
            engine_ids.append(clean)
    if problems:
        return None, problems
    user = V3User(name, auth, auth_key if auth != "NONE" else "", priv, priv_key if priv != "NONE" else "",
                  engine_ids, editing.index if editing else None, editing.raw if editing else {})
    if not user.missing_variables():
        try:   # the gateway's own check, with ${VAR} keys expanded
            UsmUser.create(name, auth, _expand(user.auth_key) or None, priv, _expand(user.priv_key) or None,
                           engine_ids)
        except ValueError as exc:
            return None, [str(exc)]
    return user, []


def _expand(text: str) -> str:
    return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(0)), text or "")


def check_settings(st: SnmpSettings) -> tuple[list[tuple[str, str]], list[str]]:
    """(problems that block saving as (field, message), warnings)."""
    problems: list[tuple[str, str]] = []
    warnings: list[str] = []
    if not st.listeners:
        problems.append(("listeners", "Add at least one network interface to listen on."))
    if not st.versions:
        problems.append(("versions", "Accept at least one SNMP version."))
    if not st.accept_all_hosts and not st.allowed_sources:
        problems.append(("hosts", "Add at least one host, or accept packets from all hosts."))
    if st.engine_id:
        clean, problem = _engine_hex(st.engine_id)
        if clean is None:
            problems.append(("engine_id", problem))
    if "v3" in st.versions and not st.users:
        warnings.append("SNMPv3 is accepted but there are no users, so every v3 trap will be rejected.")
    if not st.communities and any(v in st.versions for v in ("v1", "v2c")):
        warnings.append("No communities: v1/v2c traps with any community are accepted.")
    for u in st.users:
        missing = u.missing_variables()
        if missing:
            warnings.append(f"User {u.name}: {', '.join(missing)} isn't set on this computer. The gateway "
                            f"won't start until it is set (or the key is typed in here instead).")
    return problems, warnings


# ------------------------------------------------------------------ saving
def save_settings(text: str, st: SnmpSettings, original: SnmpSettings) -> str:
    """config.yaml text with the snmp: section changed to `st` (only real changes are written)."""
    base = ["snmp"]
    if [(x.address, x.port) for x in st.listeners] != [(x.address, x.port) for x in original.listeners] \
            or (st.uses_interfaces and not original.uses_interfaces):
        if len(st.listeners) == 1 and not original.uses_interfaces:
            only = st.listeners[0]
            text = set_in(text, base + ["listen_host"], only.address)
            text = set_in(text, base + ["listen_port"], only.port)
        else:
            text = set_list(text, base + ["network_interfaces"],
                            [{"address": x.address, "port": x.port} for x in st.listeners])
    simple = [("communities", st.communities, original.communities),
              ("allowed_sources", st.allowed_sources, original.allowed_sources),
              ("versions", [v for v in VERSIONS if v in st.versions],
               [v for v in VERSIONS if v in original.versions]),
              ("respond_to_informs", st.respond_to_informs, original.respond_to_informs)]
    for key, new, old in simple:
        if new != old:
            text = set_list(text, base + [key], new) if isinstance(new, list) else set_in(text, base + [key], new)
    if st.accept_all_hosts != original.accept_all_hosts or \
            ("accept_all_hosts" not in original.raw and st.allowed_sources != original.allowed_sources):
        text = set_in(text, base + ["accept_all_hosts"], st.accept_all_hosts)
    if st.engine_id != original.engine_id:
        if st.engine_id:
            text = set_in(text, base + ["v3", "engine_id"], st.engine_id)
        else:
            text = set_in(text, base + ["v3", "engine_id"], None)
    if st.replay_protection != original.replay_protection:
        text = set_in(text, base + ["v3", "replay_protection"], st.replay_protection)
    return _save_users(text, st.users, original.users)


def _save_users(text: str, users: list[V3User], original: list[V3User]) -> str:
    path = ["snmp", "v3", "users"]
    kept = {u.index for u in users if u.index is not None}
    for u in sorted(original, key=lambda x: x.index or 0, reverse=True):     # removals, last first
        if u.index not in kept:
            text = remove_from(text, path, u.index)  # type: ignore[arg-type]
    remaining = sorted(u.index for u in original if u.index in kept)  # type: ignore[type-var]
    position = {old: new for new, old in enumerate(remaining)}
    by_index = {u.index: u for u in original}
    for u in users:
        if u.index is None:
            continue
        old = by_index[u.index]
        at = path + [position[u.index]]
        for key, new_v, old_v in (("name", u.name, old.name),
                                  ("auth_protocol", u.auth_protocol, old.auth_protocol),
                                  ("auth_key", u.auth_key, old.auth_key),
                                  ("priv_protocol", u.priv_protocol, old.priv_protocol),
                                  ("priv_key", u.priv_key, old.priv_key)):
            if new_v == old_v:
                continue
            if (new_v in ("", "NONE")) and key != "name":
                text = delete_in(text, at + [key])
            else:
                text = set_in(text, at + [key], new_v)
        if u.engine_ids != old.engine_ids:
            text = set_list(text, at + ["engine_ids"], u.engine_ids) if u.engine_ids else \
                delete_in(text, at + ["engine_ids"])
    for u in users:
        if u.index is None:
            text = append_to(text, path, u.as_dict())
    return text
