"""Load config.yaml and merge it over sensible defaults."""
from __future__ import annotations

import copy
import os
import re
from pathlib import Path

import yaml

DEFAULTS: dict = {
    "snmp": {
        "listen_host": "0.0.0.0",
        "listen_port": 162,
        "communities": ["public"],     # empty list = accept any community
        "allowed_sources": [],         # IPs / CIDRs; empty = accept from anywhere
        "respond_to_informs": True,
        "versions": ["v1", "v2c", "v3"],   # which SNMP versions to accept
        "v3": {
            "engine_id": None,             # hex; auto-generated and stored in state_file if empty
            "state_file": "snmp2opcua_engine.json",
            "replay_protection": True,
            "users": [],
        },
    },
    "opcua": {
        "mode": "server",              # "server" or "client"
        "server": {
            "endpoint": "opc.tcp://0.0.0.0:4840/snmp2opcua/",
            "server_name": "SNMP Trap Gateway",
            "namespace": "urn:snmp2opcua:gateway",
            "security_policies": ["NoSecurity"],
            "certificate": None,
            "private_key": None,
            "events": True,
            "recent_traps": 50,
            "max_devices": 1000,
        },
        "client": {
            "url": "opc.tcp://localhost:4840",
            "username": None,
            "password": None,
            "security_string": None,
            "timeout": 4,
            "reconnect_delay": 5,
            "nodes": {},
        },
    },
    "traps": {
        "queue_size": 10000,
        "oid_names": {},
        "severity": {"default": 500, "rules": {}},
    },
    "logging": {"level": "INFO"},
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict) and key != "nodes":
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env(value):
    """Replace ${VAR} with the environment variable VAR (for keys you don't want in the file)."""
    if not isinstance(value, str):
        return value

    def sub(m):
        if m.group(1) not in os.environ:
            raise ValueError(f"environment variable {m.group(1)} is not set")
        return os.environ[m.group(1)]
    return _ENV.sub(sub, value)


def build_v3_users(cfg: dict) -> list:
    from .usm import UsmUser
    users = []
    seen = set()
    for i, u in enumerate(cfg["snmp"]["v3"].get("users") or []):
        if not isinstance(u, dict):
            raise ValueError(f"snmp.v3.users[{i}] must be a mapping")
        name = str(u.get("name") or "")
        if name in seen:
            raise ValueError(f"duplicate SNMPv3 user {name!r}")
        seen.add(name)
        users.append(UsmUser.create(
            name, u.get("auth_protocol"), expand_env(u.get("auth_key")),
            u.get("priv_protocol"), expand_env(u.get("priv_key")), u.get("engine_ids")))
    return users


def load_config(path: str | Path | None) -> dict:
    data: dict = {}
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    cfg = _merge(DEFAULTS, data)
    mode = cfg["opcua"]["mode"]
    if mode not in ("server", "client"):
        raise ValueError(f"opcua.mode must be 'server' or 'client', got {mode!r}")
    port = int(cfg["snmp"]["listen_port"])
    if not 0 < port < 65536:
        raise ValueError(f"snmp.listen_port out of range: {port}")
    bad = set(cfg["snmp"]["versions"] or []) - {"v1", "v2c", "v3"}
    if bad:
        raise ValueError(f"snmp.versions has unknown entries {sorted(bad)}; use v1, v2c, v3")
    cfg["snmp"]["v3"]["_users"] = build_v3_users(cfg)   # validates keys/protocols at startup
    return cfg
