# snmp2opcua: SNMP trap to OPC UA gateway

Receives SNMP traps from switches, UPSs, PLCs, firewalls and similar devices, and publishes them over OPC UA so SCADA, HMI and historian systems can use them.

```
 devices ──SNMP v1/v2c/v3 trap/inform (UDP 162)──▶ snmp2opcua ──OPC UA──▶ SCADA / HMI / historian
```

It has two modes:

- **server** (default): the gateway runs its own OPC UA server. Each trap updates variables and fires an OPC UA event.
- **client**: the gateway connects to an OPC UA server you already have and writes trap fields into NodeIds you choose.

## Features

- SNMP **v1 traps**, **v2c traps and informs**, and **v3 traps and informs** (informs are acknowledged)
- **SNMPv3 USM**: authentication with MD5, SHA-1 or SHA-224/256/384/512, and encryption with DES, AES-128 or AES-192/256 (both the net-snmp and Cisco key formats). Informs work with engine discovery, and traps get replay protection
- The SNMP decoder is built in and needs no SNMP library. v1 traps are converted to v2 notification OIDs (RFC 3584), so traps from every version look the same downstream
- Community allow-list (v1/v2c), USM users (v3), a source IP/CIDR allow-list, and a setting to accept only some SNMP versions (e.g. v3 only)
- Friendly OID names: common MIBs are built in (IF-MIB, SNMPv2-MIB, UPS-MIB, ...), and you can add your own in the config
- OPC UA event severity is mapped per trap name or OID prefix
- Each source device gets its own node with a trap count and its last trap
- A bounded queue holds traps while OPC UA is slow or unreachable. In client mode the gateway reconnects automatically
- **Desktop window** to start and stop the gateway, watch traps arrive, see why packets were rejected, send test traps and edit the configuration
- Runs on Linux and Windows, Python 3.9+ (tested on 3.13)

## Install and run

```bash
pip install -r requirements.txt          # asyncua, PyYAML, cryptography
export SNMP_AUTH_KEY=authpass123 SNMP_PRIV_KEY=privpass123   # v3 keys used by config.yaml (Windows: set ...)
python -m snmp2opcua -c config.yaml      # UDP 162 needs root/admin, see below
```

For a quick test without root, run in one terminal (with the two variables above set):

```bash
python -m snmp2opcua -c config.yaml --port 1162 --log-level DEBUG
```

and in another:

```bash
python -m snmp2opcua.sendtrap --port 1162 --trap-oid linkDown -v ifIndex.3 i 3 -v ifDescr.3 s eth3
python -m snmp2opcua.sendtrap --port 1162 --inform --trap-oid 1.3.6.1.4.1.9999.0.1 -v 1.3.6.1.4.1.9999.1 s "Door open"
python -m snmp2opcua.sendtrap --port 1162 --snmp-version 1 --enterprise 1.3.6.1.4.1.9999 --specific 7
python -m snmp2opcua.sendtrap --port 1162 --snmp-version 3 -u opcgw -a SHA256 -A authpass123 -x AES -X privpass123 --trap-oid linkDown -v ifIndex.3 i 3
python -m snmp2opcua.sendtrap --port 1162 --snmp-version 3 -u opcgw -a SHA256 -A authpass123 -x AES -X privpass123 --inform --trap-oid coldStart
python examples/watch_traps.py opc.tcp://localhost:4840/snmp2opcua/
```

You can also use net-snmp, then browse the server with UaExpert:

```bash
snmptrap -v 2c -c public localhost:1162 '' 1.3.6.1.6.3.1.1.5.3
snmptrap -v 3 -u opcgw -l authPriv -a SHA-256 -A authpass123 -x AES -X privpass123 \
         -e 0x8000000001020304 localhost:1162 '' 1.3.6.1.6.3.1.1.5.3
snmpinform -v 3 -u opcgw -l authPriv -a SHA-256 -A authpass123 -x AES -X privpass123 localhost:1162 '' 1.3.6.1.6.3.1.1.5.1
```

## OPC UA address space (server mode)

All NodeIds are string NodeIds in namespace `urn:snmp2opcua:gateway`, which is usually `ns=2`.

| NodeId | Type | Meaning |
|---|---|---|
| `ns=2;s=Gateway` | Object | Emits a `SnmpTrapEventType` event for every trap |
| `…;s=Gateway.LastTrap.Json` | String | Full last trap as JSON (one atomic snapshot) |
| `…;s=Gateway.LastTrap.SourceIP` / `TrapOID` / `TrapName` / `Version` / `PduType` / `SecurityName` | String | Fields of the last trap (`SecurityName` is the v3 user) |
| `…;s=Gateway.LastTrap.Uptime` | UInt32 | Agent sysUpTime (1/100 s) |
| `…;s=Gateway.LastTrap.ReceivedAt` | DateTime | Receive time (UTC) |
| `…;s=Gateway.LastTrap.VarBindsJson` | String | Varbinds as JSON `[{"oid","name","type","value"}]` |
| `…;s=Gateway.RecentTrapsJson` | String | JSON array of the last N traps, newest first |
| `…;s=Gateway.Devices.<ip>.TrapCount` / `LastTrapOID` / `LastTrapName` / `LastTrapTime` / `LastTrapJson` | | Per-source device |
| `…;s=Gateway.Status.TrapsReceived` / `TrapsPublished` / `TrapsDropped` / `TrapsRejected` / `MalformedPackets` / `StartTime` | | Gateway health |

**Event fields.** `SnmpTrapEventType` is a subtype of BaseEventType. It adds `SourceIP`, `SnmpVersion`, `SecurityName`, `TrapOID`, `TrapName` and `VarBindsJson`. It also fills the standard `Severity`, `Message`, `SourceName` and `Time` fields.

> **Which to use?** For alarms, subscribe to **events**. OPC UA queues them per subscription, so bursts aren't lost. Polling the variables only shows the latest trap. If you read the variables, read `LastTrap.Json`, because the individual `LastTrap.*` fields are written one after another.

## Client mode (write into an existing OPC UA server)

```yaml
opcua:
  mode: client
  client:
    url: opc.tcp://scada-server:4840
    username: gateway
    password: null                  # or env var OPCUA_PASSWORD
    security_string: "Basic256Sha256,SignAndEncrypt,certs/cert.der,certs/key.pem"
    nodes:
      trap_json:   "ns=2;s=SNMP.LastTrapJson"
      trap_name:   "ns=2;s=SNMP.LastTrapName"
      source_ip:   "ns=2;s=SNMP.LastSourceIP"
      severity:    "ns=2;s=SNMP.LastSeverity"
      trap_count:  "ns=2;s=SNMP.TrapCount"
      received_at: "ns=2;s=SNMP.LastTrapTime"
```

The target nodes must already exist and be writable. The gateway reads each node's data type once and converts values to match (String, any integer type, Double/Float, DateTime). The available fields are `trap_json`, `varbinds_json`, `source_ip`, `version`, `security_name`, `trap_oid`, `trap_name`, `uptime`, `received_at`, `severity`, `trap_count` and `summary`.

If the server goes down, traps wait in the queue (`traps.queue_size`) and are written after the gateway reconnects. If a write is rejected (wrong type, no access), the gateway logs it and skips that node.

## Desktop window

```bash
python -m snmp2opcua.gui -c config.yaml           # add --start to start the gateway right away
python -m snmp2opcua --gui -c config.yaml         # same thing
```

On Windows you can also double-click `run_gui.pyw`, which uses the `config.yaml` next to it. The window uses Tkinter, which comes with Python from python.org. On Debian/Ubuntu, install it with `sudo apt install python3-tk`.

- **Toolbar:** *Start gateway* / *Stop gateway*, the config file in use, and the gateway's state. Under it you'll see the UDP address being listened on and the OPC UA endpoint or target server.
- **Counters:** received, published to OPC UA, waiting to publish, rejected, unreadable and dropped. A counter gets an amber or red stripe and a ⚠ label only when something needs attention. Everything else stays grey, following high-performance HMI practice (ISA-101).
- **Traps:** a live list, newest first.
  - High-severity rows (800 or more) are tinted red and medium ones (600–799) amber. The severity number and label are always shown as text as well.
  - You can filter by any text (source, trap name, numeric OID, v3 user, values), pause the feed, and export to CSV.
  - Select a trap to see its full JSON.
- **Devices:** every source that has sent traps, with a count and its last trap.
- **Rejected:** every refused or unreadable packet with the exact reason, e.g. a wrong community, an unknown v3 user, a failed authentication or decryption, or a stale trap.
- **Send test trap:** sends v1, v2c or v3 traps and informs to the gateway or any other host. You can pick a configured v3 user or enter custom credentials, which is handy for testing a device's settings.
- **Configuration:** edit `config.yaml`, then use *Check*, *Save* or *Save and restart*. An invalid file is never saved, and the previous version is kept as `config.yaml.bak`.
- **Log:** the gateway's own log messages.

## SNMPv3

Add a USM user for each user name your devices send with:

```yaml
snmp:
  versions: [v3]                 # optional: refuse unauthenticated v1/v2c traps
  v3:
    users:
      - name: opcgw
        auth_protocol: SHA256    # MD5, SHA, SHA224, SHA256, SHA384, SHA512, NONE
        auth_key: ${SNMP_AUTH_KEY}
        priv_protocol: AES       # DES, AES, AES192, AES256, AES192C, AES256C, NONE
        priv_key: ${SNMP_PRIV_KEY}
        # engine_ids: [800000090300aabbccddeeff]   # optional: only these devices
```

- **The security level must match.** A user with auth and priv keys only accepts `authPriv` messages, and a user with only an auth key only accepts `authNoPriv`. Anything else is rejected and logged.
- **No per-device engine IDs needed for traps.** With traps the device is the authoritative engine, so the gateway localizes keys to the engine ID inside each message. That means one user entry covers every device that uses those credentials. To lock a user to specific devices, list their engine IDs in `engine_ids`.
- **Informs:** the gateway is the authoritative engine here. Senders discover its engine ID automatically, the same way `snmpinform` and most devices do. The engine ID and a boots counter are kept in `snmp.v3.state_file`, so that file must be writable. You can set a fixed `engine_id` if a device needs it configured by hand.
- **AES-192/256 key formats:** `AES192`/`AES256` use the Blumenthal key extension (net-snmp's `AES-192`/`AES-256`). `AES192C`/`AES256C` use the Reeder extension, which Cisco and many other vendors use (net-snmp's `AES-192-C`/`AES-256-C`). If AES-256 traps fail with "decryption failed", try the other variant.
- **Replay protection** (RFC 3414) rejects stale or replayed traps. A device that resets its engineBoots counter on reboot will be rejected after it reboots. The log tells you when this happens, and you can turn the check off with `replay_protection: false`.
- **Keys** must be at least 8 characters. Use `${ENV_VAR}` so they aren't stored in the file.
- **Troubleshooting:** the log names the cause of each rejection: unknown user, wrong security level, authentication failed (wrong auth key or protocol), decryption failed (wrong priv key or protocol), stale or replayed trap.

## Production notes

- **Port 162**: run as root or Administrator, or on Linux use the included `snmp2opcua.service`, which grants `CAP_NET_BIND_SERVICE`. You can also listen on 1162 and redirect: `iptables -t nat -A PREROUTING -p udp --dport 162 -j REDIRECT --to-ports 1162`.
- **Windows**: stop or disable the built-in **SNMP Trap** service, which holds UDP 162. Open UDP 162 and TCP 4840 in the firewall.
- **OPC UA security**: `NoSecurity` is for lab use. For production, set `security_policies: [Basic256Sha256_SignAndEncrypt]` and provide a certificate and key, for example:
  `openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout certs/server_key.pem -outform der -out certs/server_cert.der -subj "/CN=snmp2opcua" -addext "subjectAltName=URI:urn:snmp2opcua:gateway,DNS:$(hostname)"`
- **Community strings and v3 keys** are never published to OPC UA.
- **Linux service:** the included unit reads the v3 keys from `/etc/snmp2opcua.env` and provides `/var/lib/snmp2opcua` for `state_file`.
- Lock down `snmp.allowed_sources` to your device subnets.

## Limitations and extending

- SNMPv3 support covers USM (the user-based security model). It doesn't do VACM access control or filter by context; any configured user that authenticates is accepted.
- There is no MIB compiler. Add vendor names under `traps.oid_names`. Prefix matching means table columns resolve too, e.g. `ifOperStatus.12`.
- To publish somewhere else (MQTT, a database, ...), write a class with `start()`, `publish(trap)`, `update_status(stats)` and `stop()`, and return it from `make_publisher()` in `gateway.py`.

## Tests

```bash
python -m unittest discover -s tests -v
```

The 32 tests cover:

- decoding a hand-encoded v1 packet and every SNMP value type
- INFORM acknowledgements, community filtering and garbled packets
- for SNMPv3: the RFC 3414 key-localization test vectors, a DES known-answer test, and every auth × priv combination
- for SNMPv3: rejection of wrong keys, tampered messages, unknown users and the wrong security level
- for SNMPv3: replay protection, engine discovery, authenticated inform responses, and time-window Reports
- live UDP end-to-end runs with a fake publisher
- the desktop window's controller: start, stop and restart, live trap and rejection events, test traps, config checks with backup, and the port-in-use error

They don't need asyncua.

## Layout

```
snmp2opcua/
  ber.py           BER encode/decode (SNMP subset)
  trap.py          SNMP v1/v2c message → Trap, INFORM ack builder
  snmpv3.py        SNMPv3 messages: auth, timeliness, decrypt, discovery Reports, inform Responses
  usm.py           USM crypto: key localization, HMAC, DES/AES
  receiver.py      asyncio UDP listener, filtering, stats
  oids.py          built-in OID names + resolver
  severity.py      trap → OPC UA severity rules
  opcua_server.py  server mode (asyncua Server)
  opcua_client.py  client mode (asyncua Client)
  gateway.py       wiring, queue, shutdown
  sendtrap.py      test trap/inform sender
  gui.py           desktop window (Tkinter)
  gui_controller.py  runs the gateway in a thread for the window; no Tk code, so it's testable
config.yaml        example configuration
examples/watch_traps.py   OPC UA subscriber for testing
run_gui.pyw        double-click launcher for the desktop window
```
