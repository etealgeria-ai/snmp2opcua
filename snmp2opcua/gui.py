"""Desktop window for the SNMP trap to OPC UA gateway (Tkinter, no extra packages).

    python -m snmp2opcua.gui -c config.yaml [--start]

The look follows high-performance HMI practice (ISA-101): a neutral grey console where
colour appears only when something needs attention. High-severity traps, rejections and
dropped traps get colour, and always with a text label as well.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import queue
import sys
import threading
from collections import deque
from pathlib import Path
from typing import Any, Literal

try:
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover - reported in main()
    tk = None  # type: ignore[assignment]

from .gui_controller import GatewayController, TrapRequest, parse_varbind_lines
from .usm import AUTH_PROTOCOLS, PRIV_PROTOCOLS, UsmUser

# Neutral console palette; colour is reserved for abnormal states
PANEL = "#D5D9DD"       # window background
SURFACE = "#EEF0F2"     # tiles, headings, tabs
FIELD = "#FFFFFF"       # tables and editors
INK = "#1E2830"
MUTED = "#56636E"
LINE = "#B4BCC3"
ACCENT = "#2F6690"      # running state, selection, primary action
ACCENT_DARK = "#24506F"
WARN = "#C98A00"
WARN_TINT = "#FBEFC6"
WARN_INK = "#7A5200"
ALARM = "#B3261E"
ALARM_TINT = "#F5D5D2"
STOPPED = "#8A949C"

MAX_TRAPS = 5000
MAX_REJECTS = 2000
MAX_LOG_LINES = 3000
CUSTOM_USER = "Custom credentials"

TILES = [
    ("received", "Received"),
    ("published", "Published to OPC UA"),
    ("queued", "Waiting to publish"),
    ("rejected", "Rejected"),
    ("malformed", "Unreadable packets"),
    ("dropped", "Dropped"),
]
# Which counters are abnormal when non-zero, and how loud
TILE_ALERT = {"queued": WARN, "rejected": WARN, "malformed": WARN, "dropped": ALARM}


class GatewayApp:
    def __init__(self, root: tk.Tk, controller: GatewayController, autostart: bool = False):
        self.root = root
        self.ctl = controller
        self.traps: deque[dict] = deque(maxlen=MAX_TRAPS)
        self.trap_by_iid: dict[str, dict] = {}
        self.devices: dict[str, dict] = {}
        self.reject_count = 0
        self.paused = False
        self.unseen = 0
        self.seq = 0
        self.had_error = False
        self.restart_pending = False
        self.sending = False
        self.polling = False

        self._setup_style()
        self._build()
        self._load_config_into_ui(first=True)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(150, self._poll)
        root.after(1000, self._tick)
        if autostart:
            root.after(300, self.start)

    # ================================================================== styling
    def _setup_style(self) -> None:
        base = tkfont.nametofont("TkDefaultFont")
        family = base.actual("family")
        self.f_base = tkfont.Font(family=family, size=10)
        self.f_small = tkfont.Font(family=family, size=9)
        self.f_head = tkfont.Font(family=family, size=11, weight="bold")
        self.f_kpi = tkfont.Font(family=family, size=20, weight="bold")
        mono = tkfont.nametofont("TkFixedFont")
        self.f_mono = tkfont.Font(family=mono.actual("family"), size=10)

        self.root.configure(background=PANEL)
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=PANEL, foreground=INK, font=self.f_base, bordercolor=LINE,
                        lightcolor=PANEL, darkcolor=PANEL, troughcolor=SURFACE, focuscolor=ACCENT,
                        fieldbackground=FIELD, selectbackground=ACCENT, selectforeground="#FFFFFF")
        style.configure("TFrame", background=PANEL)
        style.configure("TLabel", background=PANEL, foreground=INK)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Small.TLabel", foreground=MUTED, font=self.f_small)
        style.configure("Head.TLabel", font=self.f_head)
        style.configure("Error.TLabel", foreground=ALARM)
        style.configure("TNotebook", background=PANEL, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", padding=(14, 6), background=PANEL, foreground=MUTED, borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", SURFACE)], foreground=[("selected", INK)])
        style.configure("TButton", padding=(10, 4), background=SURFACE)
        style.map("TButton", background=[("disabled", PANEL), ("active", "#E1E5E9")],
                  foreground=[("disabled", STOPPED)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#FFFFFF", bordercolor=ACCENT_DARK)
        style.map("Accent.TButton", background=[("disabled", "#9DB3C6"), ("active", ACCENT_DARK)],
                  foreground=[("disabled", "#EEF3F7")])
        rowheight = int(self.f_base.metrics("linespace") * 1.7)
        style.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=INK,
                        rowheight=rowheight, borderwidth=0)
        # Mapping only the selected state keeps per-row tag colours visible on Tk 8.6.9+
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview.Heading", background=SURFACE, foreground=MUTED, font=self.f_small,
                        relief="flat", padding=(6, 4))
        style.map("Treeview.Heading", background=[("active", "#E1E5E9")])
        style.configure("TLabelframe", background=PANEL, bordercolor=LINE)
        style.configure("TLabelframe.Label", background=PANEL, foreground=MUTED)
        style.configure("TCheckbutton", background=PANEL)
        style.configure("TRadiobutton", background=PANEL)

    # ================================================================== layout
    def _build(self) -> None:
        root = self.root

        # --- toolbar: actions on the left, state on the right
        bar = ttk.Frame(root, padding=(12, 10, 12, 4))
        bar.pack(side="top", fill="x")
        self.btn_start = ttk.Button(bar, text="Start gateway", style="Accent.TButton", command=self.start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(bar, text="Stop gateway", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=(6, 0))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=12)
        ttk.Button(bar, text="Open config…", command=self.open_config).pack(side="left")
        self.config_label = ttk.Label(bar, text=str(self.ctl.config_path), style="Muted.TLabel")
        self.config_label.pack(side="left", padx=(8, 0))

        self.status_text = ttk.Label(bar, text="Stopped", style="Head.TLabel")
        self.status_text.pack(side="right")
        self.status_dot = tk.Canvas(bar, width=14, height=14, highlightthickness=0, background=PANEL)
        self.status_dot.pack(side="right", padx=(0, 6))
        self.dot = self.status_dot.create_oval(2, 2, 12, 12, fill=STOPPED, outline="")

        # --- where traps come from and where they go
        info = ttk.Frame(root, padding=(12, 0, 12, 8))
        info.pack(side="top", fill="x")
        self.info_listen = ttk.Label(info, text="", style="Muted.TLabel")
        self.info_listen.pack(side="left")
        self.info_opcua = ttk.Label(info, text="", style="Muted.TLabel")
        self.info_opcua.pack(side="left", padx=(24, 0))

        # --- counters
        strip = ttk.Frame(root, padding=(12, 0, 12, 10))
        strip.pack(side="top", fill="x")
        self.tiles: dict[str, tuple[tk.Frame, tk.Label, tk.Label, str]] = {}
        for i, (key, caption) in enumerate(TILES):
            tile = tk.Frame(strip, background=SURFACE, highlightthickness=1, highlightbackground=LINE)
            tile.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            strip.columnconfigure(i, weight=1, uniform="tiles")
            stripe = tk.Frame(tile, width=4, background=SURFACE)
            stripe.pack(side="left", fill="y")
            inner = tk.Frame(tile, background=SURFACE)
            inner.pack(side="left", fill="both", expand=True, padx=10, pady=6)
            num = tk.Label(inner, text="–", font=self.f_kpi, background=SURFACE, foreground=INK, anchor="w")
            num.pack(fill="x")
            cap = tk.Label(inner, text=caption, font=self.f_small, background=SURFACE, foreground=MUTED, anchor="w")
            cap.pack(fill="x")
            self.tiles[key] = (stripe, num, cap, caption)

        # --- status line (packed before the notebook so it stays visible when resizing)
        self.status_line = ttk.Label(root, text="", style="Small.TLabel", padding=(12, 4, 12, 6))
        self.status_line.pack(side="bottom", fill="x")

        self.nb = ttk.Notebook(root)
        self.nb.pack(side="top", fill="both", expand=True, padx=12)
        self.tab_traps = self._build_traps_tab()
        self.tab_devices = self._build_devices_tab()
        self.tab_rejected = self._build_rejected_tab()
        self.tab_test = self._build_test_tab()
        self.tab_config = self._build_config_tab()
        self.tab_log = self._build_log_tab()

    def _make_tree(self, parent: ttk.Frame, columns: list[tuple[str, str, int, bool]]) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=[c[0] for c in columns], show="headings", selectmode="browse")
        for cid, heading, width, stretch in columns:
            tree.heading(cid, text=heading, anchor="w")
            tree.column(cid, width=width, minwidth=40, stretch=stretch, anchor="w")
        ys = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        xs = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        return tree

    def _text_box(self, parent: ttk.Frame, height: int, readonly: bool,
                  wrap: Literal["none", "char", "word"] = "none") -> tk.Text:
        text = tk.Text(parent, height=height, font=self.f_mono, wrap=wrap, background=FIELD, foreground=INK,
                       insertbackground=INK, relief="flat", borderwidth=0, highlightthickness=1,
                       highlightbackground=LINE, highlightcolor=ACCENT, padx=8, pady=6, undo=not readonly)
        ys = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=ys.set)
        text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        if wrap == "none":
            xs = ttk.Scrollbar(parent, orient="horizontal", command=text.xview)
            text.configure(xscrollcommand=xs.set)
            xs.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        if readonly:
            text.configure(state="disabled")
        return text

    # ------------------------------------------------------------------ traps tab
    def _build_traps_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Traps")

        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        ttk.Label(bar, text="Filter").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._refilter())
        ttk.Entry(bar, textvariable=self.filter_var, width=34).pack(side="left", padx=(6, 0))
        self.trap_count_label = ttk.Label(bar, text="", style="Muted.TLabel")
        self.trap_count_label.pack(side="left", padx=(12, 0))
        ttk.Button(bar, text="Export CSV…", command=self.export_csv).pack(side="right")
        ttk.Button(bar, text="Clear", command=self.clear_traps).pack(side="right", padx=(0, 6))
        self.btn_pause = ttk.Button(bar, text="Pause feed", command=self.toggle_pause)
        self.btn_pause.pack(side="right", padx=(0, 6))

        pane = ttk.Panedwindow(tab, orient="vertical")
        pane.pack(side="top", fill="both", expand=True)
        top = ttk.Frame(pane)
        self.trap_tree = self._make_tree(top, [
            ("time", "Time", 80, False), ("source", "Source", 130, False), ("version", "Version", 64, False),
            ("user", "v3 user", 100, False), ("trap", "Trap", 240, True), ("severity", "Severity", 110, False),
            ("varbinds", "Variables", 420, True)])
        self.trap_tree.tag_configure("high", background=ALARM_TINT)
        self.trap_tree.tag_configure("medium", background=WARN_TINT)
        self.trap_tree.bind("<<TreeviewSelect>>", self._show_trap_detail)
        self.empty_traps = tk.Label(top, background=FIELD, foreground=MUTED, font=self.f_base, justify="center")
        self.empty_traps.place(relx=0.5, rely=0.5, anchor="center")
        pane.add(top, weight=3)

        bottom = ttk.Frame(pane, padding=(0, 8, 0, 0))
        self.trap_detail = self._text_box(bottom, height=9, readonly=True)
        pane.add(bottom, weight=1)
        return tab

    # ------------------------------------------------------------------ devices tab
    def _build_devices_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Devices")
        self.device_tree = self._make_tree(tab, [
            ("source", "Device", 170, False), ("count", "Traps", 80, False),
            ("last", "Last trap", 320, True), ("seen", "Last seen", 120, False), ("version", "Version", 80, False)])
        self.device_tree.tag_configure("high", background=ALARM_TINT)
        return tab

    # ------------------------------------------------------------------ rejected tab
    def _build_rejected_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Rejected")
        self.reject_tree = self._make_tree(tab, [
            ("time", "Time", 80, False), ("source", "Source", 140, False), ("kind", "Problem", 130, False),
            ("reason", "Reason", 700, True)])
        return tab

    # ------------------------------------------------------------------ test tab
    def _build_test_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(16, 14, 16, 14))
        self.nb.add(tab, text="Send test trap")
        form = ttk.Frame(tab)
        form.pack(side="top", anchor="nw", fill="x")
        form.columnconfigure(1, weight=1)
        pad: dict[str, Any] = {"pady": 5, "sticky": "w"}

        ttk.Label(form, text="Send to").grid(row=0, column=0, padx=(0, 16), **pad)
        dest = ttk.Frame(form)
        dest.grid(row=0, column=1, **pad)
        self.t_host = tk.StringVar(value="127.0.0.1")
        self.t_port = tk.StringVar(value="162")
        ttk.Entry(dest, textvariable=self.t_host, width=22).pack(side="left")
        ttk.Label(dest, text="port").pack(side="left", padx=(10, 6))
        ttk.Entry(dest, textvariable=self.t_port, width=7).pack(side="left")

        ttk.Label(form, text="SNMP version").grid(row=1, column=0, padx=(0, 16), **pad)
        ver = ttk.Frame(form)
        ver.grid(row=1, column=1, **pad)
        self.t_version = tk.StringVar(value="2c")
        for value, label in (("1", "v1"), ("2c", "v2c"), ("3", "v3")):
            ttk.Radiobutton(ver, text=label, value=value, variable=self.t_version,
                            command=self._update_test_form).pack(side="left", padx=(0, 14))

        ttk.Label(form, text="Notification").grid(row=2, column=0, padx=(0, 16), **pad)
        oid = ttk.Frame(form)
        oid.grid(row=2, column=1, **pad)
        self.t_oid = tk.StringVar(value="linkDown")
        ttk.Entry(oid, textvariable=self.t_oid, width=40).pack(side="left")
        ttk.Label(oid, text="OID or name, such as linkDown or coldStart", style="Small.TLabel").pack(
            side="left", padx=(10, 0))

        ttk.Label(form, text="Variables").grid(row=3, column=0, padx=(0, 16), pady=5, sticky="nw")
        vbf = ttk.Frame(form)
        vbf.grid(row=3, column=1, pady=5, sticky="w")
        self.t_varbinds = tk.Text(vbf, height=4, width=52, font=self.f_mono, background=FIELD, foreground=INK,
                                  relief="flat", highlightthickness=1, highlightbackground=LINE,
                                  highlightcolor=ACCENT, padx=6, pady=4, undo=True)
        self.t_varbinds.insert("1.0", "ifIndex.3 i 3\nifDescr.3 s eth3")
        self.t_varbinds.pack(side="top", anchor="w")
        ttk.Label(vbf, text="One per line: OID TYPE VALUE. Types: i integer, u gauge, c counter, C counter64, "
                            "t timeticks, a IP address, o OID, s string, x hex, n null",
                  style="Small.TLabel", wraplength=520, justify="left").pack(side="top", anchor="w", pady=(4, 0))

        self.t_inform = tk.BooleanVar(value=False)
        self.inform_check = ttk.Checkbutton(form, text="Send as an inform and wait for the acknowledgement",
                                            variable=self.t_inform)
        self.inform_check.grid(row=4, column=1, **pad)

        self.community_label = ttk.Label(form, text="Community")
        self.community_label.grid(row=5, column=0, padx=(0, 16), **pad)
        self.t_community = tk.StringVar(value="public")
        self.community_entry = ttk.Entry(form, textvariable=self.t_community, width=22, show="•")
        self.community_entry.grid(row=5, column=1, **pad)

        self.v3_frame = ttk.Labelframe(form, text="SNMPv3 credentials", padding=(12, 8))
        self.v3_frame.grid(row=6, column=0, columnspan=2, pady=(8, 5), sticky="w")
        self.t_user = tk.StringVar(value=CUSTOM_USER)
        ttk.Label(self.v3_frame, text="User").grid(row=0, column=0, padx=(0, 12), pady=4, sticky="w")
        self.user_combo = ttk.Combobox(self.v3_frame, textvariable=self.t_user, state="readonly", width=28)
        self.user_combo.grid(row=0, column=1, pady=4, sticky="w")
        self.user_combo.bind("<<ComboboxSelected>>", lambda _e: self._update_test_form())
        self.t_cname = tk.StringVar()
        self.t_auth = tk.StringVar(value="SHA256")
        self.t_akey = tk.StringVar()
        self.t_priv = tk.StringVar(value="AES")
        self.t_pkey = tk.StringVar()
        self.custom_rows: list[tk.Widget] = []
        rows = [("User name", ttk.Entry(self.v3_frame, textvariable=self.t_cname, width=30)),
                ("Authentication", ttk.Combobox(self.v3_frame, textvariable=self.t_auth, state="readonly", width=12,
                                                values=["NONE", *AUTH_PROTOCOLS])),
                ("Auth key", ttk.Entry(self.v3_frame, textvariable=self.t_akey, width=30, show="•")),
                ("Privacy", ttk.Combobox(self.v3_frame, textvariable=self.t_priv, state="readonly", width=12,
                                         values=["NONE", *PRIV_PROTOCOLS])),
                ("Priv key", ttk.Entry(self.v3_frame, textvariable=self.t_pkey, width=30, show="•"))]
        for r, (label, widget) in enumerate(rows, start=1):
            lab = ttk.Label(self.v3_frame, text=label)
            lab.grid(row=r, column=0, padx=(0, 12), pady=4, sticky="w")
            widget.grid(row=r, column=1, pady=4, sticky="w")
            self.custom_rows += [lab, widget]

        actions = ttk.Frame(tab)
        actions.pack(side="top", anchor="w", pady=(14, 0))
        self.btn_send = ttk.Button(actions, text="Send trap", style="Accent.TButton", command=self.send_test)
        self.btn_send.pack(side="left")
        self.test_result = ttk.Label(actions, text="", wraplength=700, justify="left")
        self.test_result.pack(side="left", padx=(14, 0))
        self._update_test_form()
        return tab

    # ------------------------------------------------------------------ config tab
    def _build_config_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Configuration")
        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        ttk.Button(bar, text="Save and restart", style="Accent.TButton",
                   command=self.save_and_restart).pack(side="right")
        ttk.Button(bar, text="Save", command=self.save_config).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="Check", command=self.validate_config).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="Reload from file", command=self.reload_config).pack(side="right", padx=(0, 6))
        self.config_msg = ttk.Label(bar, text="", style="Muted.TLabel", wraplength=640, justify="left")
        self.config_msg.pack(side="left", fill="x", expand=True)
        box = ttk.Frame(tab)
        box.pack(side="top", fill="both", expand=True)
        self.editor = self._text_box(box, height=20, readonly=False)
        self.editor.bind("<<Modified>>", self._on_editor_modified)
        return tab

    # ------------------------------------------------------------------ log tab
    def _build_log_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Log")
        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        ttk.Label(bar, text="Gateway messages, newest at the bottom", style="Muted.TLabel").pack(side="left")
        ttk.Button(bar, text="Clear log", command=self.clear_log).pack(side="right")
        box = ttk.Frame(tab)
        box.pack(side="top", fill="both", expand=True)
        self.log_text = self._text_box(box, height=20, readonly=True)
        self.log_text.tag_configure("WARNING", foreground=WARN_INK)
        self.log_text.tag_configure("ERROR", foreground=ALARM)
        self.log_text.tag_configure("CRITICAL", foreground=ALARM)
        return tab

    # ================================================================== config handling
    def _load_config_into_ui(self, first: bool = False) -> None:
        try:
            text = self.ctl.read_text()
        except OSError as exc:
            text = ""
            self._set_config_msg(f"Can't read {self.ctl.config_path}: {exc}", error=True)
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", text)
        self.editor.edit_reset()
        self.editor.edit_modified(False)
        try:
            cfg = self.ctl.load()
        except Exception as exc:
            self._set_config_msg(f"The configuration has a problem: {exc}", error=True)
            self.status_line.configure(text="Fix the configuration before starting the gateway.")
            if first:
                self.nb.select(self.tab_config)
            return
        self._refresh_from_config(cfg)
        if not first:
            self._set_config_msg("Loaded from file.")

    def _refresh_from_config(self, cfg: dict) -> None:
        """Update form defaults and hints from a loaded config (never touches the editor)."""
        snmp = cfg["snmp"]
        self.t_port.set(str(snmp["listen_port"]))
        if snmp.get("communities"):
            self.t_community.set(str(snmp["communities"][0]))
        names = [u.name for u in self.ctl.configured_users()]
        self.user_combo.configure(values=[*names, CUSTOM_USER])
        if names and self.t_user.get() not in names:
            self.t_user.set(names[0])
        self.empty_traps.configure(text=f"No traps yet.\nPoint your devices at this computer on UDP port "
                                        f"{snmp['listen_port']}, or use the Send test trap tab.")
        self._update_test_form()

    def _set_config_msg(self, text: str, error: bool = False) -> None:
        self.config_msg.configure(text=text, style="Error.TLabel" if error else "Muted.TLabel")

    def _on_editor_modified(self, _event=None) -> None:
        if self.editor.edit_modified():
            self._set_config_msg("Unsaved changes.")

    def _editor_text(self) -> str:
        return self.editor.get("1.0", "end-1c")

    def validate_config(self) -> bool:
        try:
            cfg = self.ctl.validate_text(self._editor_text())
        except ValueError as exc:
            self._set_config_msg(f"Not valid: {exc}", error=True)
            return False
        users = ", ".join(f"{u.name} ({u.level})" for u in cfg["snmp"]["v3"]["_users"]) or "none"
        self._set_config_msg(f"Valid. Listens on UDP {cfg['snmp']['listen_port']}, OPC UA {cfg['opcua']['mode']} "
                             f"mode, SNMPv3 users: {users}.")
        return True

    def save_config(self) -> bool:
        try:
            self.ctl.save_text(self._editor_text())
        except (ValueError, OSError) as exc:
            self._set_config_msg(f"Not saved: {exc}", error=True)
            return False
        self.editor.edit_modified(False)
        self._load_config_into_ui()
        self._set_config_msg("Saved. The previous version was kept as a .bak file."
                             + (" Restart the gateway to apply it." if self.ctl.running else ""))
        return True

    def save_and_restart(self) -> None:
        if not self.save_config():
            return
        if self.ctl.running:
            self.restart_pending = True
            self.stop()
        else:
            self.start()

    def reload_config(self) -> None:
        if self.editor.edit_modified() and not messagebox.askokcancel(
                "Reload configuration", "Discard your unsaved changes and reload the file?", parent=self.root):
            return
        self._load_config_into_ui()

    def open_config(self) -> None:
        if self.ctl.running:
            messagebox.showinfo("Open configuration", "Stop the gateway before opening another configuration.",
                                parent=self.root)
            return
        path = filedialog.askopenfilename(parent=self.root, title="Open configuration",
                                          filetypes=[("YAML", "*.yaml *.yml"), ("All files", "*")])
        if path:
            self.ctl.config_path = Path(path)
            self.config_label.configure(text=path)
            self._load_config_into_ui()

    # ================================================================== start / stop
    def start(self) -> None:
        if self.ctl.running:
            return
        try:
            self.ctl.start()
        except Exception as exc:
            self._show_state("error", "Not started")
            self.status_line.configure(text=f"Can't start: {exc}")
            messagebox.showerror("Can't start the gateway", str(exc), parent=self.root)
            return
        self.had_error = False
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="disabled")
        self._show_state("busy", "Starting…")

    def stop(self) -> None:
        if not self.ctl.running:
            return
        self.btn_stop.configure(state="disabled")
        self._show_state("busy", "Stopping…")
        threading.Thread(target=self.ctl.stop, name="gateway-stop", daemon=True).start()

    def _show_state(self, state: str, text: str) -> None:
        colour = {"running": ACCENT, "error": ALARM, "busy": WARN}.get(state, STOPPED)
        self.status_dot.itemconfigure(self.dot, fill=colour)
        self.status_text.configure(text=text)

    def _on_started(self, info: dict) -> None:
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self._show_state("running", "Running")
        versions = ", ".join(info.get("versions") or [])
        self.info_listen.configure(text=f"Listening on UDP {info.get('listen')} for SNMP {versions}")
        mode = "server" if info.get("mode") == "server" else "client, writing to"
        self.info_opcua.configure(text=f"OPC UA {mode} {info.get('opcua')}")
        if self.ctl.cfg:
            self._refresh_from_config(self.ctl.cfg)
        if self.ctl.started_at:
            self.status_line.configure(text=f"Running since {self.ctl.started_at:%H:%M:%S}")

    def _on_stopped(self) -> None:
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        if self.had_error:
            self._show_state("error", "Stopped after an error")
        else:
            self._show_state("stopped", "Stopped")
            self.status_line.configure(text="Gateway stopped.")
        self.info_listen.configure(text="")
        self.info_opcua.configure(text="")
        if self.restart_pending:
            self.restart_pending = False
            self.start()

    def _on_error(self, message: str) -> None:
        self.had_error = True
        self.restart_pending = False
        self.status_line.configure(text=message)
        self.root.after_idle(lambda: messagebox.showerror("Gateway stopped", message, parent=self.root))

    # ================================================================== event pump
    def _poll(self) -> None:
        if self.polling:          # a modal dialog can run the event loop re-entrantly
            return
        self.polling = True
        try:
            for _ in range(500):
                kind, payload = self.ctl.events.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass
        except Exception:
            logging.getLogger("snmp2opcua.gui").exception("UI update failed")
        finally:
            self.polling = False
        self.root.after(150, self._poll)

    def _handle(self, kind: str, payload) -> None:
        if kind == "trap":
            self._add_trap(payload)
        elif kind in ("rejected", "malformed"):
            self._add_rejection(kind, payload)
        elif kind == "log":
            self._append_log(*payload)
        elif kind == "started":
            self._on_started(payload)
        elif kind == "stopped":
            self._on_stopped()
        elif kind == "error":
            self._on_error(payload)
        elif kind == "test_result":
            self._on_test_result(*payload)

    def _tick(self) -> None:
        stats = self.ctl.stats()
        for key, (stripe, num, cap, caption) in self.tiles.items():
            value = stats.get(key)
            num.configure(text="–" if value is None else f"{value:,}")
            alert = TILE_ALERT.get(key) if value else None
            stripe.configure(background=alert or SURFACE)
            cap.configure(text=f"⚠ {caption}" if alert else caption, foreground=INK if alert else MUTED)
        self.root.after(1000, self._tick)

    # ================================================================== traps
    @staticmethod
    def _varbind_summary(d: dict) -> str:
        return ",  ".join(f"{v['name']} = {v['value']}" for v in d.get("varbinds", []))

    def _trap_values(self, d: dict) -> tuple:
        return (d["time"], d["source_ip"], d["version"], d.get("security_name", ""), d["trap_name"],
                f"{d['severity']}  {d['severity_label']}", self._varbind_summary(d))

    @staticmethod
    def _tag_for(d: dict) -> tuple[str, ...]:
        return ("high",) if d["severity"] >= 800 else ("medium",) if d["severity"] >= 600 else ()

    def _matches(self, d: dict) -> bool:
        needle = self.filter_var.get().strip().lower()
        if not needle:
            return True
        if "_search" not in d:
            d["_search"] = " ".join(str(x) for x in self._trap_values(d)).lower() + " " + d["trap_oid"]
        return needle in d["_search"]

    def _add_trap(self, d: dict) -> None:
        self.seq += 1
        d["_iid"] = f"t{self.seq}"
        if len(self.traps) == self.traps.maxlen:
            oldest = self.traps[0]
            self.trap_by_iid.pop(oldest["_iid"], None)
            if self.trap_tree.exists(oldest["_iid"]):
                self.trap_tree.delete(oldest["_iid"])
        self.traps.append(d)
        self.trap_by_iid[d["_iid"]] = d
        self._update_device(d)
        if self.paused:
            self.unseen += 1
            self.btn_pause.configure(text=f"Resume feed ({self.unseen} new)")
        elif self._matches(d):
            self.trap_tree.insert("", 0, iid=d["_iid"], values=self._trap_values(d), tags=self._tag_for(d))
        self._update_trap_count()

    def _update_trap_count(self) -> None:
        shown = len(self.trap_tree.get_children())
        total = len(self.traps)
        self.trap_count_label.configure(text=f"Showing {shown:,} of {total:,}" if total else "")
        if total:
            self.empty_traps.place_forget()
        else:
            self.empty_traps.place(relx=0.5, rely=0.5, anchor="center")

    def _refilter(self) -> None:
        self.trap_tree.delete(*self.trap_tree.get_children())
        for d in reversed(self.traps):
            if self._matches(d):
                self.trap_tree.insert("", "end", iid=d["_iid"], values=self._trap_values(d), tags=self._tag_for(d))
        self._update_trap_count()

    def _show_trap_detail(self, _event=None) -> None:
        sel = self.trap_tree.selection()
        d = self.trap_by_iid.get(sel[0]) if sel else None
        text = "" if d is None else json.dumps({k: v for k, v in d.items() if not k.startswith("_")},
                                               indent=2, ensure_ascii=False, default=str)
        self.trap_detail.configure(state="normal")
        self.trap_detail.delete("1.0", "end")
        self.trap_detail.insert("1.0", text)
        self.trap_detail.configure(state="disabled")

    def toggle_pause(self) -> None:
        self.paused = not self.paused
        if self.paused:
            self.unseen = 0
            self.btn_pause.configure(text="Resume feed")
        else:
            self.btn_pause.configure(text="Pause feed")
            self._refilter()

    def clear_traps(self) -> None:
        self.traps.clear()
        self.trap_by_iid.clear()
        self.trap_tree.delete(*self.trap_tree.get_children())
        self._show_trap_detail()
        self._update_trap_count()

    def export_csv(self) -> None:
        rows = [d for d in reversed(self.traps) if self._matches(d)]
        if not rows:
            messagebox.showinfo("Export CSV", "There are no traps to export.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Export traps", defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")], initialfile="traps.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["received_at", "source_ip", "version", "v3_user", "trap_oid", "trap_name",
                            "severity", "uptime", "varbinds_json"])
                for d in rows:
                    w.writerow([d["received_at"], d["source_ip"], d["version"], d.get("security_name", ""),
                                d["trap_oid"], d["trap_name"], d["severity"], d.get("uptime", ""),
                                json.dumps(d.get("varbinds", []), ensure_ascii=False, default=str)])
        except OSError as exc:
            messagebox.showerror("Export CSV", f"Couldn't write {path}: {exc}", parent=self.root)
            return
        self.status_line.configure(text=f"Exported {len(rows):,} traps to {path}")

    # ================================================================== devices / rejected / log
    def _update_device(self, d: dict) -> None:
        ip = d["source_ip"]
        dev = self.devices.setdefault(ip, {"count": 0})
        dev["count"] += 1
        values = (ip, f"{dev['count']:,}", d["trap_name"], d["time"], d["version"])
        tags = self._tag_for(d)[:1] if d["severity"] >= 800 else ()
        iid = "dev:" + ip
        if self.device_tree.exists(iid):
            self.device_tree.item(iid, values=values, tags=tags)
            self.device_tree.move(iid, "", 0)
        else:
            self.device_tree.insert("", 0, iid=iid, values=values, tags=tags)
        self.nb.tab(self.tab_devices, text=f"Devices ({len(self.devices)})")

    def _add_rejection(self, kind: str, p: dict) -> None:
        self.reject_count += 1
        label = "Rejected" if kind == "rejected" else "Unreadable packet"
        self.reject_tree.insert("", 0, values=(p.get("time", ""), p.get("source", ""), label, p.get("reason", "")))
        children = self.reject_tree.get_children()
        if len(children) > MAX_REJECTS:
            self.reject_tree.delete(*children[MAX_REJECTS:])
        self.nb.tab(self.tab_rejected, text=f"Rejected ({self.reject_count:,})")

    def _append_log(self, level: str, line: str) -> None:
        t = self.log_text
        at_bottom = t.yview()[1] >= 0.999
        t.configure(state="normal")
        t.insert("end", line + "\n", (level,))
        lines = int(t.index("end-1c").split(".")[0])
        if lines > MAX_LOG_LINES:
            t.delete("1.0", f"{lines - MAX_LOG_LINES}.0")
        t.configure(state="disabled")
        if at_bottom:
            t.see("end")

    def clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # ================================================================== test traps
    def _update_test_form(self) -> None:
        v = self.t_version.get()
        if v == "3":
            self.community_label.grid_remove()
            self.community_entry.grid_remove()
            self.v3_frame.grid()
        else:
            self.community_label.grid()
            self.community_entry.grid()
            self.v3_frame.grid_remove()
        self.inform_check.configure(state="disabled" if v == "1" else "normal")
        if v == "1":
            self.t_inform.set(False)
        custom = self.t_user.get() == CUSTOM_USER
        for w in self.custom_rows:
            if custom:
                w.grid()
            else:
                w.grid_remove()

    def _test_request(self) -> TrapRequest:
        try:
            port = int(self.t_port.get())
            if not 0 < port < 65536:
                raise ValueError
        except ValueError:
            raise ValueError("Port must be a number from 1 to 65535") from None
        varbinds = self.t_varbinds.get("1.0", "end-1c")
        parse_varbind_lines(varbinds)        # report mistakes before anything is sent
        req = TrapRequest(host=self.t_host.get().strip() or "127.0.0.1", port=port, version=self.t_version.get(),
                          trap_oid=self.t_oid.get().strip() or "linkDown", varbinds=varbinds,
                          inform=bool(self.t_inform.get()), community=self.t_community.get())
        if req.version == "3":
            name = self.t_user.get()
            if name != CUSTOM_USER:
                req.user = next((u for u in self.ctl.configured_users() if u.name == name), None)
            else:
                req.user = UsmUser.create(self.t_cname.get().strip(), self.t_auth.get(), self.t_akey.get() or None,
                                          self.t_priv.get(), self.t_pkey.get() or None)
        return req

    def send_test(self) -> None:
        if self.sending:
            return
        try:
            req = self._test_request()
        except ValueError as exc:
            self._on_test_result(False, str(exc))
            return
        self.sending = True
        self.btn_send.configure(state="disabled")
        self.test_result.configure(text="Sending…", style="Muted.TLabel")

        def work() -> None:
            try:
                result = (True, self.ctl.send_test_trap(req))
            except Exception as exc:
                result = (False, str(exc) or type(exc).__name__)
            self.ctl.events.put(("test_result", result))

        threading.Thread(target=work, name="send-test-trap", daemon=True).start()

    def _on_test_result(self, ok: bool, message: str) -> None:
        self.sending = False
        self.btn_send.configure(state="normal")
        self.test_result.configure(text=message if ok else f"Not sent: {message}",
                                   style="TLabel" if ok else "Error.TLabel")

    # ================================================================== closing
    def on_close(self) -> None:
        if self.editor.edit_modified() and not messagebox.askokcancel(
                "Close", "You have unsaved configuration changes. Close anyway?", parent=self.root):
            return
        if self.ctl.running:
            self.status_text.configure(text="Stopping…")
            self.root.update_idletasks()
            self.ctl.stop(timeout=8)
        self.ctl.close()
        self.root.destroy()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="snmp2opcua.gui", description="Desktop window for the SNMP trap gateway")
    ap.add_argument("-c", "--config", default="config.yaml", help="path to YAML config (default: config.yaml)")
    ap.add_argument("--start", action="store_true", help="start the gateway when the window opens")
    args = ap.parse_args(argv)
    if tk is None:
        print("Tkinter is not available in this Python installation.\n"
              "  Windows/macOS: install Python from python.org (Tkinter is included)\n"
              "  Debian/Ubuntu: sudo apt install python3-tk\n"
              "  Fedora/RHEL:   sudo dnf install python3-tkinter", file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    if sys.platform == "win32":   # crisp text on high-DPI screens
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    root.title("SNMP to OPC UA gateway")
    root.geometry("1200x780")
    root.minsize(920, 600)
    GatewayApp(root, GatewayController(args.config), autostart=args.start)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
