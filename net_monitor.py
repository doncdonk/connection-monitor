"""
NetMonitor - Realtime Network Connection Monitor
"""

import tkinter as tk
from tkinter import ttk
import psutil
import requests
import threading
import time
import socket
import queue
import json
import os
import sys
from datetime import datetime
from collections import OrderedDict

# ===== Config =====
REFRESH_INTERVAL = 3
GEO_CACHE_TTL    = 300
GEO_BATCH_SIZE   = 40
RISK_COUNTRIES   = {"CN", "RU", "KP", "IR", "BY"}

PRIVATE_PREFIXES = (
    "10.", "192.168.", "127.", "::1", "fe80",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)

if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

WHITELIST_FILE = os.path.join(APP_DIR, 'isp_whitelist.json')

def is_private(ip):
    return ip.startswith(PRIVATE_PREFIXES)

def country_flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return chr(0x1F1E6 + ord(cc[0].upper()) - 65) + chr(0x1F1E6 + ord(cc[1].upper()) - 65)

def fmt_elapsed(seconds):
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds//60)}m {int(seconds%60)}s"
    else:
        return f"{int(seconds//3600)}h {int((seconds%3600)//60)}m"

# ===== ISP Whitelist =====
def load_whitelist() -> list[str]:
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return [str(x) for x in data]
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return []

def save_whitelist(wl: list[str]):
    try:
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            json.dump(wl, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def isp_matches_whitelist(isp: str, wl: list[str]) -> bool:
    if not isp:
        return False
    isp_lower = isp.lower()
    return any(entry.lower() in isp_lower for entry in wl)

# ===== GeoIP Cache =====
class GeoCache:
    def __init__(self):
        self._data = {}
        self._ts   = {}
        self._lock = threading.Lock()

    def get(self, ip):
        with self._lock:
            if ip in self._data and time.time() - self._ts[ip] < GEO_CACHE_TTL:
                return self._data[ip]
        return None

    def set(self, ip, info):
        with self._lock:
            self._data[ip] = info
            self._ts[ip]   = time.time()

geo_cache = GeoCache()

def fetch_geo_batch(ips):
    try:
        payload = [{"query": ip, "fields": "query,country,countryCode,isp,status"}
                   for ip in ips]
        r = requests.post("http://ip-api.com/batch", json=payload, timeout=6)
        if r.status_code != 200:
            raise ValueError()
        result = {}
        for item in r.json():
            ip = item.get("query", "")
            if item.get("status") == "success":
                result[ip] = {
                    "country":     item.get("country", ""),
                    "countryCode": item.get("countryCode", ""),
                    "isp":         item.get("isp", ""),
                }
            else:
                result[ip] = {"country": "Unknown", "countryCode": "", "isp": ""}
        return result
    except Exception:
        return {ip: {"country": "Error", "countryCode": "", "isp": ""} for ip in ips}

# ===== Connection tracking =====
# key: (pid, remote_ip, remote_port, proto) -> first_seen timestamp
_conn_first_seen: dict = {}
_conn_lock = threading.Lock()

def get_elapsed(key):
    with _conn_lock:
        if key not in _conn_first_seen:
            _conn_first_seen[key] = time.time()
        return time.time() - _conn_first_seen[key]

def cleanup_first_seen(active_keys):
    with _conn_lock:
        for k in list(_conn_first_seen.keys()):
            if k not in active_keys:
                del _conn_first_seen[k]

# ===== Connection fetch =====
def get_connections():
    rows = []
    pid_name = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return rows

    active_keys = set()
    for c in conns:
        if not c.raddr:
            continue
        rip   = c.raddr.ip
        rport = c.raddr.port
        lport = c.laddr.port if c.laddr else 0
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        pid   = c.pid or 0

        if pid not in pid_name:
            try:
                pid_name[pid] = psutil.Process(pid).name()
            except Exception:
                pid_name[pid] = f"(PID {pid})"

        key = (pid, rip, rport, proto)
        active_keys.add(key)
        elapsed = get_elapsed(key)

        rows.append({
            "key":        key,
            "pid":        pid,
            "process":    pid_name[pid],
            "proto":      proto,
            "local_port": lport,
            "remote_ip":  rip,
            "remote_port":rport,
            "status":     c.status or "",
            "country":    "",
            "countryCode":"",
            "isp":        "",
            "country_disp": "",
            "private":    is_private(rip),
            "elapsed":    elapsed,
        })

    cleanup_first_seen(active_keys)
    return rows

# ===== Columns =====
# (label, key, width, anchor)
COLS = [
    ("Process",    "process",      160, "w"),
    ("PID",        "pid",           52, "center"),
    ("Proto",      "proto",         50, "center"),
    ("Remote IP",  "remote_ip",    140, "w"),
    ("Port",       "remote_port",   50, "center"),
    ("Status",     "status",        90, "w"),
    ("Elapsed",    "elapsed_disp",  75, "center"),
    ("Country",    "country_disp", 160, "w"),
    ("ISP",        "isp",          200, "w"),
]

# ===== App =====
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetMonitor  -  Realtime Connection Monitor")
        self.geometry("1340x760")
        self.configure(bg="#0d1117")
        self.resizable(True, True)

        self._rows    = []
        self._running = True
        self._geo_q   = queue.Queue()
        self._sort_col = None
        self._sort_rev = False
        self._group_mode = tk.BooleanVar(value=True)

        self._f_proc    = tk.StringVar()
        self._f_ip      = tk.StringVar()
        self._f_cc      = tk.StringVar()
        self._hide_priv = tk.BooleanVar(value=True)
        self._do_risk   = tk.BooleanVar(value=True)
        self._hide_wl   = tk.BooleanVar(value=True)

        self._isp_whitelist: list[str] = load_whitelist()

        # iid -> open/closed state for groups
        self._group_open: dict[str, bool] = {}

        self._build_style()
        self._build_toolbar()
        self._build_table()
        self._build_statusbar()

        for v in (self._f_proc, self._f_ip, self._f_cc):
            v.trace_add("write", lambda *_: self._refresh_table())

        threading.Thread(target=self._data_loop,  daemon=True).start()
        threading.Thread(target=self._geo_worker, daemon=True).start()
        self.protocol("WM_DELETE_WINDOW", self._quit)

    # ---------- Style ----------
    def _build_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        BG, FG, BG2 = "#0d1117", "#c9d1d9", "#161b22"
        s.configure(".", background=BG, foreground=FG, font=("Consolas", 10))
        s.configure("Treeview", background=BG, foreground=FG,
                    fieldbackground=BG, rowheight=24, borderwidth=0)
        s.configure("Treeview.Heading", background=BG2, foreground="#58a6ff",
                    relief="flat", font=("Consolas", 10, "bold"))
        s.map("Treeview", background=[("selected", "#1f6feb")])
        s.configure("TScrollbar", background=BG2, troughcolor=BG,
                    borderwidth=0, arrowsize=12)

    # ---------- Toolbar ----------
    def _build_toolbar(self):
        bar = tk.Frame(self, bg="#161b22", pady=7)
        bar.pack(fill="x")

        tk.Label(bar, text="  NetMonitor", bg="#161b22", fg="#58a6ff",
                 font=("Consolas", 13, "bold")).pack(side="left")

        def entry(var, placeholder, width):
            f = tk.Frame(bar, bg="#161b22")
            f.pack(side="left", padx=(12, 0))
            tk.Label(f, text=placeholder, bg="#161b22", fg="#6e7681",
                     font=("Consolas", 8)).pack(anchor="w")
            tk.Entry(f, textvariable=var, width=width,
                     bg="#21262d", fg="#e6edf3",
                     insertbackground="#58a6ff",
                     relief="flat", bd=4,
                     font=("Consolas", 10)).pack()

        entry(self._f_proc, "Process filter", 16)
        entry(self._f_ip,   "IP filter",       15)
        entry(self._f_cc,   "CC (e.g. US)",     7)

        def chk(text, var, fg="#8b949e"):
            tk.Checkbutton(bar, text=text, variable=var,
                           bg="#161b22", fg=fg,
                           activebackground="#161b22",
                           selectcolor="#21262d",
                           font=("Consolas", 9),
                           command=self._refresh_table).pack(side="left", padx=8)

        chk("Hide Private",    self._hide_priv)
        chk("Risk Highlight",  self._do_risk,  "#f85149")
        chk("Group by Process",self._group_mode)
        chk("Hide WL ISPs",    self._hide_wl,  "#e3b341")

        tk.Button(bar, text="ISP Whitelist",
                  bg="#21262d", fg="#e3b341",
                  activebackground="#30363d", activeforeground="#e3b341",
                  relief="flat", bd=0, padx=8, pady=2,
                  font=("Consolas", 9),
                  cursor="hand2",
                  command=self._show_wl_dialog).pack(side="left", padx=(4, 0))

        self._badge = tk.Label(bar, text="0 conns", bg="#161b22", fg="#3fb950",
                               font=("Consolas", 10, "bold"))
        self._badge.pack(side="right", padx=16)

    # ---------- Table ----------
    def _build_table(self):
        outer = tk.Frame(self, bg="#0d1117")
        outer.pack(fill="both", expand=True, padx=8, pady=(4, 0))

        cols = [c[0] for c in COLS]
        self._tv = ttk.Treeview(outer, columns=cols, show="headings",
                                selectmode="browse")
        for label, _, width, anchor in COLS:
            self._tv.heading(label, text=label,
                             command=lambda l=label: self._sort_by(l))
            self._tv.column(label, width=width, minwidth=40, anchor=anchor)

        vsb = ttk.Scrollbar(outer, orient="vertical",   command=self._tv.yview)
        hsb = ttk.Scrollbar(outer, orient="horizontal", command=self._tv.xview)
        self._tv.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tv.pack(fill="both", expand=True)

        # Tags
        self._tv.tag_configure("group",   background="#161b22", foreground="#58a6ff",
                               font=("Consolas", 10, "bold"))
        self._tv.tag_configure("risk",    background="#2d1111", foreground="#ff7b72")
        self._tv.tag_configure("private", background="#0d1117", foreground="#484f58")
        self._tv.tag_configure("even",    background="#0d1117", foreground="#c9d1d9")
        self._tv.tag_configure("odd",     background="#111820", foreground="#c9d1d9")

        self._tv.bind("<ButtonRelease-1>", self._on_click)
        self._tv.bind("<Button-3>",        self._on_right_click)

    # ---------- Statusbar ----------
    def _build_statusbar(self):
        self._status = tk.StringVar(value="Starting...")
        tk.Label(self, textvariable=self._status,
                 bg="#0d1117", fg="#3fb950",
                 font=("Consolas", 9), anchor="w").pack(fill="x", padx=10, pady=3)

    # ---------- Data loop ----------
    def _data_loop(self):
        while self._running:
            rows = get_connections()

            need = list(OrderedDict.fromkeys(
                r["remote_ip"] for r in rows
                if not r["private"] and geo_cache.get(r["remote_ip"]) is None
            ))
            if need:
                self._geo_q.put(need)

            for r in rows:
                g = geo_cache.get(r["remote_ip"])
                if g:
                    r.update(g)
                elif r["private"]:
                    r["country"]     = "Private"
                    r["countryCode"] = ""
                cc   = r.get("countryCode", "")
                flag = country_flag(cc)
                r["country_disp"] = f"{flag}  {r['country']}" if flag else r["country"]
                r["elapsed_disp"] = fmt_elapsed(r["elapsed"])

            self._rows = rows
            self.after(0, self._refresh_table)
            time.sleep(REFRESH_INTERVAL)

    # ---------- GeoIP worker ----------
    def _geo_worker(self):
        while self._running:
            try:
                ips = self._geo_q.get(timeout=2)
                need = [ip for ip in ips if geo_cache.get(ip) is None]
                for i in range(0, len(need), GEO_BATCH_SIZE):
                    batch = need[i:i+GEO_BATCH_SIZE]
                    for ip, info in fetch_geo_batch(batch).items():
                        geo_cache.set(ip, info)
            except queue.Empty:
                pass

    # ---------- Table render ----------
    def _refresh_table(self, *_):
        fp      = self._f_proc.get().lower()
        fi      = self._f_ip.get().lower()
        fc      = self._f_cc.get().upper()
        hide    = self._hide_priv.get()
        risk    = self._do_risk.get()
        grp     = self._group_mode.get()
        hide_wl = self._hide_wl.get()

        filtered = []
        wl_hidden = 0
        for r in self._rows:
            if hide and r["private"]:                              continue
            if fp and fp not in r["process"].lower():              continue
            if fi and fi not in r["remote_ip"].lower():            continue
            if fc and not r.get("countryCode","").startswith(fc):  continue
            if hide_wl and isp_matches_whitelist(r.get("isp",""), self._isp_whitelist):
                wl_hidden += 1
                continue
            filtered.append(r)

        self._tv.delete(*self._tv.get_children())

        if grp:
            self._render_grouped(filtered, risk)
        else:
            self._render_flat(filtered, risk)

        self._badge.config(text=f"{len(filtered)} conns")

        wl_part = f"  /  WL filtered: {wl_hidden}" if wl_hidden > 0 else ""
        self._status.set(
            f"Connections: {len(filtered)}{wl_part}  /  "
            f"Updated: {datetime.now().strftime('%H:%M:%S')}  /  "
            f"Interval: {REFRESH_INTERVAL}s"
        )

    def _row_vals(self, r):
        return tuple(r.get(key, "") for _, key, *_ in COLS)

    def _row_tag(self, r, i, risk):
        cc = r.get("countryCode", "")
        if risk and cc in RISK_COUNTRIES:
            return "risk"
        if r["private"]:
            return "private"
        return "odd" if i % 2 else "even"

    def _render_flat(self, rows, risk):
        for i, r in enumerate(rows):
            self._tv.insert("", "end", values=self._row_vals(r),
                            tags=(self._row_tag(r, i, risk),))

    def _render_grouped(self, rows, risk):
        groups: dict[str, list] = OrderedDict()
        for r in rows:
            groups.setdefault(r["process"], []).append(r)

        for proc, conns in groups.items():
            gid = f"__grp__{proc}"
            is_open = self._group_open.get(gid, True)

            header_vals = [""] * len(COLS)
            header_vals[0] = f"{'v' if is_open else '>'} {proc}  ({len(conns)})"
            self._tv.insert("", "end", iid=gid, values=tuple(header_vals),
                            tags=("group",))

            if is_open:
                for i, r in enumerate(conns):
                    vals = list(self._row_vals(r))
                    vals[0] = f"    {r['process']}"
                    self._tv.insert("", "end", values=tuple(vals),
                                    tags=(self._row_tag(r, i, risk),))

    def _on_click(self, event):
        iid = self._tv.identify_row(event.y)
        if iid and iid.startswith("__grp__"):
            self._group_open[iid] = not self._group_open.get(iid, True)
            self._refresh_table()

    # ---------- Right-click context menu ----------
    def _on_right_click(self, event):
        iid = self._tv.identify_row(event.y)
        if not iid or iid.startswith("__grp__"):
            return

        # 選択行のISPを取得
        self._tv.selection_set(iid)
        vals = self._tv.item(iid, "values")
        # ISP列は最後（インデックス8）
        isp_col_idx = next((i for i, c in enumerate(COLS) if c[1] == "isp"), None)
        if isp_col_idx is None:
            return
        isp = vals[isp_col_idx].strip()
        if not isp:
            return

        already = any(e.lower() in isp.lower() or isp.lower() in e.lower()
                      for e in self._isp_whitelist)

        menu = tk.Menu(self, tearoff=0, bg="#21262d", fg="#c9d1d9",
                       activebackground="#1f6feb", activeforeground="#ffffff",
                       relief="flat", bd=1)
        if already:
            menu.add_command(
                label=f'Remove "{isp}" from Whitelist',
                command=lambda: self._wl_remove_by_isp(isp)
            )
        else:
            menu.add_command(
                label=f'Add "{isp}" to Whitelist',
                command=lambda: self._wl_add(isp)
            )
        menu.add_separator()
        menu.add_command(label="Manage Whitelist...", command=self._show_wl_dialog)

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _wl_add(self, isp: str):
        if isp and isp not in self._isp_whitelist:
            self._isp_whitelist.append(isp)
            save_whitelist(self._isp_whitelist)
            self._refresh_table()

    def _wl_remove_by_isp(self, isp: str):
        # 部分一致で登録されているエントリを削除
        isp_lower = isp.lower()
        self._isp_whitelist = [
            e for e in self._isp_whitelist
            if e.lower() not in isp_lower and isp_lower not in e.lower()
        ]
        save_whitelist(self._isp_whitelist)
        self._refresh_table()

    # ---------- Whitelist dialog ----------
    def _show_wl_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("ISP Whitelist")
        dlg.geometry("420x380")
        dlg.configure(bg="#0d1117")
        dlg.resizable(False, True)
        dlg.grab_set()

        tk.Label(dlg, text="ISP Whitelist", bg="#0d1117", fg="#e3b341",
                 font=("Consolas", 12, "bold")).pack(anchor="w", padx=16, pady=(14, 4))
        tk.Label(dlg, text="部分一致（大文字小文字無視）でフィルタします",
                 bg="#0d1117", fg="#6e7681",
                 font=("Consolas", 8)).pack(anchor="w", padx=16)

        # リスト表示エリア
        list_frame = tk.Frame(dlg, bg="#0d1117")
        list_frame.pack(fill="both", expand=True, padx=16, pady=8)

        lb = tk.Listbox(list_frame, bg="#161b22", fg="#c9d1d9",
                        selectbackground="#1f6feb", selectforeground="#ffffff",
                        relief="flat", bd=0, font=("Consolas", 10),
                        activestyle="none")
        sb = ttk.Scrollbar(list_frame, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        lb.pack(fill="both", expand=True)

        def refresh_lb():
            lb.delete(0, "end")
            for entry in self._isp_whitelist:
                lb.insert("end", entry)

        refresh_lb()

        # 削除ボタン
        def remove_selected():
            sel = lb.curselection()
            if not sel:
                return
            idx = sel[0]
            self._isp_whitelist.pop(idx)
            save_whitelist(self._isp_whitelist)
            refresh_lb()
            self._refresh_table()

        # 追加エリア
        add_frame = tk.Frame(dlg, bg="#0d1117")
        add_frame.pack(fill="x", padx=16, pady=(0, 4))

        new_var = tk.StringVar()
        tk.Entry(add_frame, textvariable=new_var,
                 bg="#21262d", fg="#e6edf3",
                 insertbackground="#58a6ff",
                 relief="flat", bd=4,
                 font=("Consolas", 10),
                 width=28).pack(side="left", padx=(0, 6))

        def add_entry():
            val = new_var.get().strip()
            if val and val not in self._isp_whitelist:
                self._isp_whitelist.append(val)
                save_whitelist(self._isp_whitelist)
                refresh_lb()
                self._refresh_table()
                new_var.set("")

        tk.Button(add_frame, text="Add",
                  bg="#238636", fg="#ffffff",
                  activebackground="#2ea043", activeforeground="#ffffff",
                  relief="flat", bd=0, padx=10, pady=3,
                  font=("Consolas", 9), cursor="hand2",
                  command=add_entry).pack(side="left")

        # ボタンエリア
        btn_frame = tk.Frame(dlg, bg="#0d1117")
        btn_frame.pack(fill="x", padx=16, pady=(0, 12))

        tk.Button(btn_frame, text="Remove Selected",
                  bg="#b62324", fg="#ffffff",
                  activebackground="#d1282a", activeforeground="#ffffff",
                  relief="flat", bd=0, padx=10, pady=3,
                  font=("Consolas", 9), cursor="hand2",
                  command=remove_selected).pack(side="left")

        tk.Button(btn_frame, text="Close",
                  bg="#21262d", fg="#c9d1d9",
                  activebackground="#30363d", activeforeground="#ffffff",
                  relief="flat", bd=0, padx=10, pady=3,
                  font=("Consolas", 9), cursor="hand2",
                  command=dlg.destroy).pack(side="right")

    # ---------- Sort ----------
    def _sort_by(self, col_label):
        key = next((c[1] for c in COLS if c[0] == col_label), None)
        if not key:
            return
        self._sort_rev = (col_label == self._sort_col) and not self._sort_rev
        self._sort_col = col_label
        self._rows.sort(key=lambda r: str(r.get(key, "")), reverse=self._sort_rev)
        self._refresh_table()

    def _quit(self):
        self._running = False
        self.destroy()


if __name__ == "__main__":
    app = App()
    import os, sys
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    ico_path = os.path.join(base, 'netmonitor.ico')
    if os.path.exists(ico_path):
        app.iconbitmap(ico_path)
    app.mainloop()
