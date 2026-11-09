"""Shared logic for LLARP Control (GUI) and llarpctl (CLI). No GTK imports here.

llarpd is launched detached (own session, output appended to a log file, pid in a
state file), so it keeps running when the GUI closes or the SSH session ends, and
either front end can control a daemon the other one started.
"""

import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import fcntl
except ImportError:  # not on Windows (only the tests run there)
    fcntl = None

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "llarp-gui"
BOOTSTRAP_DIR = CONFIG_DIR / "bootstraps"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
STATE_FILE = CONFIG_DIR / "state.json"
LOG_FILE = CONFIG_DIR / "llarpd.log"
_HERE = Path(__file__).resolve().parent
# this repo's own bootstraps (kept current; upstream's contrib/bootstrap lists relays that are
# gone), or else those of an llarp checkout next to it
BUNDLED_DIR = next(
    (d for d in (_HERE / "bootstrap", _HERE.parent / "llarp" / "contrib" / "bootstrap") if d.is_dir()),
    _HERE / "bootstrap",
)

DEFAULT_SETTINGS = {
    "llarpd": shutil.which("llarpd") or "/usr/local/bin/llarpd",
    "config": str(Path.home() / ".llarpd" / "llarpd.ini"),
    "router_mode": False,
    # router mode behind NAT: the public IP/port the home router forwards to this machine
    "public_ip": "",
    "public_port": 1090,
    "log_level": "info",
    "exit_node": False,
    "use_exit": None,  # .loki exit to route internet traffic through (VPN), or None
    "exits": [],  # saved exits, most recent first: [{"address": str, "auth": str}]
    "bootstraps": [],  # [{"name": str, "file": str, "enabled": bool}]
}
LOG_LEVELS = ("trace", "debug", "info", "warn", "error")

STOP_TIMEOUT = 10  # seconds before SIGKILL

# stuck llarpd: its endpoint keeps failing to build paths ("no first hop candidate")
STUCK_AFTER = 600  # seconds of unbroken failures before it counts as stuck
STUCK_GAP = 60  # a break longer than this ends the streak
HEALTH_TAIL_BYTES = 2 << 20  # how much of the end of the log to look at
WATCHDOG_EVERY = 60  # seconds between checks in run_foreground
# VPN reconnect: restart llarpd when no traffic gets through the exit for this long, doubling
# the wait after each try that doesn't help
VPN_RECONNECT_AFTER = 180  # seconds
VPN_RECONNECT_MAX = 1800  # seconds
LOG_TIME_RE = re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")

# conf.d override written by this app (llarpd loads <data-dir>/conf.d/*.ini)
OVERRIDE_NAME = "50-llarp-gui.ini"
GUI_KEYFILE_NAME = "llarp-gui-address.private"

B32Z = "ybndrfg8ejkmcpqxot1uwisza345h769"
# endpoint log lines are prefixed with "<endpoint name>:<our address>.loki"
OWN_ADDR_RE = re.compile(r"[\w-]+:([" + B32Z + r"]{52}\.loki)\b")
# llarpd logs a few endpoint lines before its key is loaded; those show the zero key
ZERO_ADDR = B32Z[0] * 52 + ".loki"
RANGE_RE = re.compile(r"on range (\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
TUN_RE = re.compile(r"\bset (\S+) to have address\b")
EXIT_TROUBLE_RE = re.compile(r"cannot ensure path to exit|could not establish flow to|did not build path to")
# a .loki address or ONS name, optionally with an IP range: "x.loki" / "x.loki:10.0.0.0/8"
LOKI_NAME_RE = re.compile(r"^(?:[" + B32Z + r"]{52}|[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)\.loki$")
# logged when we've found an exit's introset and started a session handshake with it
B32Z_ADDR_RE = re.compile(r"^[" + B32Z + r"]{52}\.loki$")
EXIT_REACHED_RE = re.compile(r"OBContext:([" + B32Z + r"]{52}\.loki) send intro frame")
NO_RELAYS_RE = re.compile(r"no first hop candidate|did not build path, no hops available")
# the exit answered but we can't read it: almost always mismatched llarpd versions
UNREADABLE_EXIT_RE = re.compile(r"failed to decrypt message from ([" + B32Z + r"]{52}\.loki)")
# we reached the exit's introset and sent to it, but it never answered
SILENT_EXIT_RE = re.compile(r"OBContext:([" + B32Z + r"]{52}\.loki) half open state")
PATH_BUILT_RE = re.compile(r"\bis built, took\b")
NO_RELAYS_WINDOW = 20  # seconds
STARTUP_GRACE = 30  # seconds after start when "no relays yet" is normal
EXIT_TROUBLE_WINDOW = 90  # seconds an exit error stays relevant
# proving the exit passes traffic: TCP connects through the tunnel, cached this long
PROBE_TARGETS = (("1.1.1.1", 443), ("9.9.9.9", 443))
PROBE_TIMEOUT = 4  # seconds per target
PROBE_EVERY = 15  # seconds
EXIT_ANSWER_GRACE = 45  # seconds after start before a silent exit counts as trouble
IPV4_RANGE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
IFACE_RE = re.compile(r"^[\w.-]+$")
WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
# llarpd's own DNS listener (the default for Linux builds without systemd)
DEFAULT_DNS_BIND = "127.3.2.1:53"


def _detect_wsl():
    try:
        return "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        return False


# Running in the LLARP distro of LLARP Control for Windows: the Windows host reaches .loki
# through this distro (DNS on our WSL address, the tunnel range routed to us).
IS_WSL = _detect_wsl()


class LlarpError(Exception):
    """A user-facing failure; the message is shown as-is."""


# ---------------------------------------------------------------- bencode / keys


def bdecode(data, i=0):
    """Decode one bencoded value from data at offset i; returns (value, next_i)."""
    c = data[i : i + 1]
    if c == b"i":
        end = data.index(b"e", i)
        return int(data[i + 1 : end]), end + 1
    if c == b"l":
        i += 1
        out = []
        while data[i : i + 1] != b"e":
            v, i = bdecode(data, i)
            out.append(v)
        return out, i + 1
    if c == b"d":
        i += 1
        out = {}
        while data[i : i + 1] != b"e":
            k, i = bdecode(data, i)
            v, i = bdecode(data, i)
            out[k] = v
        return out, i + 1
    if c.isdigit():
        colon = data.index(b":", i)
        n = int(data[i:colon])
        start = colon + 1
        if start + n > len(data):
            raise ValueError("truncated string")
        return data[start : start + n], start + n
    raise ValueError(f"invalid bencode at offset {i}")


def b32z(pubkey: bytes) -> str:
    bits = val = 0
    out = ""
    for byte in pubkey:
        val = (val << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out += B32Z[(val >> bits) & 31]
    if bits:
        out += B32Z[(val << (5 - bits)) & 31]
    return out


def snode_address(pubkey: bytes) -> str:
    return b32z(pubkey) + ".snode"


def key_pubkey(path) -> bytes:
    """Public key from an llarpd secret key file: raw 64 bytes, a bencoded string,
    or a service identity dict whose "s" entry is the signing key."""
    data = Path(path).read_bytes()
    if len(data) != 64:
        value, _ = bdecode(data)
        data = value.get(b"s") if isinstance(value, dict) else value
    if not isinstance(data, bytes) or len(data) != 64:
        raise ValueError("unrecognised key file format")
    return data[32:]  # libsodium secret keys are seed || pubkey


def inspect_bootstrap(data: bytes):
    """Validate bootstrap file contents. Returns list of (address, netid) per RC."""
    value, end = bdecode(data)
    if data[end:].strip():
        raise ValueError("trailing data after bencoded value")
    rcs = value if isinstance(value, list) else [value]
    info = []
    for rc in rcs:
        if not isinstance(rc, dict) or b"k" not in rc or b"z" not in rc:
            raise ValueError("not a signed RouterContact")
        netid = rc.get(b"i", b"?")
        info.append((snode_address(rc[b"k"]), netid.decode(errors="replace")))
    if not info:
        raise ValueError("bootstrap list is empty")
    return info


def describe_bootstrap(entry):
    """(ok, one-line summary, per-router detail lines) for a bootstrap entry."""
    try:
        info = inspect_bootstrap(Path(entry["file"]).read_bytes())
    except Exception as e:  # noqa: BLE001 - any parse/read error is reported inline
        return False, f"invalid: {e}", []
    nets = ", ".join(sorted({n for _, n in info}))
    return True, f"{len(info)} router(s) · net: {nets} · {info[0][0]}", [f"{a}  ({n})" for a, n in info]


# ---------------------------------------------------------------- system helpers


def ini_get(path, section, key):
    """Value of an uncommented key in [section] of an ini file, or None."""
    current = None
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
        elif current == section and "=" in line and not line.startswith(("#", ";")):
            k, v = line.split("=", 1)
            if k.strip() == key:
                return v.strip()
    return None


def default_route_iface():
    try:
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout
    except OSError:
        return None
    m = re.search(r"\bdev (\S+)", out)
    return m.group(1) if m else None


def half_default_route_dev():
    """Interface the 0.0.0.0/1 route (what llarpd adds to send all traffic to an exit) uses."""
    try:
        out = subprocess.run(["ip", "-4", "route", "show", "0.0.0.0/1"], capture_output=True, text=True).stdout
    except OSError:
        return None
    m = re.search(r"\bdev (\S+)", out)
    return m.group(1) if m else None


RESOLV_CONF = Path("/etc/resolv.conf")
WSL_CONF = Path("/etc/wsl.conf")
PUBLIC_RESOLVERS = "# written by LLARP Control: DNS through Windows did not answer\nnameserver 9.9.9.9\nnameserver 1.1.1.1\n"


def ensure_wsl_dns():
    """Inside the LLARP distro: once setup has taken DNS over from WSL (generateResolvConf =
    false, because Windows' DNS forwarder didn't answer), keep /etc/resolv.conf in place.
    Returns True if it had to be rewritten."""
    try:
        if not re.search(r"^\s*generateResolvConf\s*=\s*false\b", WSL_CONF.read_text(), re.I | re.M):
            return False
        if RESOLV_CONF.exists() and RESOLV_CONF.read_text().strip():
            return False
        RESOLV_CONF.unlink(missing_ok=True)  # also a dangling symlink
        RESOLV_CONF.write_text(PUBLIC_RESOLVERS)
        return True
    except OSError:
        return False


def wsl_host_ip():
    """This WSL distro's address on the virtual network the Windows host shares with it."""
    return iface_ipv4(default_route_iface() or "eth0")


def wslpath(path):
    """C:\\x\\y -> /mnt/c/x/y (inside WSL)."""
    try:
        out = subprocess.run(["wslpath", "-u", path], capture_output=True, text=True).stdout.strip()
    except OSError:
        out = ""
    return out or "/mnt/" + path[0].lower() + path[2:].replace("\\", "/")


def is_public_ipv4(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global


def iface_ipv4(iface):
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface], capture_output=True, text=True).stdout
    except OSError:
        return None
    m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)/", out)
    return m.group(1) if m else None


def host_public_ipv4():
    """A public IPv4 assigned to one of this machine's interfaces (what llarpd's relay mode
    looks for), or None when the machine only has private addresses (behind NAT)."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True).stdout
    except OSError:
        return None
    return next((a for a in re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)/", out) if is_public_ipv4(a)), None)


def detect_public_ip():
    """Ask an outside service which IP our traffic comes from."""
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "llarp-gui"})
        with urllib.request.urlopen(req, timeout=10) as r:
            ip = r.read(64).decode().strip()
    except Exception as e:  # noqa: BLE001
        raise LlarpError(f"could not detect the public IP: {e}") from e
    if not is_public_ipv4(ip):
        raise LlarpError(f"got an unexpected answer while detecting the public IP: {ip!r}")
    return ip


# fatal startup errors llarpd logs before exiting
STARTUP_FAILED_RE = re.compile(r"failed to start up llarpd: (.+)")


def ip_forward_enabled():
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    except OSError:
        return False


def _proc_stat(pid):
    """(state, start time in clock ticks) of a process, or None if it doesn't exist."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return None
    return fields[0], int(fields[19])


def llarpd_pids():
    try:
        out = subprocess.run(["pgrep", "-x", "llarpd"], capture_output=True, text=True).stdout
    except OSError:
        return []
    return [int(p) for p in out.split()]


def _read_json(path, default):
    try:
        text = Path(path).read_text()
    except OSError:
        return default
    try:
        return json.loads(text)
    except ValueError:
        pass
    # older versions could leave a complete object followed by debris when two processes wrote
    # at once ("{...}}"): keep the first object rather than losing all state
    try:
        value, _ = json.JSONDecoder().raw_decode(text.lstrip())
        return value if isinstance(value, type(default)) else default
    except ValueError:
        return default


def _write_json(path, data):
    """Atomic replace through a temp file unique to this writer (several llarpctl processes,
    the GUIs and the Windows host write at the same time)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # may hold exit auth codes
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data, indent=2))
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


@contextlib.contextmanager
def _locked(path):
    """Exclusive lock around a read-modify-write of a JSON file (no-op where fcntl is missing)."""
    if fcntl is None:
        yield
        return
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(Path(path).with_name(f".{Path(path).name}.lock"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def format_uptime(seconds):
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return (f"{d}d " if d else "") + f"{h:d}:{m:02d}:{s:02d}"


# ---------------------------------------------------------------- controller


class Controller:
    """Settings, bootstraps, address, exit mode and the llarpd process."""

    def __init__(self):
        self.settings = {}
        self._settings_mtime = None
        self.reload()
        self._child = None  # Popen when llarpd was started by this process (to reap it)
        self._scan = {"ino": None, "pos": 0}
        self._reset_scan()

    # ---- settings

    def reload(self):
        settings = dict(DEFAULT_SETTINGS)
        settings.update(_read_json(SETTINGS_FILE, {}))
        self.settings = settings
        self._settings_mtime = self._mtime(SETTINGS_FILE)

    def reload_if_changed(self):
        """Pick up changes made by another front end. Returns True if reloaded."""
        if self._mtime(SETTINGS_FILE) != self._settings_mtime:
            self.reload()
            return True
        return False

    def save(self):
        _write_json(SETTINGS_FILE, self.settings)
        self._settings_mtime = self._mtime(SETTINGS_FILE)

    @staticmethod
    def _mtime(path):
        try:
            return Path(path).stat().st_mtime_ns
        except OSError:
            return None

    def set_setting(self, key, value):
        if key not in DEFAULT_SETTINGS or key == "bootstraps":
            raise LlarpError(f"unknown setting: {key}")
        if key == "log_level" and value not in LOG_LEVELS:
            raise LlarpError(f"log_level must be one of: {', '.join(LOG_LEVELS)}")
        if key == "public_ip":
            value = (value or "").strip()
            if value and not is_public_ipv4(value):
                raise LlarpError(f"{value} is not a public IPv4 address")
        if key == "public_port":
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise LlarpError("public_port must be a number") from None
            if not 1 <= value <= 65535:
                raise LlarpError("public_port must be between 1 and 65535")
        if key == "router_mode":
            self.set_router_mode(bool(value))
            return
        if key == "exit_node":
            self.set_exit_node(bool(value))
            return
        self.settings[key] = value
        self.save()

    # ---- log / notes

    def note(self, msg):
        """Append a control message to the shared log so every front end sees it."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"[ctl {time.strftime('%H:%M:%S')}] {msg}\n")

    def _reset_scan(self):
        self._scan.update(
            address=None, range=None, tun=None, exit_trouble=None, no_relays=None, path_built=None,
            exits_reached=set(), unreadable=None, silent=None,
        )

    def scan_log(self):
        """Incrementally scan this run's log for our address and tunnel range."""
        sc = self._scan
        try:
            st = LOG_FILE.stat()
        except OSError:
            return
        if st.st_ino != sc["ino"] or st.st_size < sc["pos"]:
            sc.update(ino=st.st_ino, pos=0)
            self._reset_scan()
        if st.st_size == sc["pos"]:
            return
        with open(LOG_FILE, "rb") as f:
            f.seek(sc["pos"])
            chunk = f.read()
        # only consume complete lines
        cut = chunk.rfind(b"\n") + 1
        sc["pos"] += cut
        for line in chunk[:cut].decode(errors="replace").splitlines():
            if line.startswith("[ctl"):
                continue
            m = OWN_ADDR_RE.search(line)
            if m and m.group(1) != ZERO_ADDR:
                sc["address"] = m.group(1)
            m = RANGE_RE.search(line)
            if m:
                sc["range"] = m.group(1)
            m = TUN_RE.search(line)
            if m:
                sc["tun"] = m.group(1)
            if EXIT_TROUBLE_RE.search(line):
                sc["exit_trouble"] = (time.time(), line.strip())
            # OBContext (per-exit) path builders log this transiently; only our endpoint matters
            if NO_RELAYS_RE.search(line) and "OBContext:" not in line:
                sc["no_relays"] = time.time()
            if PATH_BUILT_RE.search(line):
                sc["path_built"] = time.time()
            m = UNREADABLE_EXIT_RE.search(line)
            if m:
                sc["unreadable"] = (time.time(), m.group(1))
            m = SILENT_EXIT_RE.search(line)
            if m:
                sc["silent"] = (time.time(), m.group(1))
            m = EXIT_REACHED_RE.search(line)
            if m:
                sc["exits_reached"].add(m.group(1))

    @property
    def log_address(self):
        self.scan_log()
        return self._scan["address"]

    @property
    def tun_range(self):
        self.scan_log()
        return self._scan["range"]

    # ---- state / process

    def state(self):
        return _read_json(STATE_FILE, {})

    def _update_state(self, **changes):
        with _locked(STATE_FILE):  # don't lose another process's change made in between
            st = self.state()
            st.update(changes)
            _write_json(STATE_FILE, st)
        return st

    def pid(self):
        """pid of the llarpd we manage, or None if it isn't running."""
        if self._child is not None:
            self._child.poll()  # reap if it exited
        st = self.state()
        pid = st.get("pid")
        info = _proc_stat(pid) if pid else None
        if info is None or info[0] == "Z":
            return None
        if st.get("proc_start") is not None and info[1] != st["proc_start"]:
            return None  # pid was reused by something else
        return pid

    def is_running(self):
        return self.pid() is not None

    def unmanaged_pids(self):
        """llarpd processes running that this app didn't start."""
        mine = self.pid()
        return [p for p in llarpd_pids() if p != mine]

    def fingerprint(self):
        """Hash of everything that affects how llarpd runs, to detect pending changes."""
        try:
            override = self.override_file().read_text()
        except OSError:
            override = ""
        relevant = {k: self.settings.get(k) for k in ("llarpd", "config", "router_mode", "log_level", "exit_node")}
        if self.settings.get("router_mode"):
            relevant["public"] = [self.settings.get("public_ip"), self.settings.get("public_port")]
        relevant["vpn"] = [self.settings.get("use_exit"), self.exit_auth(self.settings.get("use_exit"))]
        relevant["bootstraps"] = self.enabled_bootstrap_files()
        relevant["override"] = override
        return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()

    def changes_pending(self):
        return self.is_running() and self.state().get("fingerprint") != self.fingerprint()

    def status(self):
        pid = self.pid()
        st = self.state()
        addr, kind = self.address()
        return {
            "running": pid is not None,
            "pid": pid,
            "uptime": (time.time() - st["started_at"]) if pid and st.get("started_at") else None,
            "address": addr,
            "address_kind": kind,
            "exit_node": bool(self.settings.get("exit_node")),
            "router_mode": bool(self.settings.get("router_mode")),
            "changes_pending": pid is not None and st.get("fingerprint") != self.fingerprint(),
            "tun_range": self.tun_range if pid else None,
            "vpn": self.vpn_status(),
            "bootstraps_enabled": len(self.enabled_bootstrap_files()),
            "unmanaged_pids": self.unmanaged_pids(),
            "health": self.path_health() if pid else {"stuck": False, "for": 0},
        }

    def startup_problem(self):
        s = self.settings
        if not os.access(s["llarpd"], os.X_OK):
            return f"llarpd binary not found or not executable: {s['llarpd']}"
        if not Path(s["config"]).exists():
            return f"config file not found: {s['config']} (generate one with: llarpctl generate-config)"
        if (
            s.get("router_mode")
            and not s.get("public_ip")
            and not host_public_ipv4()
            and not self._main_config_sets("bind", "inbound")
            and not os.environ.get("LLARP_BIND_UDP_INBOUND")
        ):
            return (
                "Router mode needs a public IP address, but this machine only has private ones "
                "(it's behind a router/NAT). Either set your public IP under Settings → Public IP "
                "(llarpctl set public_ip auto) and forward UDP port "
                f"{s.get('public_port') or 1090} on your router to this machine, or run router mode on a VPS."
            )
        return None

    def exit_reason(self):
        """Why the last run of llarpd failed to start, if it logged a reason."""
        try:
            text = LOG_FILE.read_text(errors="replace")
        except OSError:
            return None
        m = None
        for m in STARTUP_FAILED_RE.finditer(text):
            pass
        if not m:
            return None
        reason = m.group(1).strip()
        if "no inbound links configured" in reason:
            reason += (
                " - router mode needs a public IP. Behind a home router, set it under "
                "Settings → Public IP and forward the UDP port to this machine."
            )
        return reason

    def _command_and_env(self):
        s = self.settings
        cmd = [s["llarpd"]]
        if s.get("router_mode"):
            cmd.append("--router")
        cmd.append(s["config"])

        env = dict(os.environ)
        files = self.enabled_bootstrap_files()
        if files:
            env["LLARP_BOOTSTRAP_FILEPATHS"] = ",".join(files)
        else:
            env.pop("LLARP_BOOTSTRAP_FILEPATHS", None)
        if s.get("log_level"):
            env["LLARP_LOG_LEVEL"] = s["log_level"]
        if s.get("router_mode") and s.get("public_ip"):
            # behind NAT: listen on our LAN address and advertise the forwarded public one
            port = int(s.get("public_port") or 1090)
            lan_ip = iface_ipv4(default_route_iface() or "")
            env["LLARP_BIND_UDP_INBOUND"] = f"{lan_ip}:{port}" if lan_ip else f":{port}"
            env["LLARP_PUBLIC_IP"] = s["public_ip"]
            env["LLARP_PUBLIC_PORT"] = str(port)
        exit_node = s.get("exit_node", False)
        env["LLARP_BECOME_EXIT_NODE"] = "1" if exit_node else "0"
        if exit_node:
            env["LLARP_PUBLISH_INTROSET"] = "1"  # exits must be reachable
        use_exit = s.get("use_exit")
        if use_exit:
            env["LLARP_USE_EXITS"] = use_exit
            auth = self.exit_auth(use_exit)
            if auth:
                env["LLARP_EXIT_AUTHS"] = f"{use_exit}:{auth}"
        return cmd, env, files

    def _launch(self):
        if self.is_running():
            raise LlarpError(f"llarpd is already running (pid {self.pid()})")
        problem = self.startup_problem()
        if problem:
            raise LlarpError(problem)
        self._write_override()
        self.update_bundled_bootstraps()
        if IS_WSL and ensure_wsl_dns():
            self.note(f"{RESOLV_CONF} was missing; wrote public resolvers (Quad9, Cloudflare)")
        cmd, env, files = self._command_and_env()

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if LOG_FILE.exists():
            LOG_FILE.replace(LOG_FILE.with_suffix(".log.1"))
        self.note("starting: " + " ".join(shlex.quote(c) for c in cmd))
        self.note("bootstraps: " + (", ".join(files) if files else "none (llarpd uses its config / built-in fallbacks)"))
        if self.settings.get("exit_node"):
            self.note("exit node mode on")
        if env.get("LLARP_PUBLIC_IP"):
            self.note(f"router behind NAT: listening on {env['LLARP_BIND_UDP_INBOUND']}, "
                      f"advertising {env['LLARP_PUBLIC_IP']}:{env['LLARP_PUBLIC_PORT']}")
        if self.settings.get("use_exit"):
            self.note(f"VPN: routing internet traffic through {self.settings['use_exit']}")

        data_dir = self.data_dir()
        log = open(LOG_FILE, "ab")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=env,
                cwd=str(data_dir) if data_dir.is_dir() else None,
                start_new_session=True,
            )
        except OSError as e:
            raise LlarpError(f"failed to start llarpd: {e}") from e
        finally:
            log.close()
        self._child = proc
        self._update_state(
            pid=proc.pid,
            proc_start=(_proc_stat(proc.pid) or (None, None))[1],
            started_at=time.time(),
            cmd=cmd,
            fingerprint=self.fingerprint(),
            stop_requested_at=None,
        )
        return proc

    def start(self):
        """Start llarpd in the background. Returns its pid."""
        proc = self._launch()
        time.sleep(0.3)
        if proc.poll() is not None:
            raise LlarpError(f"llarpd exited immediately with code {proc.returncode}; see the log")
        return proc.pid

    def run_foreground(self):
        """Run llarpd and wait for it (for systemd and LLARP Control for Windows). Returns its
        exit code. Watchdog: a llarpd stuck unable to build paths (see path_health) is
        restarted, since it otherwise keeps running, and keeps advertising itself, uselessly."""
        current = {"proc": self._launch(), "stopping": False}

        def forward(sig, _frame):
            current["stopping"] = True
            self._update_state(stop_requested_at=time.time())
            current["proc"].send_signal(sig)

        signal.signal(signal.SIGTERM, forward)
        signal.signal(signal.SIGINT, forward)
        next_check = time.time() + WATCHDOG_EVERY
        vpn_watch = {"bad_since": None, "reconnects": 0}
        while True:
            try:
                code = current["proc"].wait(timeout=5)
            except subprocess.TimeoutExpired:
                if time.time() < next_check or current["stopping"]:
                    continue
                next_check = time.time() + WATCHDOG_EVERY
                reason = None
                health = self.path_health()
                if health["stuck"]:
                    reason = (f"llarpd has failed to build paths for {int(health['for']) // 60} min "
                              "(no relays to use as first hop)")
                else:
                    reason = self.vpn_needs_reconnect(vpn_watch)
                if not reason:
                    continue
                self.note(f"watchdog: {reason}; restarting it")
                current["proc"].terminate()
                try:
                    current["proc"].wait(timeout=STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    current["proc"].kill()
                    current["proc"].wait()
                if current["stopping"]:
                    break
                current["proc"] = self._launch()
                continue
            self.note(f"llarpd exited with code {code}")
            return code
        code = current["proc"].returncode
        self.note(f"llarpd exited with code {code}")
        return code

    def vpn_needs_reconnect(self, watch, now=None):
        """Watchdog part for the VPN: llarpd can keep a dead session to an exit (e.g. after the
        exit restarted) and never set up a new one. Returns a reason to restart llarpd, or None.

        `watch` ({"bad_since", "reconnects"}) carries state between calls. Restarts after
        VPN_RECONNECT_AFTER seconds without traffic getting through, then waits twice as long
        after each further try (up to VPN_RECONNECT_MAX); a working VPN resets that."""
        now = time.time() if now is None else now
        self.reload_if_changed()  # the VPN may have been turned off or changed meanwhile
        use_exit = self.settings.get("use_exit")
        state = self.vpn_status()["state"] if use_exit else "off"
        if state == "on" or state == "off":
            watch.update(bad_since=None, reconnects=0)
            return None
        if state not in ("connecting", "trouble"):  # stopped / pending (restart to apply)
            watch["bad_since"] = None
            return None
        if watch["bad_since"] is None:
            watch["bad_since"] = now
            return None
        wait = min(VPN_RECONNECT_MAX, VPN_RECONNECT_AFTER * 2 ** watch["reconnects"])
        if now - watch["bad_since"] < wait:
            return None
        minutes = int(now - watch["bad_since"]) // 60
        watch["bad_since"] = None
        watch["reconnects"] += 1
        return f"no traffic has got through {use_exit} for {minutes} min (reconnect #{watch['reconnects']})"

    def path_health(self):
        """{"stuck", "for"}: llarpd's own endpoint has failed to build paths ("no first hop
        candidate") with no break longer than STUCK_GAP, for at least STUCK_AFTER seconds.
        A healthy node only logs that during its first seconds. Reads the end of the log only."""
        result = {"stuck": False, "for": 0}
        try:
            size = LOG_FILE.stat().st_size
            with open(LOG_FILE, "rb") as f:
                f.seek(max(0, size - HEALTH_TAIL_BYTES))
                text = f.read().decode(errors="replace")
        except OSError:
            return result
        streak_start = last = None
        for line in text.splitlines():
            if "OBContext:" in line or not NO_RELAYS_RE.search(line):
                continue
            m = LOG_TIME_RE.match(line)
            if not m:
                continue
            try:
                t = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                continue
            if last is None or t - last > STUCK_GAP:
                streak_start = t
            last = t
        if last is None or time.time() - last > STUCK_GAP:
            return result  # not failing right now
        result["for"] = last - streak_start
        result["stuck"] = result["for"] >= STUCK_AFTER
        return result

    def request_stop(self):
        """Send SIGTERM without waiting. Returns False if it wasn't running."""
        pid = self.pid()
        if pid is None:
            return False
        self._update_state(stop_requested_at=time.time())
        self.note("stopping llarpd")
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        return True

    def enforce_stop_timeout(self):
        """SIGKILL llarpd if a stop was requested more than STOP_TIMEOUT ago."""
        pid = self.pid()
        asked = self.state().get("stop_requested_at")
        if pid and asked and time.time() - asked > STOP_TIMEOUT:
            self.note("llarpd did not exit in time, sending SIGKILL")
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def stop(self, timeout=STOP_TIMEOUT):
        """Stop llarpd and wait for it to exit. Returns False if it wasn't running."""
        if not self.request_stop():
            return False
        deadline = time.time() + timeout
        while self.is_running() and time.time() < deadline:
            time.sleep(0.2)
        if self.is_running():
            self._update_state(stop_requested_at=0)  # make the timeout fire now
            self.enforce_stop_timeout()
            time.sleep(0.5)
        if not self.is_running():
            self.note("llarpd stopped")
        return True

    def stopping(self):
        return self.is_running() and bool(self.state().get("stop_requested_at"))

    def restart(self):
        self.stop()
        return self.start()

    # ---- paths & address

    def data_dir(self):
        """llarpd's data dir: [router] data-dir, else the config file's directory."""
        cfg = Path(self.settings["config"])
        try:
            configured = ini_get(cfg, "router", "data-dir")
        except OSError:
            configured = None
        return Path(configured).expanduser() if configured else cfg.parent

    def override_file(self):
        return self.data_dir() / "conf.d" / OVERRIDE_NAME

    def keyfile_path(self):
        """The .loki key file llarpd will use, from the main config or our override."""
        for ini in (Path(self.settings["config"]), self.override_file()):
            try:
                value = ini_get(ini, "network", "keyfile")
            except OSError:
                continue
            if value:
                path = Path(value).expanduser()
                return path if path.is_absolute() else self.data_dir() / path
        return None

    def persistent_address(self):
        """Address derived from on-disk keys, or None if llarpd picks a random one each run."""
        try:
            if self.settings.get("router_mode"):
                key = self.data_dir() / "identity.key"
                return snode_address(key_pubkey(key)) if key.exists() else None
            key = self.keyfile_path()
            return b32z(key_pubkey(key)) + ".loki" if key and key.exists() else None
        except (OSError, ValueError):
            return None

    def address(self):
        """(address, kind) where kind is "permanent", "temporary", or a reason it's unknown."""
        addr = self.persistent_address()
        if addr:
            return addr, "permanent"
        running = self.is_running()
        if running and self.log_address:
            return self.log_address, "temporary"
        if running:
            return None, "waiting for llarpd"
        if self.settings.get("router_mode") or self.keyfile_path():
            return None, "created on first start"
        return None, "random, assigned at each start"

    def _override_has_keyfile(self):
        try:
            return bool(ini_get(self.override_file(), "network", "keyfile"))
        except OSError:
            return False

    def _main_config_sets(self, section, key):
        try:
            return ini_get(self.settings["config"], section, key) is not None
        except OSError:
            return False

    def _write_override(self, persist=None):
        """Regenerate our conf.d override from settings: a persistent key file (if enabled)
        and, while the VPN is on, blackhole-routes=false.

        llarpd's VPN "kill switch" puts a blackhole default route in the kernel's *local*
        table. On machines with any extra policy-routing rules (Tailscale, other VPNs, docker
        setups...) the local table is looked up on its own before main, so that blackhole
        swallows everything - including llarpd's own traffic to its relays - and the VPN can
        never connect. Turning it off keeps the normal more-specific routes in charge.

        Inside WSL (LLARP Control for Windows) a client also answers DNS on the distro's
        address, so Windows can resolve .loki names through it."""
        if persist is None:
            persist = self._override_has_keyfile()
        network, dns = [], []
        if persist:
            network.append(f"keyfile={self.data_dir() / GUI_KEYFILE_NAME}")
        if self.settings.get("use_exit") and not self._main_config_sets("network", "blackhole-routes"):
            network.append("blackhole-routes=false")
        if IS_WSL and not self.settings.get("router_mode"):
            ip = wsl_host_ip()
            if ip:
                if not self._main_config_sets("dns", "bind"):
                    dns.append(f"bind={DEFAULT_DNS_BIND}")  # an explicit bind replaces the default
                dns.append(f"bind={ip}:53")
        override = self.override_file()
        try:
            if network or dns:
                override.parent.mkdir(parents=True, exist_ok=True)
                text = "# written by LLARP Control; regenerated on every change\n"
                if network:
                    text += "[network]\n" + "\n".join(network) + "\n"
                if dns:
                    text += "[dns]\n" + "\n".join(dns) + "\n"
                if not override.exists() or override.read_text() != text:
                    override.write_text(text)
            else:
                override.unlink(missing_ok=True)
        except OSError as e:
            raise LlarpError(f"could not update {override}: {e}") from e

    def set_persistent_address(self, enabled):
        """Give llarpd a persistent key file (via our conf.d override), or stop doing so."""
        if not enabled and self.settings.get("exit_node"):
            raise LlarpError("an exit node needs a permanent address; turn off exit mode first")
        self._write_override(persist=enabled)
        if enabled:
            self.note(f"persistent address enabled: keyfile={self.data_dir() / GUI_KEYFILE_NAME}")
        else:
            self.note("persistent address disabled")

    # ---- modes

    def set_router_mode(self, enabled):
        if enabled and self.settings.get("exit_node"):
            raise LlarpError("router mode can't be combined with exit mode; turn off exit mode first")
        if enabled and self.settings.get("use_exit"):
            raise LlarpError("router mode can't use an exit as a VPN; turn off the VPN first")
        self.settings["router_mode"] = enabled
        self.save()

    def set_exit_node(self, enabled):
        """Returns a list of side effects worth telling the user about."""
        notes = []
        if enabled and self.settings.get("router_mode"):
            raise LlarpError("exit mode runs on a client endpoint; turn off router mode first")
        if enabled and self.settings.get("use_exit"):
            raise LlarpError("can't be an exit node while using one as a VPN; turn off the VPN first")
        if enabled and not self.keyfile_path():
            # an exit with a throwaway address is useless to anyone trying to use it
            self.set_persistent_address(True)
            notes.append("enabled a permanent address (exit nodes need one)")
        self.settings["exit_node"] = enabled
        self.save()
        self.note(f"exit node {'enabled' if enabled else 'disabled'}")
        return notes

    # ---- VPN through an exit

    @staticmethod
    def normalize_exit(address):
        address = address.strip().lower()
        if address and not address.endswith(".loki") and "." not in address:
            address += ".loki"
        if not LOKI_NAME_RE.match(address):
            raise LlarpError(f"'{address}' is not a .loki address or name")
        return address

    def saved_exits(self):
        return self.settings["exits"]

    def _saved_exit(self, address):
        return next((e for e in self.settings["exits"] if e["address"] == address), None)

    def exit_auth(self, address):
        entry = self._saved_exit(address) if address else None
        return entry.get("auth") if entry else None

    def remember_exit(self, address, auth=None):
        """Add/move an exit to the top of the saved list; auth=None keeps its code, "" clears it."""
        address = self.normalize_exit(address)
        if auth is not None and ("," in auth or not auth.isprintable()):
            raise LlarpError("auth code can't contain commas or control characters")
        entry = self._saved_exit(address) or {"address": address, "auth": ""}
        if auth is not None:
            entry["auth"] = auth
        self.settings["exits"] = [entry] + [e for e in self.settings["exits"] if e is not entry]
        self.save()
        return entry

    def forget_exit(self, address):
        address = self.normalize_exit(address)
        if self.settings.get("use_exit") == address:
            raise LlarpError("that exit is in use; turn the VPN off first")
        entry = self._saved_exit(address)
        if entry is None:
            raise LlarpError(f"{address} isn't saved")
        self.settings["exits"].remove(entry)
        self.save()

    def set_vpn(self, address, auth=None):
        """Route internet traffic through an exit (address), or stop (None).
        Takes effect when llarpd (re)starts."""
        if address is None:
            if self.settings.get("use_exit"):
                self.note(f"VPN off (was {self.settings['use_exit']})")
            self.settings["use_exit"] = None
            self.save()
            self._write_override()
            return None
        if self.settings.get("router_mode"):
            raise LlarpError("the VPN runs on a client endpoint; turn off router mode first")
        if self.settings.get("exit_node"):
            raise LlarpError("can't use an exit as a VPN while being an exit node; turn off exit mode first")
        own, _ = self.address()
        if own and own == self.normalize_exit(address):
            raise LlarpError("that's this node's own address")
        entry = self.remember_exit(address, auth)
        self.settings["use_exit"] = entry["address"]
        self.save()
        self._write_override()
        self.note(f"VPN on via {entry['address']}")
        return entry["address"]

    def probe_exit(self, use_exit):
        """True if a TCP connection through the tunnel (to a well-known public address) works.
        Run at most every PROBE_EVERY seconds per llarpd run; the result is kept in the state
        file so every front end shares it."""
        st = self.state()
        cached = st.get("exit_probe") or {}
        now = time.time()
        if (cached.get("exit") == use_exit and cached.get("started_at") == st.get("started_at")
                and now - cached.get("at", 0) < PROBE_EVERY):
            return bool(cached.get("ok"))
        ok = False
        for target in PROBE_TARGETS:
            try:
                socket.create_connection(target, timeout=PROBE_TIMEOUT).close()
                ok = True
                break
            except OSError:
                continue
        self._update_state(exit_probe={"exit": use_exit, "started_at": st.get("started_at"), "at": now, "ok": ok})
        return ok

    def vpn_status(self):
        """{"exit", "state": off|stopped|pending|connecting|on|trouble, "detail"}.

        "on" needs evidence from llarpd's log that the exit was actually found on the network,
        not just that the routes into the tunnel are in place."""
        use_exit = self.settings.get("use_exit")
        if not use_exit:
            return {"exit": None, "state": "off", "detail": "VPN off"}
        if not self.is_running():
            return {"exit": use_exit, "state": "stopped", "detail": f"will use {use_exit} when llarpd starts"}
        if self.state().get("fingerprint") != self.fingerprint():
            return {"exit": use_exit, "state": "pending", "detail": "restart llarpd to apply VPN change"}
        self.scan_log()
        sc = self._scan
        now = time.time()
        routed = sc["tun"] is not None and half_default_route_dev() == sc["tun"]
        reached = use_exit in sc["exits_reached"] or (not B32Z_ADDR_RE.match(use_exit) and sc["exits_reached"])
        starting = now - (self.state().get("started_at") or 0) < STARTUP_GRACE
        recent_path = sc["path_built"] and now - sc["path_built"] < NO_RELAYS_WINDOW
        if sc["unreadable"] and now - sc["unreadable"][0] < EXIT_TROUBLE_WINDOW:
            return {
                "exit": use_exit,
                "state": "trouble",
                "detail": f"{use_exit} answers but its replies can't be read; it probably runs a different "
                "llarpd version (compare `llarpd --version` on both machines)",
            }
        silent = sc["silent"]
        if silent and now - silent[0] < EXIT_TROUBLE_WINDOW and (silent[1] == use_exit or not B32Z_ADDR_RE.match(use_exit)):
            return {
                "exit": use_exit,
                "state": "trouble",
                "detail": f"{use_exit} doesn't answer: it may be offline, not running as an exit, or need an "
                "auth code (still retrying)",
            }
        if sc["no_relays"] and now - sc["no_relays"] < NO_RELAYS_WINDOW and not starting and not recent_path:
            return {
                "exit": use_exit,
                "state": "trouble",
                "detail": "can't reach any llarp relays, so internet traffic is blocked (see the log)",
            }
        if sc["exit_trouble"] and now - sc["exit_trouble"][0] < EXIT_TROUBLE_WINDOW and not reached:
            return {"exit": use_exit, "state": "trouble", "detail": f"can't reach {use_exit} yet (still retrying)"}
        if routed and reached:
            # llarpd logs nothing when the exit answers, so prove it: does traffic get through?
            if self.probe_exit(use_exit):
                return {"exit": use_exit, "state": "on", "detail": f"internet traffic goes through {use_exit}"}
            started = self.state().get("started_at") or 0
            if now - started < EXIT_ANSWER_GRACE:
                return {"exit": use_exit, "state": "connecting", "detail": f"waiting for {use_exit} to answer…"}
            return {
                "exit": use_exit,
                "state": "trouble",
                "detail": f"{use_exit} was found, but no traffic gets through it: it may be offline, "
                "not running as an exit, or need an auth code (still retrying)",
            }
        if routed:
            return {"exit": use_exit, "state": "connecting", "detail": f"looking for {use_exit} on the network…"}
        return {"exit": use_exit, "state": "connecting", "detail": f"connecting to {use_exit}…"}

    # ---- bootstraps

    def enabled_bootstrap_files(self):
        return [
            b["file"] for b in self.settings["bootstraps"] if b.get("enabled", True) and Path(b["file"]).exists()
        ]

    def find_bootstrap(self, ref):
        """Look up a bootstrap by 1-based index or name."""
        entries = self.settings["bootstraps"]
        if str(ref).isdigit() and 1 <= int(ref) <= len(entries):
            return entries[int(ref) - 1]
        for entry in entries:
            if entry["name"] == ref:
                return entry
        raise LlarpError(f"no bootstrap '{ref}' (see: llarpctl bootstrap list)")

    def add_bootstrap_bytes(self, data: bytes, name: str):
        """Validate and store bootstrap bytes. Returns (entry, info)."""
        try:
            info = inspect_bootstrap(data)
        except Exception as e:  # noqa: BLE001
            raise LlarpError(f"'{name}' is not a valid bootstrap file: {e}") from e
        BOOTSTRAP_DIR.mkdir(parents=True, exist_ok=True)
        stem = "".join(c if c.isalnum() or c in "-_." else "_" for c in Path(name).stem) or "bootstrap"
        dest = BOOTSTRAP_DIR / f"{stem}.signed"
        n = 1
        while dest.exists():
            if dest.read_bytes() == data:
                raise LlarpError(f"'{name}' is already in the list")
            n += 1
            dest = BOOTSTRAP_DIR / f"{stem}-{n}.signed"
        dest.write_bytes(data)
        entry = {"name": name, "file": str(dest), "enabled": True}
        self.settings["bootstraps"].append(entry)
        self.save()
        self.note(f"added bootstrap {name} ({len(info)} router(s))")
        return entry, info

    def add_bootstrap_path(self, path):
        path = Path(path).expanduser()
        try:
            data = path.read_bytes()
        except OSError as e:
            raise LlarpError(f"could not read {path}: {e}") from e
        return self.add_bootstrap_bytes(data, path.name)

    @staticmethod
    def fetch_url(url):
        """Download a bootstrap file. Returns (data, suggested name)."""
        if not url.startswith(("http://", "https://")):
            raise LlarpError("URL must start with http:// or https://")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "llarp-gui"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read(1 << 20)  # bootstrap files are tiny; cap at 1 MiB
        except Exception as e:  # noqa: BLE001
            raise LlarpError(f"download failed: {e}") from e
        parsed = urllib.parse.urlparse(url)
        return data, Path(parsed.path).name or parsed.netloc

    def add_bootstrap_url(self, url):
        data, name = self.fetch_url(url)
        return self.add_bootstrap_bytes(data, name)

    def add_bootstrap(self, source):
        """Add from a URL, a file path, or the name of a bundled bootstrap."""
        if source.startswith(("http://", "https://")):
            return self.add_bootstrap_url(source)
        if IS_WSL and WINDOWS_PATH_RE.match(source):
            source = wslpath(source)
        if not Path(source).expanduser().exists():
            bundled = BUNDLED_DIR / source
            if bundled.suffix != ".signed":
                bundled = bundled.with_name(bundled.name + ".signed")
            if bundled.exists():
                return self.add_bootstrap_path(bundled)
        return self.add_bootstrap_path(source)

    def update_bundled_bootstraps(self):
        """Bring added copies of bundled bootstraps (same name, e.g. opennet.signed) up to date
        with the bundled file, since a stale copy can point only at relays that are gone. The
        entry keeps its place and its enabled flag. Returns the names updated."""
        updated = []
        for src in self.bundled_bootstraps():
            try:
                data = src.read_bytes()
                inspect_bootstrap(data)
            except Exception:  # noqa: BLE001
                continue
            for entry in self.settings["bootstraps"]:
                dest = Path(entry["file"])
                if entry["name"] != src.name or not dest.is_file():
                    continue
                try:
                    if dest.read_bytes() != data:
                        dest.write_bytes(data)
                        updated.append(entry["name"])
                except OSError:
                    pass
        for name in updated:
            self.note(f"updated bootstrap {name} to the bundled version")
        return updated

    def bundled_bootstraps(self):
        return sorted(BUNDLED_DIR.glob("*.signed")) if BUNDLED_DIR.is_dir() else []

    def remove_bootstrap(self, entry):
        self.settings["bootstraps"].remove(entry)
        path = Path(entry["file"])
        if path.parent == BOOTSTRAP_DIR:
            path.unlink(missing_ok=True)
        self.save()
        self.note(f"removed bootstrap {entry['name']}")

    def set_bootstrap_enabled(self, entry, enabled):
        entry["enabled"] = enabled
        self.save()

    # ---- exit forwarding

    def nat_target(self):
        """((range, iface), None) to masquerade, or (None, reason) when unknown."""
        rng = self.tun_range if self.is_running() else None
        if rng is None:
            try:
                rng = ini_get(self.settings["config"], "network", "ifaddr")
            except OSError:
                rng = None
        if not rng or not IPV4_RANGE_RE.match(rng):
            return None, "start llarpd so the tunnel range is known"
        iface = default_route_iface()
        if not iface or not IFACE_RE.match(iface):
            return None, "no default internet interface found"
        return (rng, iface), None

    @staticmethod
    def _nat_rules(rng, iface):
        r, i = shlex.quote(rng), shlex.quote(iface)
        return [
            ("-t nat", f"POSTROUTING -s {r} -o {i} -j MASQUERADE"),
            ("", f"FORWARD -s {r} -o {i} -j ACCEPT"),
            ("", f"FORWARD -d {r} -i {i} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"),
        ]

    def forwarding_script(self, enable, target):
        rules = self._nat_rules(*target)
        if enable:
            steps = ["sysctl -w net.ipv4.ip_forward=1"]
            for table, rule in rules:
                steps.append(f"(iptables {table} -C {rule} 2>/dev/null || iptables {table} -A {rule})".replace("  ", " "))
            return " && ".join(steps)
        return "; ".join(f"(iptables {table} -D {rule} 2>/dev/null || true)".replace("  ", " ") for table, rule in rules)

    @staticmethod
    def privileged_command(script, graphical=False):
        """argv to run a shell script as root: directly if root, else pkexec (GUI) or sudo."""
        if os.geteuid() == 0:
            return ["sh", "-c", script]
        tool = "pkexec" if graphical else "sudo"
        if not shutil.which(tool):
            raise LlarpError(f"{tool} is not installed. Run this as root instead:\n\n{script}")
        return [tool, "sh", "-c", script]

    def nat_applied(self):
        applied = self.state().get("nat")
        return tuple(applied) if applied else None

    def mark_nat(self, target):
        self._update_state(nat=list(target) if target else None)

    # ---- Windows host (LLARP Control for Windows runs llarpd in a WSL distro)

    @staticmethod
    def _bridge_rules(tun, eth):
        # masquerade: llarpd only delivers replies to its own tunnel address
        return [
            ["-t", "nat", "POSTROUTING", "-o", tun, "-j", "MASQUERADE"],
            ["FORWARD", "-i", eth, "-o", tun, "-j", "ACCEPT"],
            ["FORWARD", "-i", tun, "-o", eth, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ]

    @staticmethod
    def _mss_rule(tun):
        # Windows sends full-size packets; clamp TCP to what fits the tunnel (best effort)
        return ["-t", "mangle", "FORWARD", "-o", tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                "-j", "TCPMSS", "--clamp-mss-to-pmtu"]

    @staticmethod
    def wsl_peer_routes(eth):
        """Host routes llarpd's route poker added for its relays while routing through an
        exit (`<ip> via <gateway> dev <eth>`): the Windows host must send these direct too."""
        try:
            out = subprocess.run(["ip", "-4", "route", "show"], capture_output=True, text=True).stdout
        except OSError:
            return []
        peers = []
        for line in out.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+) via \S+ dev (\S+)", line)
            if m and m.group(2) == eth and is_public_ipv4(m.group(1)):
                peers.append(m.group(1))
        return sorted(set(peers))

    @staticmethod
    def _iptables(rule, op):
        """op: -C (check), -A (append) or -D (delete). Returns the CompletedProcess."""
        if rule[0] == "-t":
            argv = ["iptables", rule[0], rule[1], op] + rule[2:]
        else:
            argv = ["iptables", op] + rule
        try:
            return subprocess.run(argv, capture_output=True, text=True)
        except OSError as e:
            raise LlarpError(f"iptables is not available: {e}") from e

    def windows_bridge(self, enable=None):
        """Inside WSL: let the Windows host reach .loki through this distro.

        enable=True forwards traffic from the WSL network into llarpd's tunnel (iptables),
        False removes that, None only reports. Returns what the Windows side needs: our
        address on the WSL network, the tunnel range to route here and the DNS server."""
        if not IS_WSL:
            raise LlarpError("winhost only works inside WSL (LLARP Control for Windows)")
        running = self.is_running()
        router = bool(self.settings.get("router_mode"))
        self.scan_log()
        tun = self._scan["tun"] if running else None
        rng = self._scan["range"] if running else None
        eth = default_route_iface()
        wsl_ip = iface_ipv4(eth) if eth else None
        applied = self.state().get("winbridge")
        wanted = [tun, eth] if enable and running and not router and tun and eth else None
        if wanted and not all(IFACE_RE.match(x) for x in wanted):
            raise LlarpError(f"unexpected interface names: {wanted}")

        if applied and applied != wanted and enable is not None:
            for rule in self._bridge_rules(*applied):
                self._iptables(rule, "-D")
            self._iptables(self._mss_rule(applied[0]), "-D")
            self._update_state(winbridge=None)
            applied = None
        if wanted and applied != wanted:
            try:
                Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
            except OSError as e:
                raise LlarpError(f"could not turn on IP forwarding: {e}") from e
            for rule in self._bridge_rules(*wanted):
                if self._iptables(rule, "-C").returncode != 0:
                    res = self._iptables(rule, "-A")
                    if res.returncode != 0:
                        raise LlarpError(f"iptables failed: {(res.stderr or res.stdout).strip()}")
            mss = self._mss_rule(tun)
            if self._iptables(mss, "-C").returncode != 0:
                self._iptables(mss, "-A")
            self._update_state(winbridge=wanted)
            applied = wanted
            self.note(f"Windows host: forwarding {eth} -> {tun} ({rng})")

        try:
            dns_ok = bool(wsl_ip) and f"bind={wsl_ip}:53" in self.override_file().read_text()
        except OSError:
            dns_ok = False
        # VPN through an exit: llarpd sends everything into its tunnel once 0.0.0.0/1 points
        # there; its relays stay reachable via host routes the Windows side mirrors
        vpn = None
        use_exit = self.settings.get("use_exit")
        if use_exit and running and not router:
            routed = bool(tun) and half_default_route_dev() == tun
            vpn = {
                "exit": use_exit,
                "state": self.vpn_status()["state"],
                "routed": routed,
                "peers": self.wsl_peer_routes(eth) if routed and eth else [],
            }
        return {
            "running": running,
            "router_mode": router,
            "wsl_ip": wsl_ip,
            "tun": tun,
            "range": rng if rng and IPV4_RANGE_RE.match(rng) else None,
            "dns": wsl_ip if running and dns_ok and not router else None,
            "public_port": int(self.settings.get("public_port") or 1090),
            "bridged": applied is not None,
            "vpn": vpn,
        }

    # ---- config generation

    def generate_config(self):
        cfg = Path(self.settings["config"])
        if cfg.exists():
            raise LlarpError(f"{cfg} already exists; not overwriting")
        cmd = [self.settings["llarpd"], "--generate"]
        if self.settings.get("router_mode"):
            cmd.append("--router")
        cmd.append(str(cfg))
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise LlarpError(f"failed to run llarpd: {e}") from e
        output = res.stdout + res.stderr
        if res.returncode != 0 or not cfg.exists():
            raise LlarpError(f"llarpd --generate failed (exit {res.returncode}):\n{output}")
        return cfg, output
