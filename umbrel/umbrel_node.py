#!/usr/bin/env python3
"""LLARP for Umbrel: runs llarpd and serves the control page's API.

Runs on the host network (llarpd needs the host's UDP port and its own tun interface).
The HTTP API listens only on a unix socket in the app's data dir; the `web` service
(umbrel_bridge.py) exposes that socket to Umbrel's app proxy, so the control page is
only reachable through the Umbrel login - never on the LAN or over LLARP.

Modes:
  router (default) - relay with a .snode address
  client           - .loki address; port 80 on it (the Umbrel login page) is reachable
                     from other LLARP clients. Everything else arriving over LLARP is
                     dropped by an nftables table this service manages.
"""

import base64
import json
import os
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

DATA = Path(os.environ.get("LLARP_DATA", "/data"))
os.environ.setdefault("XDG_CONFIG_HOME", str(DATA / "config"))
APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR))

import llarp_core as core  # noqa: E402
from llarp_core import LlarpError  # noqa: E402

LLARPD = os.environ.get("LLARPD", "/usr/local/bin/llarpd")
SOCKET_PATH = Path(os.environ.get("LLARP_SOCKET", DATA / "run" / "ui.sock"))
STATE_FILE = DATA / "umbrel.json"
WEB_DIR = APP_DIR / "web"
BOOTSTRAP_SRC = APP_DIR / "bootstrap"
TUN_NAME = os.environ.get("LLARP_TUN", "llarp-umbrel")
UMBREL_WEB_PORT = int(os.environ.get("UMBREL_WEB_PORT", "80"))
OUR_CONF_D = "40-umbrel.ini"
NFT_TABLE = "llarp_umbrel"
LOG_MAX = 16 << 20  # trim llarpd's log past this, keeping the newest LOG_KEEP
LOG_KEEP = 4 << 20

lock = threading.RLock()
ctl = None
state = {"enabled": True}
runtime = {
    "last_error": None,  # why llarpd isn't running, for the page
    "next_start": 0.0,  # backoff after a failed start
    "failures": 0,
    "firewall": None,  # None (not needed) / "on" / error text
    "notice": None,
}


def log(msg):
    print(f"[umbrel] {msg}", flush=True)


def save_state():
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(STATE_FILE)


# ---------------------------------------------------------------- setup


def setup():
    """First run: settings, llarpd config, permanent .loki key, bundled bootstraps."""
    global ctl
    (DATA / "run").mkdir(parents=True, exist_ok=True)
    fresh = not core.SETTINGS_FILE.exists()
    ctl = core.Controller()
    s = ctl.settings
    s["llarpd"] = LLARPD
    s["exit_node"] = False
    s["use_exit"] = None
    if fresh:
        s["router_mode"] = True  # a relay by default
        s["log_level"] = "info"
    ctl.save()
    use_mode_dir()

    known = {Path(b["file"]).name for b in s["bootstraps"]} | {b["name"] for b in s["bootstraps"]}
    for f in sorted(BOOTSTRAP_SRC.glob("*.signed")):
        if f.name not in known:
            try:
                ctl.add_bootstrap_path(f)
            except LlarpError as e:
                log(f"bundled bootstrap {f.name}: {e}")

    try:
        state.update(json.loads(STATE_FILE.read_text()))
    except (OSError, ValueError):
        save_state()


def use_mode_dir():
    """Point llarpd at the current mode's own data dir (/data/router or /data/client), so the
    .snode identity and the .loki key never mix and a client never dials the relay it used to be."""
    s = ctl.settings
    router = bool(s.get("router_mode"))
    cfg = DATA / ("router" if router else "client") / "llarpd.ini"
    s["config"] = str(cfg)
    ctl.save()
    (cfg.parent / "conf.d").mkdir(parents=True, exist_ok=True)
    if not cfg.exists():
        # a client config works for both modes (--router switches llarpd to relay)
        s["router_mode"] = False
        try:
            ctl.generate_config()
        finally:
            s["router_mode"] = router
            ctl.save()
        log(f"generated {cfg}")
    if not router and not ctl.keyfile_path():
        ctl.set_persistent_address(True)  # the .loki address must survive restarts


def write_our_conf():
    """Fixed tun name in client mode, so the firewall knows which interface is LLARP."""
    path = ctl.data_dir() / "conf.d" / OUR_CONF_D
    if ctl.settings.get("router_mode"):
        path.unlink(missing_ok=True)  # relays have no tun; the option would only warn
    else:
        path.write_text(f"# written by LLARP for Umbrel\n[network]\nifname={TUN_NAME}\n")


# ---------------------------------------------------------------- firewall


def tun_exists():
    return Path(f"/sys/class/net/{TUN_NAME}").exists()


def firewall_apply():
    """Only let other LLARP clients reach the Umbrel login page (TCP 80) on our .loki address."""
    rules = f"""
table inet {NFT_TABLE}
delete table inet {NFT_TABLE}
table inet {NFT_TABLE} {{
    chain inbound {{
        type filter hook prerouting priority -150; policy accept;
        iifname "{TUN_NAME}" ct state established,related accept
        iifname "{TUN_NAME}" tcp dport {UMBREL_WEB_PORT} accept
        iifname "{TUN_NAME}" counter drop
    }}
}}
"""
    res = subprocess.run(["nft", "-f", "-"], input=rules, capture_output=True, text=True)
    if res.returncode != 0:
        return (res.stderr or res.stdout).strip() or f"nft exited {res.returncode}"
    return "on"


def firewall_remove():
    subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], capture_output=True)


def firewall_sync():
    want = not ctl.settings.get("router_mode") and ctl.is_running() and tun_exists()
    if want and runtime["firewall"] != "on":
        result = firewall_apply()
        if result != runtime["firewall"]:
            log("firewall: " + ("only port %d is reachable over LLARP" % UMBREL_WEB_PORT if result == "on" else result))
        runtime["firewall"] = result
    elif not want and runtime["firewall"] is not None:
        firewall_remove()
        runtime["firewall"] = None


# ---------------------------------------------------------------- llarpd lifecycle


def prepare_router():
    """Behind NAT a relay must be told its public IP; detect it once if we can."""
    s = ctl.settings
    if not s.get("router_mode") or s.get("public_ip") or core.host_public_ipv4():
        return
    try:
        ip = core.detect_public_ip()
    except LlarpError as e:
        log(str(e))
        return
    ctl.set_setting("public_ip", ip)
    runtime["notice"] = f"Detected your public IP {ip}."
    log(f"public IP detected: {ip}")


def start_llarpd():
    write_our_conf()
    prepare_router()
    try:
        ctl.start()
    except LlarpError as e:
        fail(str(e))
        return False
    runtime["last_error"] = None
    runtime["started_at"] = time.time()
    return True


def fail(reason):
    runtime["last_error"] = reason
    runtime["failures"] += 1
    delay = min(300, 15 * 2 ** min(runtime["failures"] - 1, 5))
    runtime["next_start"] = time.time() + delay
    log(f"llarpd not running: {reason} (retrying in {delay}s)")


MILESTONES = (
    ("session with router", "connected to the LLARP network"),
    ("is built, took", "first path built; the node is reachable"),
    ("IntroSet publish confirmed", "address published; other LLARP clients can find it"),
)
echo = {"ino": None, "pos": 0, "seen": set()}


def echo_log():
    """Copy the important parts of llarpd's log to our stdout, so Umbrel's log viewer shows them:
    control notes, errors, and the first time each milestone happens in a run."""
    try:
        st = core.LOG_FILE.stat()
    except OSError:
        return
    if echo["ino"] is None:
        echo.update(ino=st.st_ino, pos=st.st_size)  # a log from before we started: already shown
    elif st.st_ino != echo["ino"]:
        echo.update(ino=st.st_ino, pos=0, seen=set())  # rotated: llarpd was restarted
    elif st.st_size < echo["pos"]:
        echo["pos"] = st.st_size  # trimmed by trim_log; what's left was shown already
    with open(core.LOG_FILE, "rb") as f:
        f.seek(echo["pos"])
        chunk = f.read(1 << 20)
    cut = chunk.rfind(b"\n") + 1
    echo["pos"] += cut
    for line in chunk[:cut].decode(errors="replace").splitlines():
        if line.startswith("[ctl"):
            log("llarpd: " + line.split("] ", 1)[-1])
            if "starting:" in line:
                echo["seen"] = set()
        elif "[error]" in line or "[critical]" in line:
            log("llarpd: " + line[line.find("[error]") if "[error]" in line else line.find("[critical]"):][:300])
        else:
            for needle, text in MILESTONES:
                if needle in line and needle not in echo["seen"]:
                    echo["seen"].add(needle)
                    log(text)


def trim_log():
    """llarpd appends to its log forever; keep the newest part. Its file descriptor is in
    append mode, so its next write lands at the new end of the file."""
    try:
        if core.LOG_FILE.stat().st_size <= LOG_MAX:
            return
        with open(core.LOG_FILE, "r+b") as f:
            f.seek(-LOG_KEEP, os.SEEK_END)
            tail = f.read()
            tail = tail[tail.find(b"\n") + 1:]
            f.seek(0)
            f.write(tail)
            f.truncate()
    except OSError as e:
        log(f"could not trim the log: {e}")


def watchdog():
    was_running = False
    while True:
        with lock:
            try:
                ctl.enforce_stop_timeout()
                running = ctl.is_running()
                if was_running and not running and not ctl.state().get("stop_requested_at"):
                    fail(ctl.exit_reason() or "llarpd stopped unexpectedly (see the log)")
                elif running and time.time() - runtime.get("started_at", 0) > 120:
                    runtime["failures"] = 0  # it stayed up; reset the backoff
                if state["enabled"] and not running and time.time() >= runtime["next_start"]:
                    running = start_llarpd()
                elif not state["enabled"] and running and not ctl.stopping():
                    ctl.request_stop()
                was_running = running
                firewall_sync()
                echo_log()
                trim_log()
            except Exception as e:  # noqa: BLE001 - keep the watchdog alive
                log(f"watchdog error: {e!r}")
        time.sleep(2)


def restart_llarpd():
    ctl.stop()
    runtime["next_start"] = 0
    runtime["failures"] = 0
    if state["enabled"]:
        start_llarpd()
    firewall_sync()


def shutdown(*_):
    log("stopping")
    with lock:
        try:
            ctl.stop()
        finally:
            firewall_remove()
            SOCKET_PATH.unlink(missing_ok=True)
    os._exit(0)


# ---------------------------------------------------------------- status


def umbrel_web_reachable():
    try:
        with socket.create_connection(("127.0.0.1", UMBREL_WEB_PORT), timeout=1):
            return True
    except OSError:
        return False


def status():
    s = ctl.settings
    st = ctl.status()
    router = bool(s.get("router_mode"))
    lan_ip = core.iface_ipv4(core.default_route_iface() or "")
    bootstraps = []
    for b in s["bootstraps"]:
        ok, summary, _ = core.describe_bootstrap(b)
        bootstraps.append({"name": b["name"], "enabled": b["enabled"], "ok": ok, "summary": summary})
    connected = None
    if st["running"]:
        ctl.scan_log()
        built = ctl._scan.get("path_built")
        connected = bool(built and time.time() - built < 600) if not router else None
    return {
        "enabled": state["enabled"],
        "running": st["running"],
        "uptime": core.format_uptime(st["uptime"]) if st["uptime"] else None,
        "mode": "router" if router else "client",
        "address": st["address"],
        "address_kind": st["address_kind"],
        "connected": connected,
        "error": None if st["running"] else (runtime["last_error"] or ctl.startup_problem()),
        "retry_in": max(0, int(runtime["next_start"] - time.time())) if not st["running"] and state["enabled"] else 0,
        "notice": runtime["notice"],
        "public_ip": s.get("public_ip", ""),
        "public_port": s.get("public_port", 1090),
        "host_public_ip": core.host_public_ipv4(),
        "lan_ip": lan_ip,
        "firewall": runtime["firewall"],
        "umbrel_web": umbrel_web_reachable() if not router else None,
        "umbrel_web_port": UMBREL_WEB_PORT,
        "bootstraps": bootstraps,
        "version": llarpd_version(),
    }


_version = None


def llarpd_version():
    global _version
    if _version is None:
        try:
            out = subprocess.run([LLARPD, "--version"], capture_output=True, text=True, timeout=10).stdout
            _version = out.strip().splitlines()[0] if out.strip() else "unknown"
        except (OSError, subprocess.TimeoutExpired):
            _version = "unknown"
    return _version


def log_tail(max_bytes=96 * 1024):
    try:
        with open(core.LOG_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            text = f.read().decode(errors="replace")
    except OSError:
        return ""
    if size > max_bytes:
        text = text.split("\n", 1)[-1]
    return text


# ---------------------------------------------------------------- API


def api(method, path, body):
    if method == "GET" and path == "/api/status":
        return status()
    if method == "GET" and path == "/api/log":
        return {"log": log_tail()}
    if method != "POST":
        raise LookupError(path)

    if path == "/api/power":
        state["enabled"] = bool(body.get("on"))
        save_state()
        runtime["next_start"] = 0
        runtime["failures"] = 0
        if not state["enabled"]:
            ctl.stop()
        elif not ctl.is_running():
            start_llarpd()
        firewall_sync()
    elif path == "/api/mode":
        mode = body.get("mode")
        if mode not in ("router", "client"):
            raise LlarpError("mode must be router or client")
        if (mode == "router") != bool(ctl.settings.get("router_mode")):
            ctl.stop()
            ctl.set_router_mode(mode == "router")
            use_mode_dir()
            ctl.note(f"switched to {mode} mode")
            runtime["notice"] = None
            restart_llarpd()
    elif path == "/api/public":
        ip = body.get("ip")
        if ip == "auto":
            ip = core.detect_public_ip()
        if ip is not None:
            ctl.set_setting("public_ip", ip)
        if body.get("port") is not None:
            ctl.set_setting("public_port", body["port"])
        runtime["notice"] = None
        if ctl.settings.get("router_mode") and ctl.changes_pending():
            restart_llarpd()
    elif path == "/api/restart":
        restart_llarpd()
    elif path == "/api/bootstrap/add":
        if body.get("url"):
            ctl.add_bootstrap_url(body["url"])
        else:
            try:
                data = base64.b64decode(body.get("data", ""), validate=True)
            except ValueError:
                raise LlarpError("upload was not valid base64") from None
            ctl.add_bootstrap_bytes(data, body.get("name") or "bootstrap.signed")
    elif path == "/api/bootstrap/remove":
        ctl.remove_bootstrap(ctl.find_bootstrap(body.get("name", "")))
    elif path == "/api/bootstrap/enable":
        ctl.set_bootstrap_enabled(ctl.find_bootstrap(body.get("name", "")), bool(body.get("enabled")))
    else:
        raise LookupError(path)
    return status()


class Handler(BaseHTTPRequestHandler):
    server_version = "llarp-umbrel"

    def log_message(self, fmt, *args):
        pass

    def send(self, code, data, ctype="application/json"):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self.send(200, (WEB_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/icon.svg":
            return self.send(200, (WEB_DIR / "icon.svg").read_bytes(), "image/svg+xml")
        self.handle_api("GET", path, {})

    def do_POST(self):
        # JSON only: browsers can't send that cross-site without a preflight we never answer
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self.send(415, {"error": "expected application/json"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > 2 << 20:
            return self.send(413, {"error": "request too large"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.send(400, {"error": "invalid JSON"})
        self.handle_api("POST", self.path.split("?", 1)[0], body if isinstance(body, dict) else {})

    def handle_api(self, method, path, body):
        try:
            with lock:
                result = api(method, path, body)
        except LookupError:
            return self.send(404, {"error": "not found"})
        except LlarpError as e:
            return self.send(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            log(f"API error on {path}: {e!r}")
            return self.send(500, {"error": f"internal error: {e}"})
        self.send(200, result)


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        conn, _ = super().get_request()
        return conn, ("local", 0)


def main():
    setup()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    SOCKET_PATH.unlink(missing_ok=True)
    server = UnixHTTPServer(str(SOCKET_PATH), Handler)
    os.chmod(SOCKET_PATH, 0o660)
    log(f"mode: {'router' if ctl.settings.get('router_mode') else 'client'}; API on {SOCKET_PATH}")
    threading.Thread(target=watchdog, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
