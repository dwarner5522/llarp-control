#!/usr/bin/env python3
"""Expose the node service's unix socket on a TCP port for Umbrel's app proxy.

This runs in its own container on the app network; the node service runs on the host
network and only listens on the socket, so the control page is reachable solely
through the Umbrel login.
"""

import os
import socket
import threading

SOCKET_PATH = os.environ.get("LLARP_SOCKET", "/data/run/ui.sock")
PORT = int(os.environ.get("PORT", "7090"))


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client):
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(SOCKET_PATH)
    except OSError:
        body = b"LLARP is starting up; reload in a few seconds."
        client.sendall(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nRetry-After: 3\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
        )
        client.close()
        upstream.close()
        return
    t = threading.Thread(target=pump, args=(upstream, client), daemon=True)
    t.start()
    pump(client, upstream)
    t.join()
    client.close()
    upstream.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(64)
    print(f"[bridge] :{PORT} -> {SOCKET_PATH}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
