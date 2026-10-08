"""dd_wire_capture.py -- capture what OUR transport actually puts on the
wire: run a local listener (plain HTTP and TLS with a self-signed cert)
and send the funnel's exact headers/body through the same curl_cffi
session construction call() uses.  Nothing leaves localhost."""
import os
import socket
import ssl
import sys
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ADJ7 = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ADJ7)
sys.path.insert(0, HERE)

import run_install as ri  # noqa: E402  (APP_UA, CLIENT_SDK, call-logic shape)

BODY = urllib.parse.urlencode({"a": "1", "b": "2"}).encode()
AUTH = ('Signature signature="%s",adj_signing_id="1300000",algorithm="adj7",'
        'headers_id="8",native_version="3.62.0"' % ("AB" * 304))

captured = {}

def serve(sock, label, tls_wrap=None):
    conn, _ = sock.accept()
    if tls_wrap:
        conn = tls_wrap(conn)
    data = b""
    conn.settimeout(5)
    try:
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    captured[label] = data
    try:
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
    except Exception:
        pass
    conn.close()

def run_case(label, https=False):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    tls_wrap = None
    if https:
        here = HERE
        cert = os.path.join(here, "dd_test_cert.pem")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if not os.path.exists(cert):
            os.system("openssl req -x509 -newkey rsa:2048 -keyout %s.key "
                      "-out %s -days 2 -nodes -subj /CN=localhost 2>nul"
                      % (cert[:-4], cert))
            # combine key+cert into one pem for convenience
            with open(cert, "w") as f:
                f.write(open(cert).read())
            try:
                os.remove(cert[:-4] + ".key")
            except OSError:
                pass
        ctx.load_cert_chain(cert)
        tls_wrap = ctx.wrap_socket
    t = threading.Thread(target=serve, args=(sock, label, tls_wrap),
                         daemon=True)
    t.start()

    from curl_cffi import requests as _cr
    sess = _cr.Session(impersonate="chrome131_android")
    url = ("https://127.0.0.1:%d/session" if https
           else "http://127.0.0.1:%d/session") % port
    headers = {
        "Client-SDK": ri.CLIENT_SDK,
        "User-Agent": ri.APP_UA,
        "Authorization": AUTH,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        sess.request("POST", url, data=BODY, headers=headers, timeout=10,
                     verify=False)
    except Exception as e:
        print("  (request error: %r)" % (e,))
    t.join(timeout=10)
    raw = captured.get(label, b"")
    print("=== %s wire ===" % label)
    print(raw.decode("latin1", "replace") if raw else "  NOTHING CAPTURED")
    print()

run_case("plain HTTP (h1)")
run_case("TLS https (ALPN h2 available)", https=True)
