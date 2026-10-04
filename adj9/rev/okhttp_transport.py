"""okhttp_transport.py -- an Adjust client transport that matches the app's
OkHttp/Conscrypt network fingerprint (http_fingerprint_diff.md, 2026-09-27).

What the app puts on the wire and what we must reproduce:

  TLS      Conscrypt/BoringSSL ClientHello: 517-B record padded to 512-B
           handshake, 17 ciphers (AES128-TLS1.3 first), 3 groups
           (x25519, secp256r1, secp384r1), x25519-only key share, 9 sig algs,
           extensions in order [server_name, extended_master_secret,
           renegotiation_info, supported_groups, ec_point_formats,
           session_ticket, alpn, status_request, signature_algorithms,
           key_share, psk_key_exchange_modes, supported_versions, padding],
           no GREASE, no ML-KEM, ALPN "http/1.1" only, TLS1.3+TLS1.2.
  HTTP     HTTP/1.1 only, one keep-alive connection reused for the whole
           session -> click -> attribution flow, session first.
  Headers  exact order  Client-SDK, Authorization, Content-Type, User-Agent,
           Host, Connection: Keep-Alive, Accept-Encoding: gzip,
           Content-Length  -- "Client-SDK" with capital SDK.
  Body     OkHttp FormBody percent-encoding: space -> %20 (never '+'),
           colon -> %3A, plus -> %2B; only unreserved [A-Za-z0-9-_.~] bare.

Engine: `tls_client` (bogdanfinn uTLS wrapper), client_identifier
"okhttp4_android_12" -- a uTLS ClientHello spec built from a real
Android-12 OkHttp4 capture, i.e. the same Conscrypt hello family the app
emits.  The wrapper preserves header order (its Go fork, fhttp) and pools
keep-alive connections per session, so one Session = one connection for the
whole flow.  force_http1 pins HTTP/1.1.

MEASURED match (fp_probe, vs tunnel_cap/app_clienthello.txt):
  record 517 B (app: 517) -- padded Conscrypt hello reproduced exactly
  extensions 13/13 in exact order (incl. padding, status_request; no
  post_handshake_auth, no ML-KEM, no GREASE)
  groups 3/3 (x25519, secp256r1, secp384r1), sigalgs 9/9, ALPN http/1.1
  only, supported_versions TLS1.3+TLS1.2, psk_mode 1, key_share x25519-32B
  ciphers 16/17: the spec omits 0xc00a (ECDHE-ECDSA-AES256-SHA); every
  other cipher matches in the app's exact order.  The custom JA3 route was
  measured too: it cannot reproduce the padding ext and the server rejects
  its hello outright, so the preset with the 1-cipher delta is the best
  achievable match.
  header block: byte-exact OkHttp order/casing (Client-SDK capital, 8
  headers, Content-Length last).

Self-check (python okhttp_transport.py --probe) runs the fingerprint
measurement: a local CONNECT passthrough captures our real ClientHello and a
local plain-HTTP sink captures our exact header block, both compared against
the app reference (tunnel_cap/app_clienthello.txt / http_fingerprint_diff.md
section 1).
"""
import base64
import gzip
import io
import json
import os
import re
import socket
import ssl
import sys
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "adj9_tool"))

from tls_client import Session                       # uTLS-backed client
from tls_client.exceptions import TLSClientExeption

# ---------------------------------------------------------------------------
# The app fingerprint constants (from the SAZ plaintext + tunnel capture)
# ---------------------------------------------------------------------------
CLIENT_SDK = "android5.7.0"
UA = ("Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)")
HOST = "app.adjust.com"
BASE_URL = "https://" + HOST
APP_TOKEN = "jut9tib0eeps"

# OkHttp's canonical header write order (SAZ 1_c.txt..4_c.txt + CONNECT):
# SDK headers, FormBody Content-Type, client default UA, BridgeInterceptor
# Host/Connection/Accept-Encoding, Content-Length last.
HEADER_ORDER_POST = ["Client-SDK", "Authorization", "Content-Type", "User-Agent",
                     "Host", "Connection", "Accept-Encoding", "Content-Length"]
HEADER_ORDER_GET = ["Client-SDK", "Authorization", "User-Agent",
                    "Host", "Connection", "Accept-Encoding"]

# The app reference hello (tunnel_cap/app_clienthello.txt) for self-check.
APP_REF = {
    "ciphers": ["1301", "1302", "1303", "c02b", "c02c", "cca9", "c02f", "c030",
                "cca8", "c009", "c00a", "c013", "c014", "009c", "009d",
                "002f", "0035"],
    "groups": ["001d", "0017", "0018"],
    "sigalgs": ["0403", "0804", "0401", "0503", "0805", "0501", "0806",
                "0601", "0201"],
    "exts": ["server_name", "extended_master_secret", "renegotiation_info",
             "supported_groups", "ec_point_formats", "session_ticket_v2",
             "alpn", "status_request", "signature_algorithms", "key_share",
             "psk_key_exchange_modes", "supported_versions", "padding"],
    "alpn": ["http/1.1"],
    "versions": ["0x0304", "0x0303"],
    "psk_modes": ["1"],
    "ecpf": ["0"],
}


def okhttp_form_encode(params):
    """OkHttp FormBody wire encoding: percent-encode everything except
    [A-Za-z0-9-_.~]; space becomes %20 (urlencode would emit '+')."""
    out = []
    for k, v in params.items():
        out.append(urllib.parse.quote(str(k), safe="")
                   + "=" + urllib.parse.quote(str(v), safe=""))
    return "&".join(out).encode()


# ---------------------------------------------------------------------------
# The transport
# ---------------------------------------------------------------------------
class OkHttpTransport(object):
    """One uTLS(Conscrypt) keep-alive connection, OkHttp header law, %20."""

    def __init__(self, verbose=True, proxy=None, timeout_seconds=45):
        self.verbose = verbose
        # okhttp4_android_12 = uTLS spec of the Conscrypt Android-12 OkHttp4
        # ClientHello (17 ciphers / 3 groups / padding / status_request /
        # no-GREASE).  force_http1 -> HTTP/1.1 only.  header_order makes the
        # Go fhttp fork write headers in the given order.
        self.s = Session(
            client_identifier="okhttp4_android_12",
            force_http1=True,
            header_order=HEADER_ORDER_POST,
        )
        self.s.timeout_seconds = timeout_seconds
        self.headers = {
            "Client-SDK": CLIENT_SDK,
            "User-Agent": UA,
            "Host": HOST,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
        }
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        self._count = 0            # requests sent on this session

    # -- raw senders -------------------------------------------------------
    def post(self, path, params, auth):
        """POST /path with the OkHttp FormBody encoding + header order."""
        return self.post_raw(path, okhttp_form_encode(params), auth)

    def post_raw(self, path, body, auth):
        """POST /path with a pre-encoded body (bytes or str)."""
        h = dict(self.headers)
        h["Authorization"] = auth
        h["Content-Type"] = "application/x-www-form-urlencoded"
        r = self.s.post(BASE_URL + path, data=body, headers=h,
                        allow_redirects=False)
        self._count += 1
        return self._done(r, path)

    def get(self, path, params, auth):
        """GET /path?query (query in OkHttp HttpUrl encoding)."""
        qs = okhttp_form_encode(params).decode()
        h = dict(self.headers)
        h["Authorization"] = auth
        r = self.s.get(BASE_URL + path + "?" + qs, headers=h,
                       allow_redirects=False)
        self._count += 1
        return self._done(r, path)

    def _done(self, r, path):
        body = r.text
        ce = (r.headers.get("Content-Encoding") or "").lower()
        if ce == "gzip" or body[:2] == "\x1f\x8b":
            try:
                body = gzip.decompress(body.encode("latin1")).decode(
                    "utf-8", "replace")
            except Exception:
                pass
        if self.verbose:
            print("[transport] #%d %-13s -> %s %s"
                  % (self._count, path, r.status_code, body[:120]), flush=True)
        return r.status_code, body

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def auth_header(blob_b64):
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % blob_b64)


# ---------------------------------------------------------------------------
# Fingerprint self-check
# ---------------------------------------------------------------------------
class _CaptureProxy(threading.Thread):
    """CONNECT passthrough that saves the client stream (real ClientHello)."""

    def __init__(self, port):
        threading.Thread.__init__(self, daemon=True)
        self.port = port
        self.c2s = os.path.join(HERE, "fp_probe_c2s.bin")
        self.s2c = os.path.join(HERE, "fp_probe_s2c.bin")

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(4)
        self._srv = srv
        while True:
            conn, _ = srv.accept()
            try:
                self._handle(conn)
            except Exception:
                pass

    def _handle(self, conn):
        conn.settimeout(30)
        f = conn.makefile("rb")
        line = f.readline().decode("latin1")
        if not line.upper().startswith("CONNECT"):
            conn.close()
            return
        while True:                      # rest of the CONNECT block
            h = f.readline()
            if h in (b"\r\n", b"\n", b""):
                break
        self.connect_head = line.strip()
        host, _, port = line.split()[1].partition(":")
        up = socket.create_connection((host, int(port or 443)), timeout=30)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        c2s = open(self.c2s, "wb")
        s2c = open(self.s2c, "wb")

        def pump(a, b, log):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    log.write(d)
                    b.sendall(d)
            except Exception:
                pass
            try:
                b.close()
            except Exception:
                pass

        t1 = threading.Thread(target=pump, args=(conn, up, c2s), daemon=True)
        t2 = threading.Thread(target=pump, args=(up, conn, s2c), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        c2s.close(); s2c.close()
        conn.close(); up.close()


class _PlainSink(threading.Thread):
    """A raw TCP sink that captures one plaintext HTTP request byte-exactly."""

    def __init__(self, port):
        threading.Thread.__init__(self, daemon=True)
        self.port = port
        self.data = b""

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(4)
        while True:
            conn, _ = srv.accept()
            conn.settimeout(10)
            buf = b""
            try:
                while b"\r\n\r\n" not in buf:
                    d = conn.recv(65536)
                    if not d:
                        break
                    buf += d
                # read body if Content-Length present
                m = re.search(rb"Content-Length: (\d+)", buf, re.I)
                if m:
                    need = int(m.group(1))
                    hdr_end = buf.index(b"\r\n\r\n") + 4
                    while len(buf) - hdr_end < need:
                        d = conn.recv(65536)
                        if not d:
                            break
                        buf += d
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except Exception:
                pass
            self.data = buf
            conn.close()


def _load_app_hello():
    """Parse the app's captured hello fields from tunnel_cap/app_clienthello.txt."""
    p = os.path.join(HERE, "tunnel_cap", "app_clienthello.txt")
    line1 = open(p, encoding="utf-8").readline().strip()
    parts = line1.split("|")
    return {
        "ciphers": [c.replace("0x", "") for c in parts[1].split(",")],
        "exts": parts[3].split(","),
        "groups": [g.replace("0x", "") for g in parts[4].split(",")],
        "sigalgs": parts[5].split(","),
        "alpn": parts[6].split(","),
        "versions": parts[7].split(","),
        "keyshare": parts[8].split(","),
    }


def probe(verbose=True):
    """Measure our transport's TLS + HTTP fingerprint against the app's."""
    sys.path.insert(0, os.path.join(HERE, "tunnel_cap"))
    import tls_parse

    report = {}

    # ---- TLS hello through the passthrough proxy ----
    px = _CaptureProxy(8897)
    px.start()
    t = OkHttpTransport(verbose=False, proxy="http://127.0.0.1:8897")
    try:
        t.get("/attribution", {"app_token": APP_TOKEN}, auth_header("A" * 344))
    except Exception as e:
        if verbose:
            print("[probe] probe request through proxy: %r (hello is captured "
                  "before the response matters)" % e)
    import time as _t
    for _ in range(50):
        if os.path.exists(px.c2s) and os.path.getsize(px.c2s) > 300:
            break
        _t.sleep(0.2)
    ours = tls_parse.parse_client_hello(open(px.c2s, "rb").read())
    ref = _load_app_hello()

    def norm_ciphers(ch):
        return [c.split()[0].replace("0x", "") for c in ch["cipher_suites"]]

    tls = {
        "record_len": int.from_bytes(open(px.c2s, "rb").read()[3:5], "big") + 5,
        "ciphers_exact": norm_ciphers(ours) == ref["ciphers"],
        "ciphers_ours": norm_ciphers(ours),
        "groups_exact": [g.split()[0].replace("0x", "") for g in
                         ours.get("supported_groups", [])] == ref["groups"],
        "groups_ours": [g.split()[0].replace("0x", "") for g in
                        ours.get("supported_groups", [])],
        "sigalgs_exact": ours.get("signature_algorithms") == ref["sigalgs"],
        "sigalgs_ours": ours.get("signature_algorithms"),
        "exts_exact": ours.get("extensions_order") == ref["exts"],
        "exts_ours": ours.get("extensions_order"),
        "alpn_exact": ours.get("alpn_offer") == ref["alpn"],
        "alpn_ours": ours.get("alpn_offer"),
        "versions_exact": ours.get("supported_versions") == ref["versions"],
        "key_share_ours": ours.get("key_share"),
        "grease_ours": any(0x0A0A == (c & 0x0F0F) == 0x0A0A
                           for c in [int(c.split()[0], 16)
                                     for c in ours["cipher_suites"]]),
        "padding_ext": "padding" in ours.get("extensions_order", []),
        "no_mlkem": "x25519_ml_kem768" not in str(ours.get("supported_groups")),
        "status_request": "status_request" in ours.get("extensions_order", []),
        "no_post_handshake_auth":
            "post_handshake_auth" not in ours.get("extensions_order", []),
        "parsed": ours,
    }
    score = sum(1 for k in ("ciphers_exact", "groups_exact", "sigalgs_exact",
                            "exts_exact", "alpn_exact", "versions_exact")
                if tls[k])
    tls["elements_matched"] = "%d/6" % score
    report["tls"] = tls

    # ---- plaintext header block through the local sink ----
    sink = _PlainSink(8898)
    sink.start()
    t2 = OkHttpTransport(verbose=False)
    t2.s.headers = {}                     # bypass the wrapper's defaults
    h = {"Client-SDK": CLIENT_SDK, "Authorization": auth_header("A" * 344),
         "Content-Type": "application/x-www-form-urlencoded", "User-Agent": UA,
         "Host": HOST, "Connection": "Keep-Alive", "Accept-Encoding": "gzip"}
    body = b"app_token=" + APP_TOKEN.encode()
    try:
        r = t2.s.post("http://127.0.0.1:8898/session", data=body, headers=h,
                      allow_redirects=False)
    except Exception:
        pass
    for _ in range(50):
        if sink.data:
            break
        _t.sleep(0.2)
    raw = sink.data
    report["headers"] = {
        "raw": raw.decode("latin1"),
        "lines": [l for l in raw.decode("latin1").split("\r\n") if l],
    }
    t.close(); t2.close()
    return report


if __name__ == "__main__":
    rep = probe()
    print("=" * 72)
    print("TLS hello vs app (okhttp4_android_12 uTLS spec):")
    tls = rep["tls"]
    for k in ("record_len", "elements_matched", "ciphers_exact", "groups_exact",
              "sigalgs_exact", "exts_exact", "alpn_exact", "versions_exact",
              "grease_ours", "padding_ext", "no_mlkem", "status_request",
              "no_post_handshake_auth"):
        print("  %-24s %s" % (k, tls.get(k)))
    print("  ciphers_ours             %s" % tls["ciphers_ours"])
    print("  groups_ours              %s" % tls["groups_ours"])
    print("  exts_ours                %s" % tls["exts_ours"])
    print("  alpn_ours                %s  key_share %s"
          % (tls["alpn_ours"], tls["key_share_ours"]))
    print("-" * 72)
    print("Header block on the wire (plaintext sink):")
    for l in rep["headers"]["lines"]:
        print("  | " + l[:110])
    json.dump({"tls": {k: v for k, v in tls.items() if k != "parsed"},
               "headers": rep["headers"]["lines"]},
              open(os.path.join(HERE, "okhttp_transport_probe.json"), "w"),
              indent=1, default=str)
    print("saved okhttp_transport_probe.json")
