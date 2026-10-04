"""saz_session_log.py — Fiddler .saz session-log extractor for adj9 signatures.

Usage:
    python saz_session_log.py [path-to-saz]

Default: C:/Users/Downloads/pentindroid_logs.saz
Prints, per captured session: request line, status, full Authorization header,
the decoded 192-B signature (header + 44 body dwords), the Random3 header-law
check, and every body parameter (= the claims the body whitens).
Saves machine-readable output to saz_sessions.json next to this script.
"""
import base64
import datetime
import json
import re
import struct
import sys
import zipfile
import os

M31 = 2147483647


# ---- bionic random() TYPE_3 (the proven header law) ------------------------
class Random3:
    __slots__ = ("r", "f", "b")

    def __init__(self, seed):
        r = self.r = [0] * 31
        s = seed & 0xFFFFFFFF
        if s == 0:
            s = 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        r[0] = w
        prev = w
        for i in range(1, 31):
            hi, lo = divmod(prev, 127773)
            word = 16807 * lo - 2836 * hi
            if word < 0:
                word += M31
            prev = word
            r[i] = word
        self.f, self.b = 3, 0
        for _ in range(310):
            self.next()

    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o


def make_header(unix_sec):
    """16-B header = draws 1..8 pairwise-XOR as 4 big-endian u32."""
    R = Random3(unix_sec)
    d = [R.next() for _ in range(8)]
    return b"".join(struct.pack(">I", d[2 * i] ^ d[2 * i + 1]) for i in range(4))


def parse_created_at(raw):
    """Adjust created_at '2026-09-08T14:05:22.928Z+0530' (Z here = local+off)."""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", raw or "")
    if not m:
        return None
    y, mo, d, h, mi, s = map(int, m.groups())
    off = re.search(r"([+-])(\d{2})(\d{2})$", raw or "")
    dt = datetime.datetime(y, mo, d, h, mi, s)
    if off:  # the stamp is LOCAL wall time with a fake Z; subtract the offset
        sign = 1 if off.group(1) == "+" else -1
        dt -= sign * datetime.timedelta(hours=int(off.group(2)),
                                         minutes=int(off.group(3)))
    return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())


def parse_params(body, in_url):
    """Flatten x-www-form-urlencoded params (body first, then query)."""
    from urllib.parse import parse_qsl
    out = {}
    for chunk in (body, in_url.split("?", 1)[1] if "?" in in_url else ""):
        for k, v in parse_qsl(chunk, keep_blank_values=True):
            out[k] = v
    return out


def session_log(saz_path):
    z = zipfile.ZipFile(saz_path)
    idxs = sorted({int(m.group(1)) for n in z.namelist()
                   for m in [re.match(r"raw/(\d+)_c\.txt", n)] if m})
    sessions = []
    for i in idxs:
        raw = z.read("raw/%d_c.txt" % i).decode("utf-8", "replace")
        head, _, body = raw.partition("\r\n\r\n")
        lines = head.split("\r\n")
        req_line = lines[0] if lines else "?"
        url = req_line.split(" ")[1] if " " in req_line else req_line
        status = ""
        try:
            sraw = z.read("raw/%d_s.txt" % i).decode("utf-8", "replace")
            status = sraw.split("\r\n")[0]
        except KeyError:
            pass
        auth = re.search(r"Authorization: Signature (signature=\"[^\"]+\".*)",
                         head)
        entry = {"session": i, "request": req_line, "status": status,
                 "url": url.split("?")[0]}
        if not auth:
            entry["error"] = "no adj9 Authorization header"
            sessions.append(entry)
            continue
        entry["authorization"] = auth.group(1)
        sig_m = re.search(r'signature="([A-Za-z0-9+/=]+)"', auth.group(1))
        sig = base64.b64decode(sig_m.group(1))
        entry["sig_len"] = len(sig)
        entry["sig_hex"] = sig.hex()
        hdr, body_b = sig[:16], sig[16:]
        entry["header_hex"] = hdr.hex()
        entry["body_dwords"] = ["%08x" % v for v in struct.unpack(">44I", body_b)]
        # header-law check against the request's own created_at
        params = parse_params(body, url)
        entry["params"] = params
        sec = parse_created_at(params.get("created_at", ""))
        law = None
        for off in (1, 0, 2, 3):
            if sec is not None and hdr == make_header(sec + off):
                law = sec + off
                break
        entry["created_at_sec"] = sec
        entry["header_law_second"] = law
        entry["header_law_match"] = law is not None
        if law:
            entry["signed_at_utc"] = datetime.datetime.fromtimestamp(
                law, datetime.timezone.utc).isoformat()
        sessions.append(entry)
    return sessions


def main():
    saz = sys.argv[1] if len(sys.argv) > 1 else \
        "C:/Users/Downloads/pentindroid_logs.saz"
    print("SAZ:", saz)
    sessions = session_log(saz)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "saz_sessions.json")
    json.dump(sessions, open(out, "w"), indent=1)
    for s in sessions:
        print("=" * 78)
        print("SESSION %d  %s" % (s["session"], s.get("request", "")))
        print("  %s" % s.get("status", ""))
        if "error" in s:
            print("  %s" % s["error"])
            continue
        print("  Authorization: Signature %s" % s["authorization"])
        print("  signature  : %d B" % s["sig_len"])
        print("  header(16B): %s   law-match: %s%s" % (
            s["header_hex"], s["header_law_match"],
            (" @ %s (%s)" % (s["header_law_second"], s.get("signed_at_utc", "")))
            if s["header_law_match"] else ""))
        print("  body(44 dw): %s" % " ".join(s["body_dwords"][:6]))
        print("               %s …" % " ".join(s["body_dwords"][6:12]))
        print("  claims (%d params):" % len(s["params"]))
        for k in s["params"]:
            print("    %-28s %s" % (k, s["params"][k]))
    print("=" * 78)
    print("saved %s (%d sessions)" % (out, len(sessions)))


if __name__ == "__main__":
    main()
