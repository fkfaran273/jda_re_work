"""hsbc_lib.py -- shared parse helpers for the HSBC 16 Oct saz analysis.

Offline only.  Parses the raw Fiddler entries the SAZ extracted to
hsbc_saz/raw/N_c.txt and returns headers, fields, blob, envelope.
"""
import base64
import datetime
import re
import urllib.parse

SAZ = r"C:\Users\Apps\Downloads\com.penti.app\manual_run\hsbc_saz\raw"

KINDS = {"07": "session", "08": "click", "09": "attribution"}


def parse_entry(sid):
    raw = open("%s\\%s_c.txt" % (SAZ, sid), "rb").read().decode("utf-8", "replace")
    head, _, body = raw.partition("\r\n\r\n")
    auth = re.search(r"Authorization: (.+)", head).group(1).strip()
    client_sdk = re.search(r"Client-SDK: (.+)", head).group(1).strip()
    first = raw.split("\r\n", 1)[0]
    method, url = first.split()[0], first.split()[1]
    if method == "POST":
        fields = dict(urllib.parse.parse_qsl(body))
    else:
        fields = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    blob = base64.b64decode(re.search(r'signature="([^"]+)"', auth).group(1))
    g = lambda k: (re.search(k + r'="([^"]*)"', auth) or [None, ""])[1]
    env = {"adj_signing_id": g("adj_signing_id"), "headers_id": g("headers_id"),
           "native_version": g("native_version"),
           "adj_verification": g("adj_verification")}
    return {"sid": sid, "kind": KINDS[sid], "method": method, "url": url,
            "fields": fields, "blob": blob, "auth": auth,
            "client_sdk": client_sdk, "env": env}


def ts_to_unix(ts):
    """'2026-10-16T14:59:35.605Z+0530' -> unix seconds (offset applied)."""
    date_part = ts[:19]                       # drop millis
    off = ts[-5:]                             # the +HHMM / -HHMM zone
    dt = datetime.datetime.strptime(date_part, "%Y-%m-%dT%H:%M:%S")
    tzsign = -1 if off[0] == "-" else 1
    tz_h, tz_m = tzsign * int(off[1:3]), tzsign * int(off[3:5])
    dt = dt - datetime.timedelta(hours=tz_h, minutes=tz_m)
    return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
