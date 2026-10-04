"""Send ONE /session via the PC python stack THROUGH the passthrough proxy,
dumping the exact bytes http.client writes to the socket (headers+body),
so they can be diffed against the app's wire behavior byte-for-byte.

The request leaves via CONNECT 127.0.0.1:8889 -> app.adjust.com:443, so the
proxy tunnel logs also capture python's real ClientHello the same way the
app's was captured.  The adj9 blob is minted with the installed signer's
current signature (a compat shim absorbs the newer V=/pid= kwargs); the blob
value is irrelevant here -- only the wire shape is being fingerprinted.
"""
import http.client
import os
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool")

os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8889"
os.environ["HTTP_PROXY"] = "http://127.0.0.1:8889"

DUMP = os.path.join(HERE, "python_wire_send.bin")
_w = open(DUMP, "wb")

_orig_send = http.client.HTTPConnection.send


def send(self, data):
    if isinstance(data, str):
        data = data.encode("latin1")
    _w.write(b"---SEND %d bytes---\n" % len(data))
    _w.write(data)
    _w.write(b"\n---END---\n")
    _w.flush()
    return _orig_send(self, data)


http.client.HTTPConnection.send = send

import adj9_signer as S  # noqa: E402

_orig_mint = S.mint_blob


def mint_blob_compat(val, kind, second=None, V=None, pid=None, max_steps=None,
                     **kw):
    kwargs = {}
    if second is not None:
        kwargs["second"] = second
    if max_steps:
        kwargs["max_steps"] = max_steps
    return _orig_mint(val, kind, **kwargs)


S.mint_blob = mint_blob_compat

from adj9_api import Api  # noqa: E402

gps, auid = str(uuid.uuid4()), str(uuid.uuid4())
api = Api()
code, body = api.session(gps, auid)
print("code:", code)
print("body:", str(body)[:200])
print("gaids:", gps, auid)
_w.close()
