"""Passthrough CONNECT proxy -- relays bytes unmodified, logs everything.

Unlike Fiddler/mitmproxy this does NO TLS interception: the client's real
TLS handshake (ClientHello) passes through byte-for-byte and is logged to
disk.  No CA trust is needed on the device, nothing on the device changes.

Outputs (in tunnel_cap/):
  master.jsonl                  -- one event line per connection (live)
  <id>_<host>_c2s.bin           -- raw client -> server bytes (ClientHello here)
  <id>_<host>_s2c.bin           -- raw server -> client bytes (ServerHello here)
  <id>_<host>_connect.txt       -- the CONNECT request line + headers (plaintext)
"""
import asyncio
import json
import os
import re
import sys
import time

LISTEN_PORT = 8889
HERE = os.path.dirname(os.path.abspath(__file__))

_logf = open(os.path.join(HERE, "master.jsonl"), "a", buffering=1)
_seq = [0]


def ev(**kw):
    kw["t"] = round(time.time(), 3)
    _logf.write(json.dumps(kw) + "\n")


async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter,
               path: str, ev_end: str, cid: str, target: str):
    total = 0
    try:
        with open(path, "wb") as f:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                total += len(data)
                f.write(data)
                try:
                    dst.write(data)
                    await dst.drain()
                except (ConnectionError, RuntimeError, BrokenPipeError):
                    break
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass
    try:
        dst.close()
    except Exception:
        pass
    ev(id=cid, event=ev_end, target=target, bytes=total)


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    cid = "%d_%d" % (int(time.time()), _seq[0])
    _seq[0] += 1
    peer = writer.get_extra_info("peername")
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=60)
    except Exception:
        writer.close()
        return
    if not line:
        writer.close()
        return
    head = line.decode("latin1").strip()

    if head.upper().startswith("CONNECT"):
        # slurp the rest of the CONNECT header block (plaintext, fingerprint)
        hdr = []
        while True:
            h = await asyncio.wait_for(reader.readline(), timeout=30)
            if h in (b"\r\n", b"\n", b""):
                break
            hdr.append(h.decode("latin1").rstrip("\r\n"))
        m = re.match(r"CONNECT\s+(\S+)", head, re.I)
        target = m.group(1) if m else "?"
        host, _, port = target.partition(":")
        port = int(port or 443)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
        ev(id=cid, event="connect", target=target,
           peer="%s:%s" % (peer[0], peer[1]), connect_headers=hdr)
        with open(os.path.join(HERE, "%s_%s_connect.txt" % (cid, safe)), "w") as f:
            f.write(head + "\r\n" + "\r\n".join(hdr) + "\r\n")
        try:
            ur, uw = await asyncio.open_connection(host, port)
        except Exception as e:
            ev(id=cid, event="upstream_fail", target=target, err=repr(e))
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        ev(id=cid, event="tunnel_open", target=target)
        t1 = asyncio.create_task(pump(reader, uw,
                                      os.path.join(HERE, "%s_%s_c2s.bin" % (cid, safe)),
                                      "tunnel_closed", cid, target))
        t2 = asyncio.create_task(pump(ur, writer,
                                      os.path.join(HERE, "%s_%s_s2c.bin" % (cid, safe)),
                                      "tunnel_closed", cid, target))
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for p in pending:
            p.cancel()
        ev(id=cid, event="tunnel_done", target=target)
    else:
        # Plain-HTTP request through the proxy (absolute-form): log it fully,
        # this is the only case where we see plaintext request bytes.
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", head.split(" ")[1][:80] if " " in head else "req")
        ev(id=cid, event="plain_http", peer="%s:%s" % (peer[0], peer[1]), line=head)
        with open(os.path.join(HERE, "%s_%s_plain_c2s.bin" % (cid, safe)), "wb") as f:
            f.write(line)
            try:
                while True:
                    h = await asyncio.wait_for(reader.readline(), timeout=30)
                    f.write(h)
                    if h in (b"\r\n", b"\n", b""):
                        break
            except Exception:
                pass
        host_m = re.search(r"[^/]*/([^/:]+)(?::(\d+))?", head.split(" ")[1] if " " in head else "")
        writer.close()


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", LISTEN_PORT)
    ev(event="proxy_listening", port=LISTEN_PORT)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
