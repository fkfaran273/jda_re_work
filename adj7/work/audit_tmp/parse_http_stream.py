"""Parse raw TLS-decrypted HTTP streams into individual messages.

Usage: python parse_http_stream.py <file.bin> [--mode req|resp] [--json out.json]

Requests and responses live in separate files, in matching order per connection.
A stream may hold several connections' worth of data back to back; we split on
message boundaries using Content-Length / chunked framing.
"""
import sys, json, re

CRLF = b"\r\n"


def parse_headers(block):
    """block is everything up to (not including) CRLFCRLF; returns (start_line, headers list, rest_offset_in_block)."""
    idx = block.find(b"\r\n\r\n")
    if idx < 0:
        return None, [], 0
    head = block[:idx]
    lines = head.split(b"\r\n")
    start = lines[0]
    headers = []
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers.append((k.strip().decode("latin1"), v.strip().decode("latin1")))
    return start.decode("latin1", "replace"), headers, idx + 4


def get_header(headers, name, default=None):
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return default


def dechunk(data):
    out = bytearray()
    i = 0
    while i < len(data):
        j = data.find(b"\r\n", i)
        if j < 0:
            out += data[i:]
            break
        size_str = data[i:j].split(b";")[0].strip()
        try:
            size = int(size_str, 16)
        except ValueError:
            out += data[i:]
            break
        if size == 0:
            break
        out += data[j + 2 : j + 2 + size]
        i = j + 2 + size + 2
    return bytes(out)


def parse_stream(data, mode):
    msgs = []
    pos = 0
    n = len(data)
    guard = 0
    while pos < n:
        guard += 1
        if guard > 5000:
            msgs.append({"note": "guard-trip", "offset": pos, "raw_preview": data[pos:pos+200].decode("latin1", "replace")})
            break
        chunk = data[pos:pos + 65536]
        start, headers, bodyoff = parse_headers(chunk)
        if start is None:
            # trailing garbage without full header
            if data[pos:].strip():
                msgs.append({"note": "unparsed-tail", "offset": pos, "raw": data[pos:pos+500].decode("latin1", "replace")})
            break
        is_req = bool(re.match(r"^[A-Z]+ \S+ HTTP/", start))
        is_resp = bool(re.match(r"^HTTP/[\d.]+ \d{3}", start))
        if mode == "req" and not is_req:
            # try to resync: find next "HTTP" or method at line start
            m = re.search(rb"(?m)^(?:GET|POST|PUT|HEAD|DELETE|OPTIONS) ", data[pos:])
            if not m:
                break
            pos += m.start()
            continue
        if mode == "resp" and not is_resp:
            m = re.search(rb"(?m)^HTTP/[\d.]+ \d{3}", data[pos:])
            if not m:
                break
            pos += m.start()
            continue
        # full header block may extend beyond 64k window (unlikely); recompute on full remainder
        if pos + bodyoff > n:
            break
        full = data[pos:]
        start, headers, bodyoff = parse_headers(full)
        te = (get_header(headers, "Transfer-Encoding") or "").lower()
        cl = get_header(headers, "Content-Length")
        body = b""
        consumed = bodyoff
        if te and "chunked" in te:
            rest = full[bodyoff:]
            # exact chunked walk: size line, data, CRLF, ... until 0 chunk
            out = bytearray()
            i = 0
            ok_walk = False
            while i < len(rest):
                j = rest.find(b"\r\n", i)
                if j < 0:
                    break
                try:
                    size = int(rest[i:j].split(b";")[0].strip(), 16)
                except ValueError:
                    break
                i = j + 2
                if size == 0:
                    i += 2  # trailing CRLF after last chunk
                    ok_walk = True
                    break
                out += rest[i : i + size]
                i += size + 2
            body = bytes(out)
            consumed = (bodyoff + i) if ok_walk else n - pos
        elif cl is not None:
            clen = int(cl)
            body = full[bodyoff : bodyoff + clen]
            consumed = bodyoff + clen
        else:
            body = b""
            consumed = bodyoff
        msgs.append({
            "offset": pos,
            "start": start,
            "headers": headers,
            "body_len": len(body),
            "body": body,
        })
        pos += consumed
    return msgs


def main():
    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else None
    out_json = None
    if "--json" in sys.argv:
        out_json = sys.argv[sys.argv.index("--json") + 1]
    data = open(path, "rb").read()
    if not mode:
        # autodetect from first bytes
        mode = "req" if re.match(rb"^[A-Z]+ ", data[:16]) else "resp"
    msgs = parse_stream(data, mode)
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(msgs, f, indent=1, ensure_ascii=False, default=lambda b: b.decode("latin1", "replace") if isinstance(b, bytes) else str(b))
    for i, m in enumerate(msgs):
        print(f"=== msg#{i} offset={m.get('offset')} ===")
        print(m.get("start", m.get("note", "?")))
        for k, v in m.get("headers", []):
            print(f"  {k}: {v}")
        body = m.get("body", b"")
        if body:
            print(f"  [body {len(body)} bytes]: {body[:4000].decode('latin1', 'replace')}")
        print()


if __name__ == "__main__":
    main()
