# d_tagtest.py — pure-python tag-law search over the two known emu mints.
# mint1: b_mints.json (garbage nonce, heap_full.bin belongs to this run)
# mint2: a_cache/pt1/pt.json (nonce 0011..AABB)
# Message domains: plain and swap4 (each dword reversed — the LE-word domain
# the lib assembles the blob in before the rev-copy into the output home).
import json, os, hmac, hashlib, sys

HERE = os.path.dirname(os.path.abspath(__file__))

def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))

def load_mints():
    blob1 = bytes.fromhex(list(json.load(open(os.path.join(
        HERE, "b_mints.json"))).values())[0])
    blob2 = bytes.fromhex(json.load(open(os.path.join(
        HERE, "a_cache", "pt1", "pt.json")))["blob"])
    out = []
    for b in (blob1, blob2):
        out.append(dict(hdr=b[:16], body=b[16:272], tag=b[272:304]))
    return out

def msg_forms(m):
    hb = m["hdr"] + m["body"]
    return {
        "hb": hb,
        "b": m["body"],
        "hb_sw": swap4(hb),
        "b_sw": swap4(m["body"]),
        "hdrsw_bodysw": swap4(m["hdr"]) + swap4(m["body"]),
        "hdr_bodysw": m["hdr"] + swap4(m["body"]),
    }

def try_key(key, mint, label):
    msgs = msg_forms(mint)
    t = mint["tag"]
    for mn, msg in msgs.items():
        if hmac.new(key, msg, hashlib.sha256).digest() == t:
            return ("hmac", mn, label)
    for mn, msg in msgs.items():
        if hashlib.sha256(key + msg).digest() == t:
            return ("sha_k_m", mn, label)
    for mn, msg in msgs.items():
        if hashlib.sha256(msg + key).digest() == t:
            return ("sha_m_k", mn, label)
    return None

def main():
    mints = load_mints()
    m1, m2 = mints
    kb = open(os.path.join(HERE, "keyblock192.bin"), "rb").read()
    heap = open(os.path.join(HERE, "heap_full.bin"), "rb").read()

    # sanity: no-key digest forms
    for mn, msg in msg_forms(m1).items():
        if hashlib.sha256(msg).digest() == m1["tag"]:
            print("HIT sha256(%s) plain!" % mn)

    # 1. key-block windows (all offsets, useful lengths)
    for L in (16, 20, 24, 32, 48, 64, 96, 192):
        for off in range(0, max(len(kb) - L, 0) + 1):
            for mint, mname in ((m1, "m1"), (m2, "m2")):
                r = try_key(kb[off:off + L], mint, "kb+%d/%d" % (off, L))
                if r:
                    print("HIT", r, "mint", mname,
                          kb[off:off + L].hex().upper())
                    return r

    # 2. heap windows (mint1's heap — target mint1 only; verify hits on m2)
    for L in (32, 64):
        for off in range(0, len(heap) - L):
            r = try_key(heap[off:off + L], m1, "heap+%#x/%d" % (off, L))
            if r:
                k = heap[off:off + L]
                ok2 = try_key(k, m2, "verify") is not None
                print("HIT", r, "heap+%#x/%d verify_m2=%s" % (off, L, ok2),
                      k.hex().upper())
                return r
        print("heap scan L=%d done, no hit" % L, flush=True)
    print("no hit")
    return None

if __name__ == "__main__":
    main()
