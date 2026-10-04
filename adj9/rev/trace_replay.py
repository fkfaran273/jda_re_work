"""trace_replay.py — Option C: pure-Python EMIT-trace replay (no emulator)."""
import json
import struct

HITS = "..\\device\\whcap_hits7.json"
SINK_OUT = "0xb4000078f52fd970"
BLOB = json.load(open("..\\device\\blob_whcap.json"))["blob"]


def main():
    d = json.load(open(HITS))
    recs = [h for h in d if isinstance(h, dict) and h.get("tag") == "emit"]
    print("emits:", len(recs))
    streams = {}
    for h in recs:
        s = streams.setdefault(h["sink"], {})
        s[int(h["pos"], 16)] = int(h["val"], 16) & 0xFFFFFFFF
    print("sinks:", len(streams))
    out = streams.get(SINK_OUT)
    if out is None:
        cands = [s for s in streams if s.endswith("f52fd970")]
        print("sink key variants:", cands)
        return
    env = bytes.fromhex(BLOB)
    hdr = struct.unpack(">4I", env[:16])
    body = struct.unpack(">44I", env[16:])
    got_h = tuple(out.get(i, 0) for i in range(4))
    got_b = tuple(out.get(4 + i, 0) for i in range(44))
    print("header:", sum(1 for a, b in zip(got_h, hdr) if a == b), "/4")
    print("body:", sum(1 for a, b in zip(got_b, body) if a == b), "/44")
    print("max pos on sink:", max(out))
    print("npositions:", len(out))


if __name__ == "__main__":
    main()
