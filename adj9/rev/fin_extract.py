"""fin_extract.py — extract the FIRST signing's inputs from device/whcap_hits7.json
(live Frida EMIT trace, {tag:"emit", sink, pos, val}) and build the emulator
descriptors.

Findings this script encodes (verified 2026-09-12 against the data):

* The trace holds THREE signings. The FIRST one (field loop at event 0) is
  nsign record #7 of device/adj9_wh4.log — blob 5595c3c4…, ts 1789240514238,
  claims created_at 2026-09-12T21:15:11.678Z+0200 — NOT nsign #0 (211c2cd4,
  created_at 21:07:55). Proof: all 48 dwords of 5595c3c4 occur in the trace
  (sink …f52fd970 last-write map == blob, 48/48); 211c2cd4's dwords occur
  nowhere. Header law: blob7 == make_header(1789240512).
* Field loop = 9 sink-runs of 36,5,4,8,1,1,90,1,1 dwords (descriptors
  #0,#9,#8,#4,#2,#7,#10,#5,#6; #1/#3 empty, no EMITs), positions strictly
  sequential from 0, one distinct sink per field.
* The merge phase = the next 205 EMITs, all into ONE sink (…2fdee0), starting
  (pos 0, 0x19), (pos 0, 0x3d) — the 0x19 handshake.

Output: fin_descs.json with descs (va_list order), merge ground truth, target.
"""
import json
import re
import struct
import sys

HERE = "C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
DEV = "C:/Users/Apps/Downloads/com.penti.app/adj9/device"

# va_list pass order (slice 78, live-proven): descriptor build-idx per slot.
# CORRECTED 2026-09-13 (fin_dbg3/fin_result): the field capture's x28 (va_list
# overflow ptr) jumps +16 between the slot-7 and slot-8 field runs — an EMPTY
# descriptor occupies va position 8. Native merge block 0x129220 reads
# OUTLEN(ctx[8]) = 0 there (empty sink); with #6 at position 8 the emulator
# computed 1 and every later merge position drifted +1. #1 (empty) sits at
# position 8, #6 (1 dw) at position 9; #5/#6 and #1/#3 are mutually
# indistinguishable (1-dw zero / empty) so this choice is canonical.
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
FIELD_LENS = {0: 36, 9: 5, 8: 4, 4: 8, 2: 1, 7: 1, 10: 90, 5: 1, 6: 1, 1: 0, 3: 0}
# claims descriptor (#10) = 90 dwords in this signing (RT length; asserted below)


def load_events():
    d = json.load(open(DEV + "/whcap_hits7.json"))
    return [e for e in d if e.get("tag") == "emit"]


def seg_field_loop(evs):
    """Consume the first signing's field loop: per-field sink runs with the
    known dword counts, sequential positions, distinct sink per field."""
    fields = []          # (build_idx, sink, [vals])
    i = 0
    for k, bidx in enumerate(VA_ORDER):
        n = FIELD_LENS[bidx]
        if n == 0:
            fields.append((bidx, None, []))
            continue
        sink = evs[i]["sink"]
        vals = []
        for j in range(n):
            e = evs[i + j]
            assert e["sink"] == sink, "field %d: sink changed mid-field at +%d" % (bidx, j)
            assert int(e["pos"], 16) == j, "field %d: pos %d != %d" % (bidx, int(e["pos"], 16), j)
            vals.append(int(e["val"], 16))
        if fields and fields[-1][1] == sink:
            raise AssertionError("field %d reuses previous field's sink" % bidx)
        fields.append((bidx, sink, vals))
        i += n
    return fields, i


def seg_merge(evs, i):
    """The merge ground truth: the contiguous same-sink run after the field
    loop (205 events into …2fdee0, the 0x19 handshake first)."""
    sink = evs[i]["sink"]
    evs_m = []
    while i < len(evs) and evs[i]["sink"] == sink:
        evs_m.append((int(evs[i]["pos"], 16), int(evs[i]["val"], 16)))
        i += 1
    assert evs_m[0] == (0, 0x19), "merge does not start with the 0x19 handshake: %r" % (evs_m[0],)
    return sink, evs_m, i


def nsign_records():
    log = open(DEV + "/adj9_wh4.log", "rb").read().decode("utf-8", errors="replace")
    recs = re.findall(
        r"###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n"
        r"text: len=(\d+)\nnano_out=(\d+)\nhex=([0-9a-f]+)", log)
    return [(int(ts), bytes.fromhex(hx)) for ts, l, nano, hx in recs]


def main():
    evs = load_events()
    print("emit events in trace: %d" % len(evs))
    fields, i = seg_field_loop(evs)
    print("field loop: %d events consumed" % i)
    for bidx, sink, vals in fields:
        if vals:
            print("  #%2d: %3d dw sink …%s  head %s"
                  % (bidx, len(vals), sink[-6:], " ".join("%08x" % v for v in vals[:4])))
        else:
            print("  #%2d: empty" % bidx)
    assert len(fields[0][2]) == 36 and fields[0][0] == 0
    merge_sink, merge, i2 = seg_merge(evs, i)
    print("merge ground truth: %d events into sink …%s (events %d..%d)"
          % (len(merge), merge_sink[-6:], i, i2 - 1))
    print("  first 6:", [(p, "%08x" % v) for p, v in merge[:6]])

    # ---- descriptor blobs ----
    def dw2bytes(vals):
        return b"".join(struct.pack(">I", v) for v in vals)

    by_idx = {bidx: vals for bidx, sink, vals in fields}
    descs = []
    for bidx in VA_ORDER:
        vals = by_idx[bidx]
        descs.append({"build_idx": bidx, "len_dw": len(vals),
                      "data_hex": dw2bytes(vals).hex()})
    # sanity: #9 = cert SHA1, #4 = H, #10 = 90-dw claims with adj_verification head
    assert by_idx[9] == [0xFAD0F10D, 0x60F93C17, 0x937B2F1E, 0xB6C09691, 0xAE7D74BD]
    assert by_idx[10][0] == 0x4B6C6341 and len(by_idx[10]) == 90
    assert by_idx[5] == [0] and by_idx[6] == [0]

    # ---- target blobs ----
    recs = nsign_records()
    tgt_aligned = None
    for ts, blob in recs:
        if blob[:4] == bytes.fromhex("5595c3c4"):
            tgt_aligned = (ts, blob)
    assert tgt_aligned, "blob 5595c3c4 not found in adj9_wh4.log nsign records"

    out = {
        "source": "device/whcap_hits7.json (first signing = adj9_wh4.log nsign #7)",
        "va_order": VA_ORDER,
        "descs": descs,
        "merge_sink": merge_sink,
        "merge_events": [[p, v] for p, v in merge],
        "target": {
            "blob_hex": tgt_aligned[1].hex(),
            "nsign_ts": tgt_aligned[0],
            "second": 1789240512,
            "second_basis": "header law (rev/header_gen.py Random3) — unique hit in 1789240400..1789240600",
            "created_at": "2026-09-12T21:15:11.678Z+0200",
        },
        "targets_not_in_trace": {
            "note": "the trace's first signing is nsign #7, not #0; other blobs' "
                    "dwords occur nowhere in the trace",
            "first_blob_hex": recs[0][1].hex(),
            "first_blob_ts": recs[0][0],
        },
        "field_event_counts": {str(b): len(by_idx[b]) for b in VA_ORDER},
    }
    with open(HERE + "/fin_descs.json", "w") as f:
        json.dump(out, f, indent=1)
    print("wrote fin_descs.json: %d descs, %d merge events, target blob %s…"
          % (len(descs), len(merge), tgt_aligned[1].hex()[:16]))


if __name__ == "__main__":
    main()
