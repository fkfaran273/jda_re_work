---
title: WALL_A_SLICE_122
---

# SLICE 122 — the golden role table (decoded), and why our own mints are not equivalent

## 0. The golden capture is now fully decoded

`device/whcap_hits7.json` mixes several signings (sink addresses are recycled), so it must
be **segmented per signing** — a new signing starts when a sink that already has pos>0 in
the current segment is written again at pos 0. `rev/gold_seg.py` applies that rule:
**225 segments**, first segment = 148 emits, and it contains **exactly the descriptor set**:

| role | count | first word | `fin_descs` |
|---|---|---|---|
| #10 | 90 | `4b6c6341` ("KlcA…") | ✓ |
| #0 | 36 | `13271271` (tile ×8) | ✓ |
| #4 | 8 | `00100400` | ✓ |
| #9 | 5 | `fad0f10d` | ✓ |
| #8 | 4 | `bfffffff` | ✓ |
| #2 | 1 | `fb1a8296` | ✓ |
| #7 | 1 | `00000168` (=360) | ✓ |
| #5, #6 | 1 each | `00000000` | ✓ |
| extra | 1 | `00000019` | (unassigned) |

So the **builder writes the descriptors through the same EMIT op** (`0x146ed8`) — the
descriptor plane and the output plane share the primitive. `fin_descs.json` is a faithful
read-out of one signing, and the "descriptors are not emitted" reading of slice 119 was a
byte-order artefact (slice 121 §0) plus a segmentation artefact.

## 1. And here is the problem with our own mints

Our `nlh.a(ctx, map, H, 31)` mint (single call, `rev/wh_out1.json`, 937 emits — clean, no
contamination) yields this stream set:

```
counts: 1, 4, 8, 36, 36, 84, 107, 658
```

Compare with a real signing's descriptor roles: `#10=90, #0=36, #4=8, #9=5, #8=4, #2/#5/#6/#7=1`.

**There is no 5-word stream → `#9` is absent.** `wh_an.py` shows the same for the LENQ
plane of the earlier capture, and for both orders. Our mint therefore produces a blob but
**not the same descriptor set a real SDK signing produces** — consistent with all our
"+ captured descriptors ⇒ FinEx" arms returning `diff 44/48` (they were fed an incomplete
set), and it is a further, structural explanation for why crafted blobs never verified
server-side.

Positives confirmed in the same capture: the blob **is** assembled in-plane (its header
appears as a stream start, 150 of 937 emit values are blob words at BE form).

## 2. Consequences

1. **Capture the app's OWN signing, not our own call**, to obtain a complete descriptor set
   (that is exactly what the golden capture did — and it worked).
2. Filtering: the app signs concurrently on other threads (our first attempt recorded
   21 670 emits vs 148 for a single signing), so the capture must be limited to the
   signing's own thread/segment. Setting the thread from inside `harvest()`
   (`Process.getCurrentThreadId()`) destabilised the target on the last attempt — the
   working recipe remains *attach + arm + let the app sign* (as `whcap6.js` did), with the
   pos-0 segmentation rule applied offline.
3. With a complete set the earlier pipeline is unblocked: role table → descriptors →
   `FinEx` (byte-exact check) → derive the region → sweep → fresh-GAID proof.

## 3. Artifacts

- `rev/gold_seg.py` + `gold_seg.log` — the segmentation rule and the golden role table
- `rev/gold_map.py` + `gold_map.log` — sink census of the raw (unsegmented) golden capture
- `rev/our_roles.py` + `our_roles.log` — our mint's stream set (no `#9`)
- `rev/wh_out1.json` (clean single call), `rev/wh_out.json` (3-call), `rev/wh_out2.json` (thread attempt)
- `rev/agent/whlive_src.js` — LENQ+EMIT agent (thread-filter variant destabilised the target; the plain variant is the known-good one)
- `rev/WALL_A_SLICE_121.md`, `rev/WALL_A_SLICE_120.md`, `rev/WALL_A_SLICE_119.md`