# b_lineage.py — walk the blob-array realloc lineage from b_realloc.json,
# print the chain (chronological) with sizes; identify the data buffer alive
# when dwords 67..75 (last body dword + tag) were pushed.
import json, struct

log = json.load(open(r"b_realloc.json"))
BLOB0 = 0x40e0f783
FINAL_OLD = 0x9004e20

def is_blob_head(rec):
    # array stores blob dwords BE -> dword0 value 0x40e0f783 appears LE as
    # bytes 83 f7 e0 40
    h = rec.get("head")
    return h and h[:8] == "83f7e040"

# chronological chain: start at first realloc whose NEW buffer holds blob head
start = None
for i, r in enumerate(log):
    if is_blob_head(r):
        start = i
        break
print("first blob-head realloc idx %d: old=%#x n=%d -> new=%#x" %
      (start, log[start]["old"], log[start]["n"], log[start]["new"]))
chain = [log[start]]
cur = log[start]["new"]
for r in log[start + 1:]:
    if r["old"] == cur and r["n"] >= 4:
        chain.append(r)
        cur = r["new"]
        if r["new"] == FINAL_OLD:
            break
print("chain length %d, cur=%#x" % (len(chain), cur))
for j, r in enumerate(chain):
    note = ""
    if r["n"] >= 268 and r["n"] <= 384:
        note = "  <-- tag window"
    print("  [%3d] realloc(old=%#x, n=%-5d) -> %#x %s%s" %
          (j, r["old"], r["n"], r["new"],
           "BLOBHEAD" if is_blob_head(r) else "", note))
