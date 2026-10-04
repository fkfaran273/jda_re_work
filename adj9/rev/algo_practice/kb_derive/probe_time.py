"""probe_time.py — time one FinEx signing run (PENTI_CORPUS) without logging."""
import sys, time, struct
sys.path.insert(0, "C:/Users/Apps/Downloads/com.penti.app/adj9sign")
sys.path.insert(0, "C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/kb_derive")
import signer_simple as sg
from corpus_pc import PENTI_CORPUS


def build_descs(claims_raw, d0, d4, d2, cert):
    padded = claims_raw + b"\x00" * (-len(claims_raw) % 4)
    by = {0: (36, 0, d0),
          9: (5, 0, cert), 8: (4, 0, bytes.fromhex("bffffffffffffd1f0007000000000000")),
          4: (8, 0, d4),
          2: (1, 0, d2),
          7: (1, 0, struct.pack(">I", len(claims_raw))),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, b"\x00\x00\x00\x00"),
          6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in sg.VA_ORDER]


def corpus_descs():
    pc = PENTI_CORPUS
    return build_descs(bytes.fromhex(pc["d10"])[:pc["unpadded"]],
                       bytes.fromhex(pc["d0"]), bytes.fromhex(pc["d4"]),
                       bytes.fromhex(pc["d2"]), bytes.fromhex(pc["d9"]))


if __name__ == "__main__":
    descs = corpus_descs()
    t0 = time.time()
    blob, info = sg.finex_mint(descs, PENTI_CORPUS["second"], max_steps=60_000_000)
    t1 = time.time()
    good = blob == bytes.fromhex(PENTI_CORPUS["blob_hex"])
    print("steps=%d status=%s time=%.1fs byte-exact=%s" %
          (info["steps"], info["status"], t1 - t0, good))
