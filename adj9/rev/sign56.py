"""sign56.py — direct derivation of the 56 unknown bytes from the builder sub_9afa4.

The active hypothesis (REMAINING_WORK.md §4, slice 124): the per-signing 56
unknowns are `plaintext ^ per-call keystream` inside the recursive builder
sub_9afa4 (3072 insns; each descriptor block is four words XORed with ONE key
register, then vector-XOR + 16-byte str-q to the VM queue / merge).

This probe does the inverse:
  1. Disassemble sub_9afa4 with dump_at.py (exact VA — dump_fn.py walks back to
     the *previous* function, which is why the earlier analysis was wrong).
  2. Extract the mov/movk 64-bit key-stream table.
  3. Recreate the 56-byte *plaintext* shape from side-channel structure of the
     captured region (slice 115/127):
        #0 = 144 B = W0 + tile (a 4-word cycle XOR'd) x 8  (new blob maps confirm,
        a11/a12 cycles across rows; golden rows show the 32/31/32/32/31 period-8 pattern).
        #4 = 8 words (sparse; not derived from H; slice 123/125 proven).
        #2 = 1 word (4 B).
  4. Recover per-call keys and plaintext-candidates via HM / correlation across the
     10 paired rows (pair_h3.json: H, H_ts, second, d0, d2, d4).
  5. Recompose #0/#2/#4 from (second, H, claims-geometry) if a key-registry is found;
     otherwise write the negative and close the loop.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)

LIB = os.path.join(os.path.dirname(HERE), "..", "extracted", "arm64",
                   "lib", "arm64-v8a", "libsigner.so")
if not os.path.exists(LIB):
    raise SystemExit("missing %s" % LIB)

RAW = open(LIB, "rb").read()
PHYS = RAW.find(b"sub_9afa4")
FILE_SIZE = len(RAW)

if PHYS < 0 or PHYS + 4096 > FILE_SIZE:
    raise SystemExit("can't locate sub_9afa4 (%d %d)" % (PHYS, FILE_SIZE))


def pair_h3_rows():
    return json.load(open(os.path.join(HERE, "pair_h3.json"),
                          encoding="utf-8"))


def all_rows():
    return json.load(open(os.path.join(HERE, "all_signings.json"),
                          encoding="utf-8"))


def load_fin_descs():
    return json.load(open(os.path.join(HERE, "fin_descs.json"),
                          encoding="utf-8"))


def be_words(hexs, n):
    raw = bytes.fromhex(hexs)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


def tile_abc(key):
    """Apply the per-site key to the known #0 tile-walk plaintext so we can
    test against captured rows.  Implement only if the slot-order is verified."""
    raise NotImplementedError("key application not yet wired")


if __name__ == "__main__":
    print("LIB bytes %d phys 0x%x" % (FILE_SIZE, PHYS))
    print("rows %d" % len(pair_h3_rows()))
    print("all_rows %d" % len(all_rows()))
    print("fin_descs %d" % len(load_fin_descs()["descs"]))

    # ---- step 1: exact disassembly of sub_9afa4 -------------------------
    import subprocess, tempfile
    tmp = tempfile.mkdtemp()
    hdr = os.path.join(tmp, "libsigner.so")
    off = PHYS
    end = min(off + 3072 * 4 + 64, FILE_SIZE)
    name = "sub_9afa4.bin"
    open(os.path.join(tmp, name), "wb").write(RAW[off:end])
    # build a minimal header so capstone/objdump can parse
    # As Fallback: use objdump -D -b binary -m aarch64 on the raw slice

    import shutil
    try:
        shutil.which("objdump")  # noqa
        print("objdump available")
    except Exception as e:
        print("no objdump %s" % e)
        raise SystemExit("no objdump")

    out = subprocess.check_output(
        ["objdump", "-D", "-b", "binary", "-m", "aarch64",
         "-M", "little", "-M", "arch=armv8-a+crypto",
         os.path.join(tmp, name)])
    open(os.path.join(HERE, "sub_9afa4_disasm.txt"), "wb").write(out)
    print("wrote sub_9afa4_disasm.txt %d bytes" % len(out))
