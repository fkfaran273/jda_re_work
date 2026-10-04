"""Decode each obfuscated .data string using the XOR key taken straight from the
movi instruction in its decrypt block -> no guessing."""
import sys, os, pickle
import capstone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
from decryptors import LIB

PRINT = set(range(0x20, 0x7f))


def run(path=LIB):
    e = ELF(path)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    sites, P = pickle.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             "decrypt.pkl"), "rb"))
    out = {}
    for va in sorted(P):
        load_at, store_at = P[va]
        blob = e.read(store_at - 48, 64)
        key = None
        width = None
        for ins in md.disasm(blob, store_at - 48):
            if ins.mnemonic == "movi" and ins.operands and \
                    ins.operands[0].type == capstone.arm64.ARM64_OP_REG and \
                    len(ins.operands) > 1 and \
                    ins.operands[1].type == capstone.arm64.ARM64_OP_IMM:
                key = ins.operands[1].imm
            if ins.address == store_at:
                width = ins.mnemonic
                break
            if ins.address > store_at:
                break
        if key is None:
            continue
        raw = e.read(va, 32)
        if raw is None:
            continue
        dec = bytes(b ^ key for b in raw)
        txt = dec.split(b"\x00")[0].decode("ascii", "replace")
        if any(c not in PRINT for c in dec[:len(txt)]):
            txt = repr(dec[:16])
        out[va] = dict(text=txt, key=key, load=load_at, store=store_at,
                       bytes=len(txt) + 1)
    return out


if __name__ == "__main__":
    import datarefs as D
    refs, by_data, strs, funcs = pickle.load(open("cache.pkl", "rb"))
    res = run()
    print("%-10s %-4s %-44s %s" % ("va", "key", "string", "decrypt block"))
    for va, d in sorted(res.items()):
        fn = D.func_of(funcs, d["store"])
        print("0x%08x 0x%02x %-44s 0x%x..0x%x  fn 0x%x" %
              (va, d["key"], repr(d["text"])[:44], d["load"], d["store"], fn or 0))
