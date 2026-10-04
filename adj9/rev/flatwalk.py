"""flatwalk.py — decode small O-LLVM flattened fns: resolve the entry token
(writes to the state reg before the dispatch head), then walk the dispatch
chain and print each state's handler instructions in execution order."""
import sys
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True

def parse_int(s):
    try:
        return int(s.strip().lstrip("#"), 16)
    except (ValueError, AttributeError):
        return None

def flatwalk(fn, end, state_reg="x9", head=None, max_steps=40):
    insns = list(md.disasm(elf[fn:end], fn))
    idx = {i.address: k for k, i in enumerate(insns)}
    # entry token: simulate mov/movk on state reg from fn start to head
    if head is None:
        # head = first 'cmp STATE, XREG' after the prologue movs
        for k, i in enumerate(insns):
            if i.mnemonic == "cmp" and i.op_str.startswith(state_reg + ","):
                head = k
                break
    tok = 0
    for i in insns[:head]:
        if i.mnemonic == "mov" and i.op_str.startswith(state_reg + ", #"):
            tok = parse_int(i.op_str.split("#")[1]) or 0
        elif i.mnemonic == "movk" and i.op_str.startswith(state_reg + ", #"):
            part = i.op_str
            imm = parse_int(part.split("#")[1].split(",")[0])
            sh = 0
            if "lsl #" in part:
                sh = parse_int(part.split("lsl #")[1])
            tok = (tok & ~(0xFFFF << sh)) | (imm << sh)
    print("fn 0x%x entry token = 0x%x (head @0x%x)" % (fn, tok, insns[head].address))
    # build token -> handler map from the chain
    # chain: cmp STATE, R; b.eq TGT  (R materialized just before)
    other = {}
    cur_other = None
    for k in range(head, len(insns)):
        i = insns[k]
        if i.mnemonic == "mov" and i.op_str.startswith(state_reg + ", #"):
            tok2 = parse_int(i.op_str.split("#")[1]) or 0
            other[tok2] = True
        if i.mnemonic == "movk" and i.op_str.startswith(state_reg + ", #"):
            pass
    # simpler: walk the chain linearly, tracking 'other reg' materialization
    # the chain uses: cmp x9, x28 etc. — the other reg holds a token
    # We'll find for each cmp the nearest preceding materialization of the other reg.
    state = tok
    seen = set()
    for step in range(max_steps):
        if state in seen:
            print("  [state 0x%x repeats — stop]" % state)
            break
        seen.add(state)
        # find handler: scan chain for cmp STATE,<reg> with reg==token, then b.eq tgt
        # rebuild reg materialization map each scan (cheap for small fns)
        k = head
        regs = {}
        found = None
        while k < len(insns):
            i = insns[k]
            if i.mnemonic in ("mov", "movk") and i.op_str.startswith(state_reg + ","):
                pass
            # materialization of any OTHER reg via mov/movk
            import re
            m = re.match(r"^(x\d+), #(0x[0-9a-f]+)$", i.op_str.replace(" ", "")) if i.mnemonic == "mov" else None
            if m and m.group(1) != state_reg:
                regs[m.group(1)] = int(m.group(2), 16)
            if i.mnemonic == "movk":
                mm = re.match(r"^(x\d+), #(0x[0-9a-f]+), lsl #(\d+)$", i.op_str.replace(" ", ""))
                if mm and mm.group(1) != state_reg:
                    r, imm, sh = mm.group(1), int(mm.group(2), 16), int(mm.group(3))
                    base = regs.get(r, 0)
                    regs[r] = (base & ~(0xFFFF << sh)) | (imm << sh)
            if i.mnemonic == "cmp" and i.op_str.replace(" ", "").startswith(state_reg + ",x"):
                r = i.op_str.split(",")[1].strip()
                if r in regs and regs[r] == state:
                    # next branch
                    for j in range(k + 1, min(k + 3, len(insns))):
                        if insns[j].mnemonic in ("b.eq", "b.ne"):
                            tgt = parse_int(insns[j].op_str)
                            if insns[j].mnemonic == "b.eq" and tgt != fn:
                                found = (tgt, i.address)
                            break
                    if found:
                        break
            k += 1
        if not found:
            print("  state 0x%x: no handler (exit)" % state)
            break
        tgt, cmp_addr = found
        print("  state 0x%-012x -> handler 0x%x (cmp @0x%x)" % (state, tgt, cmp_addr))
        # print handler until it sets the next state (mov/movk state_reg) and branches to head
        k = idx.get(tgt)
        nxt = None
        while k is not None and k < len(insns):
            i = insns[k]
            print("      %06x: %-7s %s" % (i.address, i.mnemonic, i.op_str))
            if (i.mnemonic in ("mov", "movk")) and i.op_str.startswith(state_reg + ","):
                # re-materialize
                if i.mnemonic == "mov":
                    v = parse_int(i.op_str.split("#")[1]) if "#" in i.op_str else None
                    nxt = v
                else:
                    part = i.op_str
                    imm = parse_int(part.split("#")[1].split(",")[0])
                    sh = parse_int(part.split("lsl #")[1]) if "lsl #" in part else 0
                    base = nxt if nxt is not None else 0
                    nxt = (base & ~(0xFFFF << sh)) | (imm << sh)
            if i.mnemonic == "b" and parse_int(i.op_str) == insns[head].address:
                break
            if i.mnemonic == "ret":
                print("      [ret]")
                return
            k += 1
        if nxt is None:
            print("  [state chain broke]")
            break
        state = nxt

if __name__ == "__main__":
    fn = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16)
    flatwalk(fn, end)
