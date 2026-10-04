import json, struct, sys
sys.path.insert(0, ".")
import emu_8d6f4 as E
from unicorn import *
from unicorn.arm64_const import *

e = E.Emu()
icount = [0]
def ichook(uc, address, size, ud):
    icount[0] += 1
e.mu.hook_add(UC_HOOK_CODE, ichook)

emits = []
def emithook(uc, address, size, ud):
    x1 = uc.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFFFFFF
    w2 = uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
    w3 = uc.reg_read(UC_ARM64_REG_X3) & 0xFFFFFFFF
    emits.append((icount[0], x1, w2, w3))
e.mu.hook_add(UC_HOOK_CODE, emithook, begin=0x146ED8, end=0x146ED8)

# capture #0/#2/#4 buffer contents at each rand draw
WATCH = (0x300000ffd20, 0x300000ffd30, 0x300000ffd50)
snaps = []
def rndhook(uc, address, size, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    kind = "rand-pre" if pc == 0x12A2FC else "rand-post"
    def rd(a, n):
        try: return bytes(uc.mem_read(a, n)).hex()
        except UcError: return None
    snaps.append((kind, icount[0], uc.reg_read(UC_ARM64_REG_X0),
                  rd(0x300000ffd20,4), rd(0x300000ffd30,32), rd(0x300000ffd50,144)))
e.mu.hook_add(UC_HOOK_CODE, rndhook, begin=0x12A2F8, end=0x12A2FC)
e.mu.hook_add(UC_HOOK_CODE, rndhook, begin=0x12A318, end=0x12A31C)

# snapshot at serializer
def serhook(uc, address, size, ud):
    def rd(a, n):
        try: return bytes(uc.mem_read(a, n)).hex()
        except UcError: return None
    snaps.append(("SER", icount[0], 0,
                  rd(0x300000ffd20,4), rd(0x300000ffd30,32), rd(0x300000ffd50,144)))
e.mu.hook_add(UC_HOOK_CODE, serhook, begin=0x12D39C, end=0x12D39C)

# SetByteArrayRegion: dump blob source
blobsrc = []
_base_hook = E.Emu.hook_jni
def hooked(self, uc, address, size, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    nm = E.JNI_NAMES.get(pc - E.MAGIC, "")
    if nm == "SetByteArrayRegion":
        try:
            blobsrc.append((icount[0], uc.reg_read(UC_ARM64_REG_X2), uc.reg_read(UC_ARM64_REG_X3),
                            bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X4), uc.reg_read(UC_ARM64_REG_X3))).hex()))
        except UcError:
            pass
    return _base_hook(self, uc, address, size, ud)
E.Emu.hook_jni = hooked

st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
print("stopped", st, "emits", len(emits), "snaps", len(snaps), "blobsrc", len(blobsrc))
out = {"emits": emits, "snaps": snaps, "blobsrc": blobsrc,
       "blob": e.result.get("blob").hex() if e.result.get("blob") else None,
       "rand": e.rand_calls}
json.dump(out, open("fill_runs/emit_trace.json","w"), indent=0)
# summarize emit phases
seen = []
for (ic, s, n, v) in emits:
    if not seen or seen[-1][0] != s:
        seen.append([s, ic, 0])
for s in seen: pass
import itertools
by_stream = {}
for (ic, s, n, v) in emits:
    by_stream.setdefault(s, []).append((ic, n, v))
print("distinct streams:", len(by_stream))
for s, evs in sorted(by_stream.items(), key=lambda kv: -len(kv[1]))[:8]:
    print("stream %x: %d emits, icount %d..%d, pos 0..%d" % (s, len(evs), evs[0][0], evs[-1][0], max(n for _,n,_ in evs)))
print("rand snaps:")
for s in snaps:
    if s[0].startswith("rand") or s[0]=="SER":
        print("  %s ic=%d #2=%s #4[:8]=%s #0[:8]=%s" % (s[0], s[1], s[3][:8], s[4][:16], s[5][:8]))
