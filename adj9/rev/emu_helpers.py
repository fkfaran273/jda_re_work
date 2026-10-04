"""emu_helpers.py - pin the semantics of the wire-builder helper primitives
(0x147630 push / 0x147734 pop / 0x147a20 / 0x14784c / 0x147c68 / 0x147620 /
0x146558 / 0x147d3c / 0x147120 / 0x147220 / 0x1472e8 / 0x147304 / 0x146ed8)
by running them under Unicorn on synthetic inputs.

Usage: python emu_helpers.py [name ...]
"""
import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import *
from unicorn.arm64_const import *

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from decryptors import LIB

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

# --- PLT name map (reuse elf.py)
from elf import ELF
E = ELF(LIB)
PLT_NAME = {va: nm for nm, va in E.imports.items()}

STACK = 0x10000000        # stack region
HEAP = 0x20000000         # bump heap
LIBB = 0x0                # library mapped at 0

mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
mu.mem_map(0, 0x160000)
mu.mem_write(0, elf[:0x160000])
mu.mem_map(STACK, 0x100000)
mu.mem_map(HEAP, 0x100000)

bump = [HEAP + 0x1000]


def calloc(nm, sz):
    a = bump[0]
    bump[0] += (sz + 0xF) & ~0xF
    mu.mem_write(a, b"\x00" * sz)
    return a


def hook_plt(uc, address, size, ud):
    nm = PLT_NAME.get(address)
    if nm is None:
        return
    lr = uc.reg_read(UC_ARM64_REG_LR)
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)
    if nm == "calloc":
        r = calloc("calloc", x1)
    elif nm == "malloc":
        r = calloc("malloc", x0)
    elif nm == "realloc":
        old, n = x0, x1
        r = calloc("realloc", n)
        if old:
            # old size unknown; copy n bytes (bump heap is zeroed so safe)
            data = uc.mem_read(old, min(n, 0x10000))
            uc.mem_write(r, bytes(data))
    elif nm == "free":
        r = 0
    else:
        print("  !! unhandled PLT", nm)
        r = 0
    uc.reg_write(UC_ARM64_REG_X0, r)
    uc.reg_write(UC_ARM64_REG_PC, lr)


mu.hook_add(UC_HOOK_CODE, hook_plt, begin=min(PLT_NAME), end=max(PLT_NAME) + 4)


def call(addr, args, listdump=None):
    sp = STACK + 0x80000
    RETMAGIC = STACK + 0x1000
    regs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3]
    for r, v in zip(regs, args):
        mu.reg_write(r, v)
    mu.reg_write(UC_ARM64_REG_SP, sp)
    mu.reg_write(UC_ARM64_REG_LR, RETMAGIC)
    try:
        mu.emu_start(addr, RETMAGIC, count=2000000)
    except UcError as e:
        print("  UC ERROR", e, "pc=0x%x" % mu.reg_read(UC_ARM64_REG_PC))
        return None
    return mu.reg_read(UC_ARM64_REG_X0)


def new_list(vals):
    """build a pushdown list struct with head->... (vals[0] = top after pushes)"""
    lst = calloc("list", 0x10)
    mu.mem_write(lst, struct.pack("<II6x", 0, 0))
    for v in reversed(vals):
        call(0x147630, [0xDEAD, lst, v & 0xFFFFFFFF])
    return lst


def read_list(lst):
    cnt = struct.unpack("<I", mu.mem_read(lst, 4))[0]
    out = []
    node = struct.unpack("<Q", mu.mem_read(lst + 8, 8))[0]
    while node:
        raw = mu.mem_read(node, 0x10)
        val = struct.unpack("<I", raw[:4])[0]
        nxt = struct.unpack("<Q", raw[8:16])[0]
        out.append(val)
        node = nxt
    return cnt, out


def new_vm(bufwords=None, cursor=None):
    """vm object, layout read off the disasm of 0x146ed8/0x1472e8/0x147304/0x147120:
        +0x00  u32  limit   (out capacity in dwords; emit grows it by 0x80)
        +0x08  u64  out     (dword buffer)
        +0x10  u32  cursor  (words emitted so far)
        +0x14  u32  ssp     (save-stack pointer, entries used)
        +0x18  u64  savestack  (u32 array; base of current frame = savestack[ssp-1])
    """
    vm = calloc("vm", 0x20)
    buf = calloc("buf", 0x1000)
    n = len(bufwords) if bufwords else 0
    if bufwords:
        mu.mem_write(buf, b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in bufwords))
    savestack = calloc("sav", 0x100)
    mu.mem_write(vm, struct.pack("<I4xQIIQ", 0x400, buf,
                                 cursor if cursor is not None else n,
                                 1 if bufwords is not None else 0,
                                 savestack))
    if bufwords is not None:
        mu.mem_write(savestack, struct.pack("<I", 0))   # frame base 0
    return vm, buf


def show(tag, lst, vm=None):
    cnt, vals = read_list(lst)
    print("  %s list(count=%d, top->bottom)=%s" % (tag, cnt, [hex(v) for v in vals]))
    if vm is not None:
        limit, buf, cur, ssp, ss = struct.unpack("<I4xQIIQ", mu.mem_read(vm, 0x20))
        words = struct.unpack("<%dI" % max(cur, 1), mu.mem_read(buf, 4 * max(cur, 1)))
        print("     vm: limit=%d cursor=%d ssp=%d out=%s" % (limit, cur, ssp, [hex(w) for w in words[:16]]))


TESTS = {}

def test(name):
    def deco(fn):
        TESTS[name] = fn
        return fn
    return deco


@test("a20")
def t_a20():
    print("== 0x147a20(engine, list, 1) on list [A=0x111, B=0x222] (top first)")
    bump[0] = HEAP + 0x1000
    lst = new_list([0x111, 0x222])
    show("before", lst)
    r = call(0x147A20, [0xDEAD, lst, 1])
    show("after ", lst)
    print("  ret=0x%x" % (r or 0))


@test("a20_3")
def t_a20_3():
    print("== 0x147a20(engine, list, 3) on list [1,2,3,4]")
    bump[0] = HEAP + 0x1000
    lst = new_list([1, 2, 3, 4])
    show("before", lst)
    call(0x147A20, [0xDEAD, lst, 3])
    show("after ", lst)


@test("a20_0")
def t_a20_0():
    print("== 0x147a20(engine, list, 0) on list [1,2,3]")
    bump[0] = HEAP + 0x1000
    lst = new_list([1, 2, 3])
    show("before", lst)
    call(0x147A20, [0xDEAD, lst, 0])
    show("after ", lst)


@test("h84c")
def t_84c():
    print("== 0x14784c(engine, list, 1) on list [A=0x111, B=0x222]")
    bump[0] = HEAP + 0x1000
    lst = new_list([0x111, 0x222])
    show("before", lst)
    call(0x14784C, [0xDEAD, lst, 1])
    show("after ", lst)


@test("h84c_vm")
def t_84c_vm():
    print("== 0x14784c(engine, list, 1) with x20={list,vm} variant? plain list")
    bump[0] = HEAP + 0x1000
    lst = new_list([5, 7, 9])
    show("before", lst)
    call(0x14784C, [0xDEAD, lst, 1])
    show("after ", lst)


@test("c68")
def t_c68():
    print("== 0x147c68(engine, list, 0x55) on list [1,2]")
    bump[0] = HEAP + 0x1000
    lst = new_list([1, 2])
    show("before", lst)
    call(0x147C68, [0xDEAD, lst, 0x55])
    show("after ", lst)


@test("p620")
def t_620():
    print("== 0x147620(engine, list, 0x77) on list [1,2]")
    bump[0] = HEAP + 0x1000
    lst = new_list([1, 2])
    show("before", lst)
    call(0x147620, [0xDEAD, lst, 0x77])
    show("after ", lst)


@test("p630")
def t_630():
    print("== 0x147630(engine, list, 0x77) on list [1,2]")
    bump[0] = HEAP + 0x1000
    lst = new_list([1, 2])
    show("before", lst)
    call(0x147630, [0xDEAD, lst, 0x77])
    show("after ", lst)


@test("p6558")
def t_6558():
    print("== 0x146558(engine, list, 0x77) on list [1,2]")
    bump[0] = HEAP + 0x1000
    lst = new_list([1, 2])
    show("before", lst)
    call(0x146558, [0xDEAD, lst, 0x77])
    show("after ", lst)


@test("emit")
def t_emit():
    print("== 0x146ed8(status, vm, w2=3, w3=0xABCD) with vm out=[10..80], cursor=8, base=0")
    bump[0] = HEAP + 0x1000
    vm, buf = new_vm([10, 20, 30, 40, 50, 60, 70, 80], cursor=8)
    status = calloc("status", 8)
    def vmstate():
        lim, b, cur, ssp, ss = struct.unpack("<I4xQIIQ", mu.mem_read(vm, 0x20))
        n = max(lim, 16)
        words = struct.unpack("<%dI" % n, mu.mem_read(b, 4 * n))
        return lim, cur, ssp, [hex(w) for w in words]
    print("  before:", vmstate())
    call(0x146ED8, [status, vm, 3, 0xABCD])
    print("  after :", vmstate(), "status=%d (expect untouched 0)" % struct.unpack("<I", mu.mem_read(status, 4))[0])
    # overwrite path: cursor must NOT advance when writing below cursor
    call(0x146ED8, [status, vm, 1, 0x1111])
    print("  overw :", vmstate())
    # grow path: write at 0x400 (== limit) must realloc +0x80 dwords and bump limit
    call(0x146ED8, [status, vm, 0x400, 0x2222])
    lim, cur, ssp, words = vmstate()
    print("  grow  : limit=%d (expect 0x480) out[0x400]=%s cursor=%d" % (lim, words[0x400], cur))


@test("read")
def t_read():
    print("== 0x147304(vm, w1) reads out[base+w1] (0 if >= limit)")
    bump[0] = HEAP + 0x1000
    vm, buf = new_vm([10, 20, 30, 40, 50, 60, 70, 80], cursor=8)
    r = call(0x147304, [vm, 2])
    print("  ret=0x%x (expect 30)" % (r or 0))
    r = call(0x147304, [vm, 7])
    print("  ret=0x%x (expect 80)" % (r or 0))
    r = call(0x147304, [vm, 9])
    print("  ret=0x%x (expect 0: zeroed buffer slot beyond cursor, idx 9 < limit)" % (r or 0))
    # non-zero base: push a frame base of 4
    mu.mem_write(vm + 0x14, struct.pack("<I", 2))
    mu.mem_write(vm + 0x18, None) if False else None
    ss = struct.unpack("<Q", mu.mem_read(vm + 0x18, 8))[0]
    mu.mem_write(ss + 4, struct.pack("<I", 4))   # savestack[1] = 4
    r = call(0x147304, [vm, 2])
    print("  base=4 off=2 -> ret=0x%x (expect 50)" % (r or 0))


@test("len")
def t_len():
    print("== 0x1472e8(vm) = cursor - savestack[ssp-1]")
    bump[0] = HEAP + 0x1000
    vm, buf = new_vm([10, 20, 30, 40], cursor=4)
    r = call(0x1472E8, [vm])
    print("  ret=0x%x (expect 4)" % (r or 0))
    mu.mem_write(vm + 0x14, struct.pack("<I", 2))
    ss = struct.unpack("<Q", mu.mem_read(vm + 0x18, 8))[0]
    mu.mem_write(ss + 4, struct.pack("<I", 1))
    r = call(0x1472E8, [vm])
    print("  base=1 -> ret=0x%x (expect 3)" % (r or 0))


@test("vmpush")
def t_vmpush():
    print("== 0x147120(engine, vm) pushes cursor; then 0x147220 pops/restores")
    bump[0] = HEAP + 0x1000
    vm, buf = new_vm([10, 20, 30, 40], cursor=4)
    call(0x147120, [0xDEAD, vm])
    ssp = struct.unpack("<I", mu.mem_read(vm + 0x14, 4))[0]
    print("  after push: ssp=%d" % ssp)
    # change cursor
    mu.mem_write(vm + 0x10, struct.pack("<I", 99))
    call(0x147220, [0xDEAD, vm])
    cur = struct.unpack("<I", mu.mem_read(vm + 0x10, 4))[0]
    ssp = struct.unpack("<I", mu.mem_read(vm + 0x14, 4))[0]
    print("  after pop: cursor=%d (expect 4) ssp=%d" % (cur, ssp))


@test("d3c")
def t_d3c():
    print("== 0x147d3c(x0=&desc, x1=0x90, x2=sinkptr)")
    bump[0] = HEAP + 0x1000
    desc = calloc("desc", 0x100)
    sink = calloc("sink", 0x200)
    r = call(0x147D3C, [desc, 0x90, sink])
    nbytes, ptr = struct.unpack("<IIQ".replace("I", ""), mu.mem_read(desc, 0x10)) if False else (None, None)
    raw = mu.mem_read(desc, 0x10)
    print("  desc bytes:", raw.hex())
    print("  ret=0x%x" % (r or 0))


if __name__ == "__main__":
    names = sys.argv[1:] or list(TESTS)
    for n in names:
        TESTS[n]()
