"""dbg_replay.py - dynamic diagnostics for the 0x8d364 poll fault.
Wraps emu_8d6f4.Emu, adds:
  * per-execution log at PC 0x8d364 (x8, x2, x24, byte values)
  * scheduler event log (_switch/_launch/_dispatch_new/thread-done)
  * full x0-x30 dump at the fault + wait-area bytes at ctx
Usage: python dbg_replay.py [--runs N] [--vary '{...}']
"""
import os
import sys
import struct
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import emu_8d6f4 as E
from unicorn import *
from unicorn.arm64_const import *

POLL_PC = 0x8D364


class DbgEmu(E.Emu):
    def __init__(self, cfg=None, digest=False):
        super().__init__(cfg, digest)
        self.poll_exec = []      # every execution of the poll instruction
        self.sched_events = []
        self.fault_dump = None
        # extra code hook for the poll pc (in addition to hook_sched)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_poll, begin=POLL_PC, end=POLL_PC)
        # trace which block wrote the junk: watch head entries
        self.mu.hook_add(UC_HOOK_CODE, self.hook_head, begin=0x8CCA8, end=0x8CCA8)
        self.head_log = []

    def hook_poll(self, uc, address, size, ud):
        x8 = uc.reg_read(UC_ARM64_REG_X8)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x24 = uc.reg_read(UC_ARM64_REG_X24)
        x5 = uc.reg_read(UC_ARM64_REG_X5)
        x3 = uc.reg_read(UC_ARM64_REG_X3)
        try:
            b8 = uc.mem_read(x8, 1)[0]
        except UcError:
            b8 = None
        try:
            b2 = uc.mem_read(x2, 1)[0]
        except UcError:
            b2 = None
        # state-machine scratch: base=[sp+0x28], i=[sp+0x50]
        sp = uc.reg_read(UC_ARM64_REG_SP)
        try:
            base = struct.unpack("<Q", uc.mem_read(sp + 0x28, 8))[0]
            idx50 = struct.unpack("<Q", uc.mem_read(sp + 0x50, 8))[0]
            idx48 = struct.unpack("<Q", uc.mem_read(sp + 0x48, 8))[0]
            idx40 = struct.unpack("<Q", uc.mem_read(sp + 0x40, 8))[0]
        except UcError:
            base = idx50 = idx48 = idx40 = -1
        self.poll_exec.append((len(self.poll_exec), x8, b8, x2, b2, x24, x5, x3,
                               base, idx50, idx48, idx40))

    def hook_head(self, uc, address, size, ud):
        # dispatcher head: state x24 <- x17 next-tag; live x8 <- x1
        self.head_log.append((len(self.head_log),
                              uc.reg_read(UC_ARM64_REG_X17),
                              uc.reg_read(UC_ARM64_REG_X1),
                              uc.reg_read(UC_ARM64_REG_X5),
                              uc.reg_read(UC_ARM64_REG_X3)))

    def _switch(self, uc, resume_pc):
        frm = self._cur
        to = self._next_name()
        self.sched_events.append(("switch", frm, to, self._tick, hex(resume_pc)))
        super()._switch(uc, resume_pc)

    def _dispatch_new(self, uc):
        self.sched_events.append(("dispatch_new", self._pending,
                                  hex(self.cori.get(self._pending, {}).get("fresh", (0, 0, 0))[0])))
        super()._dispatch_new(uc)

    def _launch(self, uc):
        c = self.cori[self._cur]
        if "fresh" in c:
            self.sched_events.append(("launch_fresh", self._cur,
                                      hex(c["fresh"][0]), hex(c["fresh"][1]),
                                      hex(c["fresh"][2])))
        else:
            self.sched_events.append(("resume", self._cur, hex(c["ret"])))
        super()._launch(uc)


def _dump_row(row):
    idx, x8, b8, x2, b2, x24, x5, x3, base, idx50, idx48, idx40 = row
    print("  poll#%-5d x8=0x%-13x b8=%-5s x2=0x%-13x b2=%-5s x24=0x%x "
          "x5=0x%-11x x3=0x%-11x [sp+28]=0x%-13x i50=%s i48=%s i40=%s"
          % (idx, x8, ("%02x" % b8) if b8 is not None else "??",
             x2, ("%02x" % b2) if b2 is not None else "??",
             x24, x5, x3, base,
             "0x%x" % idx50 if idx50 >= 0 else "?",
             "0x%x" % idx48 if idx48 >= 0 else "?",
             "0x%x" % idx40 if idx40 >= 0 else "?"))


def dump_fault(e):
    uc = e.mu
    names = [("x%d" % i, UC_ARM64_REG_X0 + i) for i in range(29)]
    names += [("x29", UC_ARM64_REG_X29), ("x30", UC_ARM64_REG_X30), ("sp", UC_ARM64_REG_SP)]
    vals = []
    for nm, rc in names:
        vals.append("%s=0x%x" % (nm, uc.reg_read(rc)))
    print("FAULT REGS: " + " ".join(vals))
    # where does the junk live?
    junk = struct.pack("<Q", 0x0EB03378F1B88779)
    hits = e.find_pattern(junk)
    print("junk 0xeb03378f1b88779 found at:", ["0x%x" % a for a, _ in hits])
    # poll history
    print("\npoll executions at 0x8d364: %d" % len(e.poll_exec))
    for row in e.poll_exec[:6]:
        _dump_row(row)
    if len(e.poll_exec) > 6:
        # show phase transitions: rows where x8 or base changes
        prev = None
        shown = 0
        for row in e.poll_exec:
            if prev is None or (row[1], row[8], row[9]) != (prev[1], prev[8], prev[9]):
                _dump_row(row)
                shown += 1
            prev = row
        print("  (%d phase rows shown of %d polls)" % (shown, len(e.poll_exec)))
        print("  last 8 polls:")
        for row in e.poll_exec[-8:]:
            _dump_row(row)
    # head history: find the head pass right before the fault
    print("\nlast dispatcher-head entries (x17=next-tag, x1, x5, x3):")
    for row in e.head_log[-12:]:
        idx, x17, x1, x5, x3 = row
        print("  #%-4d x17=0x%-18x x1=0x%-13x x5=0x%-13x x3=0x%x" % (idx, x17, x1, x5, x3))
    # wait area of ctx
    if e.ctx_seen:
        ctx = e.ctx_seen[-1][2]
        print("\nctx=0x%x" % ctx)
        for off in (0x800, 0x810, 0x818, 0x820, 0x828, 0x830, 0x838, 0x840,
                    0x848, 0x850, 0x858, 0x860, 0x868, 0x870, 0x878):
            try:
                q = struct.unpack("<Q", uc.mem_read(ctx + off, 8))[0]
                print("  ctx+0x%03x: %016x" % (off, q))
            except UcError as err:
                print("  ctx+0x%03x: <unmapped>" % off)
    print("\nsched events: %d" % len(e.sched_events))
    for ev in e.sched_events[:60]:
        print("  ", ev)
    print("\npthread_create calls:", [c for c in e.calls if c[0] == "pthread_create"])
    print("rand calls:", e.rand_calls[:10], "count=%d" % len(e.rand_calls))
    print("srand log:", e.srand_log)
    print("stopped:", e.stopped)


def main():
    ap = E.argparse.ArgumentParser()
    ap.add_argument("--vary", type=str, default=None)
    ap.add_argument("--count", type=int, default=3_000_000_000)
    args = ap.parse_args()
    override = json.loads(args.vary) if args.vary else {}
    e = DbgEmu(cfg=override)
    st = e.run(0xDB1CC, count=args.count, argstyle="nsign")
    print("stopped=%s wall=%.1fs" % (st, getattr(e, "wall", 0)))
    dump_fault(e)


if __name__ == "__main__":
    main()
