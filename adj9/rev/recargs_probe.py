"""recargs_probe.py - what goes INTO the recursive builder calls?

sub_9afa4 calls itself 9x. Before each self-call the code sets up args;
the pattern `ldr x8,[x8,#off]; blr x8` (vtable call) or plain register
moves reveal whether args are pointers (heap objects) or small ints.
Dump ±12 insns around each of the 9 self-call sites + classify operands.
"""
import re
lines = open("fn_9afa4_full.log", encoding="utf-8").read().splitlines()
sites = [i for i, l in enumerate(lines) if re.search(r"bl\s+#0x9afa4\s*$", l)]
print("self-call sites:", len(sites))
for s in sites:
    print("=" * 70)
    for l in lines[max(0, s-14):s+6]:
        print("  " + l)
