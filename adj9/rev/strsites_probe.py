"""strsites_probe.py - the 4 block-write sites: what feeds each 16-byte store?

sub_9afa4 has exactly 4 `str q` sites (9be8c-region latch, 9bf08, 9cf3c,
9cfc8). For each: dump -40..+2 lines, list every source register feeding
v0 (loads, movs, eors), and check whether the 16 input bytes come from
the heap object (ldr [xObj]) or from constants. Goal: name the 4 blocks
(#0-tile? #4? #2?) by their input shape.
"""
import re
lines = open("fn_9afa4_full.log", encoding="utf-8").read().splitlines()
sites = [i for i, l in enumerate(lines) if re.search(r"str\s+q0,", l)]
print("str q0 sites:", len(sites))
for s in sites:
    print("=" * 78)
    for l in lines[max(0, s-42):s+3]:
        print("  " + l)
