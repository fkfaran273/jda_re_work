# Wall A - slice 54: time formats recovered, #10 tested flat (2026-09-11)

## Native time code (`0x13ddac-0x13de50`, straight-line)

`localtime` + `strftime` + 2x `gettimeofday` + assembler `0x13e8a4`
(null,null,0, fmt, x4, x5, w6, x7). Decoded formats (`.data`, live table):
- `0x155110`: `%Y-%m-%dT%H:%M:%S` (17 B)
- `0x155128`: `%s: %s.%03dZ%s` (full stamp with ms + TZ suffix)
- `0x155124`: 6 B (unresolved, minor)
fdiv/fcvtzs + `fmod` build ms (`w23`) + secs; stack slots feed the assembler.

## #10 resimulation (5 variants: zero/17B UTC/+0200/32B UTC/+0200)

All: dispatch 0x0, no gateway/header. Steps 1375 -> 1387 (+12 = one more
field dword emitted: lendl 5 vs 4, purely mechanical length effect).
#10 content is write-only pre-gateway (like #2/#7) - untestable until the
gateway path runs with live OUTLEN. Length question open (17B = 5dw vs
32B = 8dw changes total input 62 vs 65/66!); content question open.

## Net

Time formats banked for the day #10 goes live (construct any ts exactly).
No trajectory movement (expected class: write-only). Remaining content
unknowns unchanged (#0 true bytes, struct u32s, ns placement, #10 length).
