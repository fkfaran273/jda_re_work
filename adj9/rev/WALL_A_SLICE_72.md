# Wall A - slice 72: LIVE entry capture + memdump (2026-09-11)

## How (device notes)

- Stripped frida-server 17.17.0 (`device/bin/frida-server`): NO
  Module.findBaseAddress/getBaseAddress, NO Memory reads. HAS
  Interceptor/Memory.alloc+scan/enumerateModules/backtrace.
- server spawn broken -> force-stop + `rm AdjustIo*` + `am start` +
  fast attach (1.5s) + poll enumerateModules. Offset mapping verified
  byte-exact via scanSync (prologue pattern at base+0xBB548, r-x).
- No signing without session reset (Adjust idle otherwise).

## True entry (0xbb548, two sessions, SAME token)

x0=heap-cell, x1=tagged struct, x2=map, x3=strings, x4=out-cell,
x9=0x558c387eb58adba (deterministic), x19=heap+0x10.
Hub re-entered 11x: x9 = 522b857231f0c047 -> 66856a90d4feac07
(prologue const, also in x19) -> maze consts -> 5f69f144a4a7722a
-> phase loop (x20-token f00481f4afa5ce68 alternating
41dc46b67c5bf6/525e0726f260147e) -> x21-token 967fc24c2731e221...

## memdump/ (stall 40s + /proc/PID/mem, 128KB windows)

- x0/x2/x4/x19/sp: one heap region, entry buffers = filler (chain
  populates them - replay-from-entry is faithful).
- x2 area: live pointers (self-ref, tagged MTE, 0x13157c3e2c85f819).
- x1 struct: [heapptr, tagged x3, tagged..., 0x9a, 0xfffffffc00000100,
  0, tagged x3...].
- x3: string table (269 c-strings): fetch keys os_version/app_version/
  android_id/fire_adid + VALUES inline + emulator-indicator list
  (/dev/qemu_pipe, Bluestacks, genymotion...) + /proc paths.

## Static bonus (same turn)

RELA table: slots 0x14d4f8/500/508/510 -> ba4a8/bb548/bbbf8/bca34
(4-fn chain table, read directly not via PLT). Feeder at 0x13f6e0:
table[x21] indexed load -> local-0x18 (setter!); 0x13f738 builds
&table[x26].

## Next

Parse x2 map + x3 record stride + x1 struct fully; stock emulator mem
from memdump/; replay 0xbb548 with TRUE regs -> deterministic chain ->
visit order + calls + feeds.
