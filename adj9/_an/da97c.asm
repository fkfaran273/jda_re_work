000da97c  str        d8, [sp, #-0x70]!
000da980  stp        x29, x30, [sp, #0x10]
000da984  stp        x28, x27, [sp, #0x20]
000da988  stp        x26, x25, [sp, #0x30]
000da98c  stp        x24, x23, [sp, #0x40]
000da990  stp        x22, x21, [sp, #0x50]
000da994  stp        x20, x19, [sp, #0x60]
000da998  add        x29, sp, #0x10
000da99c  sub        sp, sp, #0x210
000da9a0  mrs        x8, tpidr_el0
000da9a4  add        x11, sp, #0xb0
000da9a8  str        x8, [sp, #8]
000da9ac  mov        x13, #0x507b
000da9b0  ldr        x8, [x8, #0x28]
000da9b4  mov        x19, #0x8a0
000da9b8  movk       x13, #0x2c50, lsl #16
000da9bc  movk       x19, #0xbd15, lsl #16
000da9c0  movk       x13, #0x48ac, lsl #32
000da9c4  movk       x19, #0xb02c, lsl #32
000da9c8  stur       x8, [x29, #-0x20]
000da9cc  movk       x13, #0xc90b, lsl #48
000da9d0  ldp        x10, x8, [x0, #0x18]
000da9d4  movk       x19, #0x93e7, lsl #48
000da9d8  mov        x27, #0x692
000da9dc  ldr        x14, [x0]
000da9e0  mov        x28, #0x1471
000da9e4  mov        x20, #0x1859
000da9e8  mov        x26, #0xd282
000da9ec  ldr        x10, [x10]
000da9f0  mov        x21, #0xe386
000da9f4  ldr        w12, [x8]
000da9f8  mov        x24, #0xd05b
000da9fc  ldp        x8, x9, [x0, #8]
000daa00  mov        x23, #0xc2a2
000daa04  mov        x25, #0x8d87
000daa08  cmp        w12, #1
000daa0c  mov        x22, #0x865
000daa10  ccmp       x10, #0, #4, ge
000daa14  movk       x27, #0x8807, lsl #16
000daa18  ldr        x8, [x8]
000daa1c  movk       x28, #0x4a0, lsl #16
000daa20  ldr        x9, [x9]
000daa24  movk       x20, #0x2b53, lsl #16
000daa28  movk       x26, #0x957d, lsl #16
000daa2c  movk       x21, #0xeab8, lsl #16
000daa30  stp        x8, x14, [sp, #0x70]
000daa34  movk       x24, #0xef20, lsl #16
000daa38  ccmp       x9, #0, #4, ne
000daa3c  stp        x9, x10, [sp, #0x20]
000daa40  add        x9, x11, #8
000daa44  movk       x23, #0x1048, lsl #16
000daa48  movk       x25, #0xa2f3, lsl #16
000daa4c  movk       x22, #0x5362, lsl #16
000daa50  ccmp       x8, #0, #4, ne
000daa54  add        x8, x11, #0x20
000daa58  movk       x27, #0xfbe3, lsl #32
000daa5c  movk       x28, #0x5fd, lsl #32
000daa60  movk       x20, #0x6ffc, lsl #32
000daa64  movk       x26, #0xadd, lsl #32
000daa68  ccmp       x14, #0, #4, ne
000daa6c  stp        x8, x9, [sp, #0x10]
000daa70  add        x8, x11, #0x100
000daa74  mov        x9, #0xd282
000daa78  movk       x9, #0x957d, lsl #16
000daa7c  movk       x21, #0xc1ec, lsl #32
000daa80  movk       x24, #0x96cc, lsl #32
000daa84  movk       x23, #0x7104, lsl #32
000daa88  str        x8, [sp, #0x68]
000daa8c  csel       x8, x19, x13, eq
000daa90  movk       x25, #0x8648, lsl #32
000daa94  movk       x22, #0x98ea, lsl #32
000daa98  movk       x9, #0xadd, lsl #32
000daa9c  movk       x27, #0xa1b3, lsl #48
000daaa0  str        x8, [sp, #0xa0]
000daaa4  movk       x28, #0xa11a, lsl #48
000daaa8  movk       x20, #0x930b, lsl #48
000daaac  movk       x26, #0x549f, lsl #48
000daab0  movk       x21, #0x808f, lsl #48
000daab4  movk       x24, #0x8753, lsl #48
000daab8  movk       x23, #0x9ffe, lsl #48
000daabc  movk       x25, #0xa5e3, lsl #48
000daac0  movk       x22, #0xabfd, lsl #48
000daac4  movk       x9, #0x549f, lsl #48
000daac8  str        w12, [sp, #0x84]
000daacc  str        wzr, [sp, #0xac]
  ------
000daad0  mov        x8, x9
000daad4  mov        x9, #0xcdf8
000daad8  movk       x9, #0xd72b, lsl #16
000daadc  cmp        x8, x21
000daae0  movk       x9, #0x55aa, lsl #32
000daae4  movk       x9, #0xfe6b, lsl #48
000daae8  b.eq       #0xdaad0
000daaec  cmp        x8, x24
000daaf0  b.eq       #0xdb138
000daaf4  cmp        x8, x20
000daaf8  b.eq       #0xdaf0c
000daafc  cmp        x8, x19
000dab00  b.eq       #0xdad80
000dab04  cmp        x8, x23
000dab08  b.eq       #0xdb014
000dab0c  cmp        x8, x28
000dab10  b.eq       #0xdae10
000dab14  cmp        x8, x27
000dab18  b.eq       #0xdaee4
000dab1c  cmp        x8, x25
000dab20  b.eq       #0xdad98
000dab24  mov        x9, #0xea12
000dab28  cmp        x8, x22
000dab2c  movk       x9, #0x2ac8, lsl #16
000dab30  movk       x9, #0x1d60, lsl #32
000dab34  movk       x9, #0x1023, lsl #48
000dab38  b.eq       #0xdaad0
000dab3c  mov        x9, #0x1381
000dab40  movk       x9, #0xa58a, lsl #16
000dab44  movk       x9, #0xb763, lsl #32
000dab48  movk       x9, #0xbbcd, lsl #48
000dab4c  cmp        x8, x9
000dab50  b.eq       #0xdae48
000dab54  mov        x9, #0xfe0a
000dab58  movk       x9, #0x69fd, lsl #16
000dab5c  movk       x9, #0x5f3a, lsl #32
000dab60  movk       x9, #0xbdc7, lsl #48
000dab64  cmp        x8, x9
000dab68  b.eq       #0xdb074
000dab6c  mov        x9, #0x507b
000dab70  movk       x9, #0x2c50, lsl #16
000dab74  movk       x9, #0x48ac, lsl #32
000dab78  movk       x9, #0xc90b, lsl #48
000dab7c  cmp        x8, x9
000dab80  b.eq       #0xdadbc
000dab84  mov        x9, #0x4c0d
000dab88  mov        x10, #0x25ce
000dab8c  movk       x9, #0x52dd, lsl #16
000dab90  movk       x10, #0x8c3e, lsl #16
000dab94  movk       x9, #0x7dcf, lsl #32
000dab98  movk       x10, #0xdec2, lsl #32
000dab9c  movk       x9, #0x48fe, lsl #48
000daba0  movk       x10, #0xf201, lsl #48
000daba4  cmp        x8, x10
000daba8  b.eq       #0xdaad0
000dabac  mov        x9, #0xcdf8
000dabb0  movk       x9, #0xd72b, lsl #16
000dabb4  movk       x9, #0x55aa, lsl #32
000dabb8  movk       x9, #0xfe6b, lsl #48
000dabbc  cmp        x8, x9
000dabc0  b.eq       #0xdb120
000dabc4  mov        x9, #0x1968
000dabc8  movk       x9, #0x5932, lsl #16
000dabcc  movk       x9, #0x8339, lsl #32
000dabd0  movk       x9, #0xb13, lsl #48
000dabd4  cmp        x8, x9
000dabd8  b.eq       #0xdb0b0
000dabdc  mov        x9, #0xea12
000dabe0  movk       x9, #0x2ac8, lsl #16
000dabe4  movk       x9, #0x1d60, lsl #32
000dabe8  movk       x9, #0x1023, lsl #48
000dabec  cmp        x8, x9
000dabf0  b.eq       #0xdb0e8
000dabf4  mov        x9, #0x1471
000dabf8  mov        x10, #0xcd53
000dabfc  movk       x9, #0x4a0, lsl #16
000dac00  movk       x10, #0xade6, lsl #16
000dac04  movk       x9, #0x5fd, lsl #32
000dac08  movk       x10, #0xefff, lsl #32
000dac0c  movk       x9, #0xa11a, lsl #48
000dac10  movk       x10, #0x13d4, lsl #48
000dac14  cmp        x8, x10
000dac18  b.eq       #0xdaad0
000dac1c  mov        x9, #0xb3d0
000dac20  movk       x9, #0x566, lsl #16
000dac24  movk       x9, #0xa50d, lsl #32
000dac28  movk       x9, #0x204a, lsl #48
000dac2c  cmp        x8, x9
000dac30  b.eq       #0xdb05c
000dac34  mov        x9, #0x692
000dac38  mov        x10, #0x7801
000dac3c  movk       x9, #0x8807, lsl #16
000dac40  movk       x10, #0xa06d, lsl #16
000dac44  movk       x9, #0xfbe3, lsl #32
000dac48  movk       x10, #0xab5f, lsl #32
000dac4c  movk       x9, #0xa1b3, lsl #48
000dac50  movk       x10, #0x22db, lsl #48
000dac54  cmp        x8, x10
000dac58  b.eq       #0xdaad0
000dac5c  mov        x9, #0x1381
000dac60  mov        x10, #0xb031
000dac64  movk       x9, #0xa58a, lsl #16
000dac68  movk       x10, #0x9cc1, lsl #16
000dac6c  movk       x9, #0xb763, lsl #32
000dac70  movk       x10, #0xffeb, lsl #32
000dac74  movk       x9, #0xbbcd, lsl #48
000dac78  movk       x10, #0x2516, lsl #48
000dac7c  cmp        x8, x10
000dac80  b.eq       #0xdaad0
000dac84  mov        x9, #0x92
000dac88  movk       x9, #0x16d6, lsl #16
000dac8c  movk       x9, #0x9d06, lsl #32
000dac90  movk       x9, #0x2680, lsl #48
000dac94  cmp        x8, x9
000dac98  b.eq       #0xdadec
000dac9c  mov        x9, #0x1968
000daca0  mov        x10, #0x754
000daca4  movk       x9, #0x5932, lsl #16
000daca8  movk       x10, #0xa078, lsl #16
000dacac  movk       x9, #0x8339, lsl #32
000dacb0  movk       x10, #0x1f94, lsl #32
000dacb4  movk       x9, #0xb13, lsl #48
000dacb8  movk       x10, #0x3282, lsl #48
000dacbc  cmp        x8, x10
000dacc0  b.eq       #0xdaad0
000dacc4  mov        x9, #0x1dac
000dacc8  movk       x9, #0x9f5e, lsl #16
000daccc  movk       x9, #0xb762, lsl #32
000dacd0  movk       x9, #0x3b4a, lsl #48
000dacd4  cmp        x8, x9
000dacd8  b.eq       #0xdaf44
000dacdc  mov        x9, #0x4c0d
000dace0  movk       x9, #0x52dd, lsl #16
000dace4  movk       x9, #0x7dcf, lsl #32
000dace8  movk       x9, #0x48fe, lsl #48
000dacec  cmp        x8, x9
000dacf0  b.eq       #0xdaf68
000dacf4  ldr        x9, [sp, #0xa0]
000dacf8  cmp        x8, x26
000dacfc  b.eq       #0xdaad0
000dad00  mov        x9, #0x6436
000dad04  movk       x9, #0x2869, lsl #16
000dad08  movk       x9, #0xc5df, lsl #32
000dad0c  movk       x9, #0x56de, lsl #48
000dad10  cmp        x8, x9
000dad14  b.eq       #0xdb098
000dad18  mov        x9, #0x5cb8
000dad1c  movk       x9, #0x2795, lsl #16
000dad20  movk       x9, #0x15f4, lsl #32
000dad24  movk       x9, #0x77a4, lsl #48
000dad28  cmp        x8, x9
000dad2c  b.eq       #0xdae60
000dad30  mov        x9, #0x6dbb
000dad34  movk       x9, #0xc058, lsl #16
000dad38  movk       x9, #0xf56d, lsl #32
000dad3c  movk       x9, #0x7e88, lsl #48
000dad40  cmp        x8, x9
000dad44  b.eq       #0xdb038
000dad48  mov        x9, #0x7408
000dad4c  movk       x9, #0x4e14, lsl #16
000dad50  movk       x9, #0x43cd, lsl #32
000dad54  movk       x9, #0x7f74, lsl #48
000dad58  cmp        x8, x9
000dad5c  b.eq       #0xdad80
000dad60  mov        x10, #0xe11a
000dad64  mov        x9, x8
000dad68  movk       x10, #0xe707, lsl #16
000dad6c  movk       x10, #0x5296, lsl #32
000dad70  movk       x10, #0x1df3, lsl #48
000dad74  cmp        x8, x10
000dad78  b.ne       #0xdaad0
000dad7c  b          #0xdb18c
  ------
000dad80  mov        x9, #0xe11a
000dad84  str        xzr, [sp, #0x98]
000dad88  movk       x9, #0xe707, lsl #16
000dad8c  movk       x9, #0x5296, lsl #32
000dad90  movk       x9, #0x1df3, lsl #48
000dad94  b          #0xdaad0
  ------
000dad98  ldr        x0, [sp, #0x58]
000dad9c  bl         #0x148a00   ; free@plt
000dada0  mov        x9, #0xea12
000dada4  add        x8, sp, #0xb0
000dada8  movk       x9, #0x2ac8, lsl #16
000dadac  movk       x9, #0x1d60, lsl #32
000dadb0  movk       x9, #0x1023, lsl #48
000dadb4  str        xzr, [x8, #0x120]
000dadb8  b          #0xdaad0
  ------
000dadbc  movi       d0, #0000000000000000
000dadc0  add        x0, sp, #0xac
000dadc4  bl         #0x13de90
000dadc8  ldr        w8, [sp, #0xac]
000dadcc  fmov       d8, d0
000dadd0  cmp        w8, #0
000dadd4  mov        x8, #0x7408
000dadd8  movk       x8, #0x4e14, lsl #16
000daddc  movk       x8, #0x43cd, lsl #32
000dade0  movk       x8, #0x7f74, lsl #48
000dade4  csel       x9, x24, x8, eq
000dade8  b          #0xdaad0
  ------
000dadec  ldr        x0, [sp, #0x50]
000dadf0  bl         #0x148a00   ; free@plt
000dadf4  mov        x9, #0x1471
000dadf8  add        x8, sp, #0xb0
000dadfc  movk       x9, #0x4a0, lsl #16
000dae00  movk       x9, #0x5fd, lsl #32
000dae04  movk       x9, #0xa11a, lsl #48
000dae08  str        xzr, [x8, #0x130]
000dae0c  b          #0xdaad0
  ------
000dae10  add        x8, sp, #0xb0
000dae14  mov        x9, #0x754
000dae18  movk       x9, #0xa078, lsl #16
000dae1c  movk       x9, #0x1f94, lsl #32
000dae20  ldr        x8, [x8, #0x138]
000dae24  movk       x9, #0x3282, lsl #48
000dae28  str        x8, [sp, #0x48]
000dae2c  cmp        x8, #0
000dae30  mov        x8, #0x6dbb
000dae34  movk       x8, #0xc058, lsl #16
000dae38  movk       x8, #0xf56d, lsl #32
000dae3c  movk       x8, #0x7e88, lsl #48
000dae40  csel       x9, x9, x8, eq
000dae44  b          #0xdaad0
  ------
000dae48  add        x8, sp, #0xb0
000dae4c  ldr        x8, [x8, #0x118]
000dae50  cmp        x8, #0
000dae54  str        x8, [sp, #0x60]
000dae58  csel       x9, x21, x23, eq
000dae5c  b          #0xdaad0
  ------
000dae60  ldr        w0, [sp, #0x84]
000dae64  bl         #0xe293c
000dae68  ldp        x27, x26, [sp, #0x70]
000dae6c  add        x2, sp, #0xb0
000dae70  mov        x1, x27
000dae74  mov        x0, x26
000dae78  bl         #0x1bb5c
000dae7c  ldr        w3, [sp, #0xbc]
000dae80  add        x0, sp, #0xac
000dae84  mov        x1, x26
000dae88  mov        x26, #0xd282
000dae8c  mov        x2, x27
000dae90  mov        x27, #0x692
000dae94  ldr        x4, [sp, #0x68]
000dae98  movk       x26, #0x957d, lsl #16
000dae9c  movk       x27, #0x8807, lsl #16
000daea0  movk       x26, #0xadd, lsl #32
000daea4  movk       x27, #0xfbe3, lsl #32
000daea8  movk       x26, #0x549f, lsl #48
000daeac  movk       x27, #0xa1b3, lsl #48
000daeb0  bl         #0x232ec
000daeb4  ldr        w8, [sp, #0xac]
000daeb8  mov        x9, #0x6436
000daebc  movk       x9, #0x2869, lsl #16
000daec0  movk       x9, #0xc5df, lsl #32
000daec4  cmp        w8, #0
000daec8  mov        x8, #0x25ce
000daecc  movk       x8, #0x8c3e, lsl #16
000daed0  movk       x9, #0x56de, lsl #48
000daed4  movk       x8, #0xdec2, lsl #32
000daed8  movk       x8, #0xf201, lsl #48
000daedc  csel       x9, x8, x9, eq
000daee0  b          #0xdaad0
  ------
000daee4  add        x8, sp, #0xb0
000daee8  ldr        x0, [x8, #0x148]
000daeec  bl         #0x148a00   ; free@plt
000daef0  ldr        x8, [sp, #0xc8]
000daef4  mov        x9, #0xe11a
000daef8  movk       x9, #0xe707, lsl #16
000daefc  movk       x9, #0x5296, lsl #32
000daf00  str        x8, [sp, #0x98]
000daf04  movk       x9, #0x1df3, lsl #48
000daf08  b          #0xdaad0
  ------
000daf0c  ldr        x10, [sp, #0x88]
000daf10  mov        x8, #0x1dac
000daf14  mov        x9, #0x5cb8
000daf18  movk       x8, #0x9f5e, lsl #16
000daf1c  movk       x9, #0x2795, lsl #16
000daf20  movk       x8, #0xb762, lsl #32
000daf24  movk       x9, #0x15f4, lsl #32
000daf28  cmp        x10, #0
000daf2c  movk       x8, #0x3b4a, lsl #48
000daf30  movk       x9, #0x77a4, lsl #48
000daf34  csel       x9, x9, x8, eq
000daf38  ldr        x8, [sp, #0x90]
000daf3c  stp        x8, x10, [sp, #0x38]
000daf40  b          #0xdaad0
  ------
000daf44  ldp        x10, x8, [sp, #0x38]
000daf48  mov        x9, #0x1859
000daf4c  movk       x9, #0x2b53, lsl #16
000daf50  movk       x9, #0x6ffc, lsl #32
000daf54  movk       x9, #0x930b, lsl #48
000daf58  sub        x8, x8, #1
000daf5c  strb       wzr, [x10], #1
000daf60  stp        x8, x10, [sp, #0x88]
000daf64  b          #0xdaad0
  ------
000daf68  ldp        x27, x26, [sp, #0x70]
000daf6c  add        x2, sp, #0xb0
000daf70  mov        x1, x27
000daf74  mov        x0, x26
000daf78  bl         #0xda4b4
000daf7c  add        x3, sp, #0xb0
000daf80  mov        x0, x26
000daf84  mov        x1, x27
000daf88  ldr        x2, [sp, #0x28]
000daf8c  bl         #0xda6b8
000daf90  add        x0, sp, #0xb0
000daf94  bl         #0x14868
000daf98  add        x2, sp, #0xb0
000daf9c  mov        x0, x26
000dafa0  mov        x1, x27
000dafa4  mov        x27, #0x692
000dafa8  movk       x27, #0x8807, lsl #16
000dafac  movk       x27, #0xfbe3, lsl #32
000dafb0  movk       x27, #0xa1b3, lsl #48
000dafb4  bl         #0x1bbb4
000dafb8  add        x0, sp, #0xb0
000dafbc  bl         #0xe4a7c
000dafc0  add        x0, sp, #0xb0
000dafc4  bl         #0xf9dc
000dafc8  add        x1, sp, #0xac
000dafcc  add        x2, sp, #0xb0
000dafd0  mov        x0, x26
000dafd4  mov        x26, #0xd282
000dafd8  movk       x26, #0x957d, lsl #16
000dafdc  movk       x26, #0xadd, lsl #32
000dafe0  movk       x26, #0x549f, lsl #48
000dafe4  bl         #0x12cb74
000dafe8  mov        x8, #0xb3d0
000dafec  mov        x9, #0xb031
000daff0  movk       x8, #0x566, lsl #16
000daff4  movk       x9, #0x9cc1, lsl #16
000daff8  movk       x8, #0xa50d, lsl #32
000daffc  movk       x9, #0xffeb, lsl #32
000db000  tst        w0, #1
000db004  movk       x8, #0x204a, lsl #48
000db008  movk       x9, #0x2516, lsl #48
000db00c  csel       x9, x9, x8, ne
000db010  b          #0xdaad0
  ------
000db014  ldr        x0, [sp, #0x60]
000db018  bl         #0x148a00   ; free@plt
000db01c  mov        x9, #0xcdf8
000db020  add        x8, sp, #0xb0
000db024  movk       x9, #0xd72b, lsl #16
000db028  movk       x9, #0x55aa, lsl #32
000db02c  movk       x9, #0xfe6b, lsl #48
000db030  str        xzr, [x8, #0x118]
000db034  b          #0xdaad0
  ------
000db038  ldr        x0, [sp, #0x48]
000db03c  bl         #0x148a00   ; free@plt
000db040  mov        x9, #0x1968
000db044  add        x8, sp, #0xb0
000db048  movk       x9, #0x5932, lsl #16
000db04c  movk       x9, #0x8339, lsl #32
000db050  movk       x9, #0xb13, lsl #48
000db054  str        xzr, [x8, #0x138]
000db058  b          #0xdaad0
  ------
000db05c  mov        x9, #0x1381
000db060  str        wzr, [sp, #0xac]
000db064  movk       x9, #0xa58a, lsl #16
000db068  movk       x9, #0xb763, lsl #32
000db06c  movk       x9, #0xbbcd, lsl #48
000db070  b          #0xdaad0
  ------
000db074  ldr        x0, [sp, #0x30]
000db078  bl         #0x148a00   ; free@plt
000db07c  mov        x9, #0x692
000db080  add        x8, sp, #0xb0
000db084  movk       x9, #0x8807, lsl #16
000db088  movk       x9, #0xfbe3, lsl #32
000db08c  movk       x9, #0xa1b3, lsl #48
000db090  str        xzr, [x8, #0x140]
000db094  b          #0xdaad0
  ------
000db098  mov        x9, #0x4c0d
000db09c  str        wzr, [sp, #0xac]
000db0a0  movk       x9, #0x52dd, lsl #16
000db0a4  movk       x9, #0x7dcf, lsl #32
000db0a8  movk       x9, #0x48fe, lsl #48
000db0ac  b          #0xdaad0
  ------
000db0b0  add        x8, sp, #0xb0
000db0b4  mov        x9, #0x7801
000db0b8  movk       x9, #0xa06d, lsl #16
000db0bc  movk       x9, #0xab5f, lsl #32
000db0c0  ldr        x8, [x8, #0x140]
000db0c4  movk       x9, #0x22db, lsl #48
000db0c8  str        x8, [sp, #0x30]
000db0cc  cmp        x8, #0
000db0d0  mov        x8, #0xfe0a
000db0d4  movk       x8, #0x69fd, lsl #16
000db0d8  movk       x8, #0x5f3a, lsl #32
000db0dc  movk       x8, #0xbdc7, lsl #48
000db0e0  csel       x9, x9, x8, eq
000db0e4  b          #0xdaad0
  ------
000db0e8  add        x8, sp, #0xb0
000db0ec  mov        x9, #0xcd53
000db0f0  movk       x9, #0xade6, lsl #16
000db0f4  movk       x9, #0xefff, lsl #32
000db0f8  ldr        x8, [x8, #0x130]
000db0fc  movk       x9, #0x13d4, lsl #48
000db100  str        x8, [sp, #0x50]
000db104  cmp        x8, #0
000db108  mov        x8, #0x92
000db10c  movk       x8, #0x16d6, lsl #16
000db110  movk       x8, #0x9d06, lsl #32
000db114  movk       x8, #0x2680, lsl #48
000db118  csel       x9, x9, x8, eq
000db11c  b          #0xdaad0
  ------
000db120  add        x8, sp, #0xb0
000db124  ldr        x8, [x8, #0x120]
000db128  cmp        x8, #0
000db12c  str        x8, [sp, #0x58]
000db130  csel       x9, x22, x25, eq
000db134  b          #0xdaad0
  ------
000db138  ldr        x0, [sp, #0x18]
000db13c  mov        w1, wzr
000db140  mov        w2, #0x148
000db144  bl         #0x148a20   ; memset@plt
000db148  ldr        w8, [sp, #0x84]
000db14c  str        d8, [sp, #0xb0]
000db150  ldr        x0, [sp, #0x10]
000db154  str        w8, [sp, #0xbc]
000db158  ldr        x8, [sp, #0x20]
000db15c  str        x8, [sp, #0xc0]
000db160  bl         #0x143794
000db164  ldr        x9, [sp, #0x68]
000db168  mov        w8, #0x14
000db16c  str        wzr, [sp, #0x1b0]
000db170  str        wzr, [sp, #0x1c0]
000db174  stp        x8, x9, [sp, #0x88]
000db178  mov        x9, #0x1859
000db17c  movk       x9, #0x2b53, lsl #16
000db180  movk       x9, #0x6ffc, lsl #32
000db184  movk       x9, #0x930b, lsl #48
000db188  b          #0xdaad0
  ------
000db18c  ldr        x8, [sp, #8]
000db190  ldr        x8, [x8, #0x28]
000db194  ldur       x9, [x29, #-0x20]
000db198  cmp        x8, x9
000db19c  b.ne       #0xdb1c8
000db1a0  ldr        x0, [sp, #0x98]
000db1a4  add        sp, sp, #0x210
000db1a8  ldp        x20, x19, [sp, #0x60]
000db1ac  ldp        x22, x21, [sp, #0x50]
000db1b0  ldp        x24, x23, [sp, #0x40]
000db1b4  ldp        x26, x25, [sp, #0x30]
000db1b8  ldp        x28, x27, [sp, #0x20]
000db1bc  ldp        x29, x30, [sp, #0x10]
000db1c0  ldr        d8, [sp], #0x70
000db1c4  ret        
  ------
000db1c8  bl         #0x148a10   ; __stack_chk_fail@plt
