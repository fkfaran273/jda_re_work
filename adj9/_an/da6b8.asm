000da6b8  sub        sp, sp, #0x90
000da6bc  stp        x29, x30, [sp, #0x30]
000da6c0  stp        x28, x27, [sp, #0x40]
000da6c4  stp        x26, x25, [sp, #0x50]
000da6c8  stp        x24, x23, [sp, #0x60]
000da6cc  stp        x22, x21, [sp, #0x70]
000da6d0  stp        x20, x19, [sp, #0x80]
000da6d4  add        x29, sp, #0x30
000da6d8  str        x2, [sp, #0x18]
000da6dc  mrs        x8, tpidr_el0
000da6e0  str        x8, [sp]
000da6e4  mov        x22, x1
000da6e8  ldr        x8, [x8, #0x28]
000da6ec  mov        x26, #0x28cc
000da6f0  mov        x1, x3
000da6f4  movk       x26, #0xc3e2, lsl #16
000da6f8  movk       x26, #0x7819, lsl #32
000da6fc  mov        x19, x3
000da700  mov        x20, x0
000da704  movk       x26, #0x6b85, lsl #48
000da708  stur       x8, [x29, #-8]
000da70c  stur       wzr, [x29, #-0xc]
000da710  bl         #0x8c98
000da714  add        x9, x19, #0x120
000da718  add        x8, x19, #0x118
000da71c  mov        x25, #0xafb5
000da720  mov        x27, #0x113f
000da724  mov        x21, #0x2f9c
000da728  mov        x23, #0x7811
000da72c  stp        x8, x9, [sp, #8]
000da730  mov        x28, #0x8779
000da734  mov        x24, #0xee15
000da738  mov        x9, #0x3581
000da73c  movk       x25, #0xa12b, lsl #16
000da740  movk       x27, #0xceaf, lsl #16
000da744  movk       x21, #0xc396, lsl #16
000da748  movk       x23, #0x740, lsl #16
000da74c  movk       x28, #0xf1b8, lsl #16
000da750  movk       x24, #0x1fe1, lsl #16
000da754  movk       x9, #0xbcba, lsl #16
000da758  movk       x25, #0xce93, lsl #32
000da75c  movk       x27, #0x4fe6, lsl #32
000da760  movk       x21, #0x5e8f, lsl #32
000da764  movk       x23, #0x67ad, lsl #32
000da768  movk       x28, #0x3378, lsl #32
000da76c  movk       x24, #0x5376, lsl #32
000da770  movk       x9, #0x133, lsl #32
000da774  movk       x25, #0xb225, lsl #48
000da778  movk       x27, #0xe9ff, lsl #48
000da77c  movk       x21, #0xf2cd, lsl #48
000da780  movk       x23, #0xf79c, lsl #48
000da784  movk       x28, #0xeb0, lsl #48
000da788  movk       x24, #0x6aa9, lsl #48
000da78c  movk       x9, #0x761f, lsl #48
  ------
000da790  cmp        x9, x25
000da794  b.eq       #0xda90c
000da798  mov        x8, x9
000da79c  cmp        x9, x27
000da7a0  b.eq       #0xda87c
000da7a4  mov        x9, #0x28cc
000da7a8  cmp        x8, x21
000da7ac  movk       x9, #0xc3e2, lsl #16
000da7b0  movk       x9, #0x7819, lsl #32
000da7b4  movk       x9, #0x6b85, lsl #48
000da7b8  b.eq       #0xda790
000da7bc  cmp        x8, x23
000da7c0  b.eq       #0xda8e8
000da7c4  cmp        x8, x28
000da7c8  b.eq       #0xda814
000da7cc  cmp        x8, x24
000da7d0  b.eq       #0xda868
000da7d4  cmp        x8, x26
000da7d8  b.eq       #0xda844
000da7dc  mov        x9, #0x3581
000da7e0  movk       x9, #0xbcba, lsl #16
000da7e4  movk       x9, #0x133, lsl #32
000da7e8  movk       x9, #0x761f, lsl #48
000da7ec  cmp        x8, x9
000da7f0  b.eq       #0xda8c4
000da7f4  mov        x10, #0x9bd
000da7f8  mov        x9, x8
000da7fc  movk       x10, #0xb5f6, lsl #16
000da800  movk       x10, #0xce8f, lsl #32
000da804  movk       x10, #0x62d5, lsl #48
000da808  cmp        x8, x10
000da80c  b.ne       #0xda790
000da810  b          #0xda92c
  ------
000da814  mov        x0, x19
000da818  bl         #0xd868
000da81c  ldr        x3, [x19, #0x118]
000da820  sub        x0, x29, #0xc
000da824  mov        x1, x20
000da828  mov        x2, x22
000da82c  ldr        x4, [sp, #0x10]
000da830  bl         #0x1c920
000da834  ldur       w8, [x29, #-0xc]
000da838  cmp        w8, #0
000da83c  csel       x9, x23, x24, eq
000da840  b          #0xda790
  ------
000da844  sub        x0, x29, #0xc
000da848  mov        x1, x20
000da84c  mov        x2, x22
000da850  ldr        x3, [sp, #8]
000da854  bl         #0x1bcc4
000da858  ldur       w8, [x29, #-0xc]
000da85c  cmp        w8, #0
000da860  csel       x9, x28, x27, eq
000da864  b          #0xda790
  ------
000da868  mov        x0, x19
000da86c  bl         #0xe374
000da870  mov        x0, x19
000da874  bl         #0xee40
000da878  b          #0xda89c
  ------
000da87c  mov        x0, x19
000da880  bl         #0xddf0
000da884  mov        x0, x19
000da888  bl         #0xe374
000da88c  mov        x0, x19
000da890  bl         #0xee40
000da894  mov        x0, x19
000da898  bl         #0xde24
  ------
000da89c  mov        x0, x19
000da8a0  bl         #0xe3a8
000da8a4  mov        x0, x19
000da8a8  bl         #0xee74
000da8ac  mov        x9, #0x9bd
000da8b0  stur       wzr, [x29, #-0xc]
000da8b4  movk       x9, #0xb5f6, lsl #16
000da8b8  movk       x9, #0xce8f, lsl #32
000da8bc  movk       x9, #0x62d5, lsl #48
000da8c0  b          #0xda790
  ------
000da8c4  sub        x1, x29, #0xc
000da8c8  mov        x0, x20
000da8cc  mov        x2, x19
000da8d0  mov        x3, x22
000da8d4  ldr        x4, [sp, #0x18]
000da8d8  bl         #0xee8c
000da8dc  tst        w0, #1
000da8e0  csel       x9, x21, x25, ne
000da8e4  b          #0xda790
  ------
000da8e8  mov        x0, x19
000da8ec  bl         #0xde3c
000da8f0  mov        x0, x19
000da8f4  bl         #0xe740
000da8f8  mov        x9, #0x9bd
000da8fc  movk       x9, #0xb5f6, lsl #16
000da900  movk       x9, #0xce8f, lsl #32
000da904  movk       x9, #0x62d5, lsl #48
000da908  b          #0xda790
  ------
000da90c  mov        x0, x19
000da910  bl         #0xf9b4
000da914  mov        x9, #0x28cc
000da918  stur       wzr, [x29, #-0xc]
000da91c  movk       x9, #0xc3e2, lsl #16
000da920  movk       x9, #0x7819, lsl #32
000da924  movk       x9, #0x6b85, lsl #48
000da928  b          #0xda790
  ------
000da92c  mov        x0, x19
000da930  bl         #0x15384
000da934  mov        x0, x20
000da938  mov        x1, x19
000da93c  bl         #0x15590
000da940  ldr        x8, [sp]
000da944  ldr        x8, [x8, #0x28]
000da948  ldur       x9, [x29, #-8]
000da94c  cmp        x8, x9
000da950  b.ne       #0xda974
000da954  ldp        x20, x19, [sp, #0x80]
000da958  ldp        x22, x21, [sp, #0x70]
000da95c  ldp        x24, x23, [sp, #0x60]
000da960  ldp        x26, x25, [sp, #0x50]
000da964  ldp        x28, x27, [sp, #0x40]
000da968  ldp        x29, x30, [sp, #0x30]
000da96c  add        sp, sp, #0x90
000da970  ret        
  ------
000da974  bl         #0x148a10   ; __stack_chk_fail@plt
000da978  b          #0x14868
