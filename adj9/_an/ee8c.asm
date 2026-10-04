0000ec8c  csel       x10, x8, x26, eq
0000ec90  mov        x8, x19
0000ec94  mov        x12, #0x6555
0000ec98  mov        x13, #0x6276
0000ec9c  movk       x12, #0xe191, lsl #16
0000eca0  movk       x13, #0xd7a8, lsl #16
0000eca4  movk       x12, #0xcafc, lsl #32
0000eca8  movk       x13, #0x9f8e, lsl #32
0000ecac  movk       x12, #0x97eb, lsl #48
0000ecb0  movk       x13, #0x93a4, lsl #48
0000ecb4  b          #0xe86c
0000ecb8  ldur       x8, [x29, #-0x20]
0000ecbc  ldr        x20, [x8, #0x18]
0000ecc0  mov        x8, x19
0000ecc4  cmp        x20, #0
0000ecc8  csel       x10, x13, x25, eq
0000eccc  b          #0xe86c
0000ecd0  ldur       x8, [x29, #-0x20]
0000ecd4  ldr        x8, [x8, #0x38]
0000ecd8  cmp        x8, #0
0000ecdc  str        x8, [sp, #0x28]
0000ece0  cset       w8, eq
0000ece4  str        w8, [sp, #0x1c]
0000ece8  mov        x8, #0x5715
0000ecec  movk       x8, #0x914d, lsl #16
0000ecf0  movk       x8, #0x6d98, lsl #32
0000ecf4  movk       x8, #0x4ce5, lsl #48
0000ecf8  csel       x10, x27, x8, eq
0000ecfc  mov        x8, x19
0000ed00  b          #0xe86c
0000ed04  ldur       x8, [x29, #-0x20]
0000ed08  ldr        x23, [x8, #0x18]
0000ed0c  mov        x8, #0x245a
0000ed10  movk       x8, #0xf6a5, lsl #16
0000ed14  movk       x8, #0x3066, lsl #32
0000ed18  cmp        x23, #0
0000ed1c  movk       x8, #0x7c2, lsl #48
0000ed20  csel       x10, x28, x8, eq
0000ed24  mov        x8, x19
0000ed28  b          #0xe86c
0000ed2c  ldur       x8, [x29, #-0x20]
0000ed30  ldr        x8, [x8, #0x28]
0000ed34  str        x8, [sp, #0x20]
0000ed38  cmp        x8, #0
0000ed3c  mov        x8, #0xb000
0000ed40  movk       x8, #0x2468, lsl #16
0000ed44  movk       x8, #0x9119, lsl #32
0000ed48  movk       x8, #0xe77, lsl #48
0000ed4c  csel       x10, x8, x24, eq
0000ed50  mov        x8, x19
0000ed54  b          #0xe86c
0000ed58  ldr        x0, [sp, #0x30]
0000ed5c  bl         #0xee40
0000ed60  mov        x13, #0x6276
0000ed64  mov        x12, #0x6555
0000ed68  mov        x10, #0x5998
0000ed6c  movk       x13, #0xd7a8, lsl #16
0000ed70  movk       x12, #0xe191, lsl #16
0000ed74  movk       x10, #0xd6dd, lsl #16
0000ed78  movk       x13, #0x9f8e, lsl #32
0000ed7c  movk       x12, #0xcafc, lsl #32
0000ed80  movk       x10, #0x3822, lsl #32
0000ed84  movk       x13, #0x93a4, lsl #48
0000ed88  movk       x12, #0x97eb, lsl #48
0000ed8c  mov        x8, x19
0000ed90  movk       x10, #0x527e, lsl #48
0000ed94  b          #0xe86c
0000ed98  ldr        x8, [sp, #0x20]
0000ed9c  ldur       x0, [x29, #-0x28]
0000eda0  add        x1, x8, #0x10
0000eda4  bl         #0xe3c0
0000eda8  mov        x12, #0x6555
0000edac  mov        x9, #0xc033
0000edb0  mov        x13, #0x6276
0000edb4  movk       x12, #0xe191, lsl #16
0000edb8  movk       x9, #0x9e58, lsl #16
0000edbc  movk       x13, #0xd7a8, lsl #16
0000edc0  movk       x12, #0xcafc, lsl #32
0000edc4  movk       x9, #0x1392, lsl #32
0000edc8  movk       x13, #0x9f8e, lsl #32
0000edcc  movk       x12, #0x97eb, lsl #48
0000edd0  tst        w0, #1
0000edd4  movk       x9, #0x8cd, lsl #48
0000edd8  movk       x13, #0x93a4, lsl #48
0000eddc  mov        x8, x19
0000ede0  csel       x10, x9, x12, ne
0000ede4  b          #0xe86c
0000ede8  ldr        x10, [sp, #0x30]
0000edec  mov        x9, #0x40000000000
0000edf0  movk       x9, #0x100, lsl #48
0000edf4  ldur       x0, [x29, #-0x20]
0000edf8  ldr        x8, [x10, #0xf0]
0000edfc  orr        x8, x8, x9
0000ee00  str        x8, [x10, #0xf0]
0000ee04  bl         #0x134480
0000ee08  ldr        x8, [sp, #8]
0000ee0c  ldr        x8, [x8, #0x28]
0000ee10  ldur       x9, [x29, #-8]
0000ee14  cmp        x8, x9
0000ee18  b.ne       #0xee3c
0000ee1c  ldp        x20, x19, [sp, #0xb0]
0000ee20  ldp        x22, x21, [sp, #0xa0]
0000ee24  ldp        x24, x23, [sp, #0x90]
0000ee28  ldp        x26, x25, [sp, #0x80]
0000ee2c  ldp        x28, x27, [sp, #0x70]
0000ee30  ldp        x29, x30, [sp, #0x60]
0000ee34  add        sp, sp, #0xc0
0000ee38  ret        
  ------
0000ee3c  bl         #0x148a10   ; __stack_chk_fail@plt
  ------
0000ee40  stp        x29, x30, [sp, #-0x20]!
0000ee44  str        x19, [sp, #0x10]
0000ee48  mov        x29, sp
0000ee4c  mov        x19, x0
0000ee50  add        x0, x0, #0x20
0000ee54  mov        w1, #0x38
0000ee58  bl         #0x1441e4
0000ee5c  ldr        x8, [x19, #0xf0]
0000ee60  orr        x8, x8, #1
0000ee64  str        x8, [x19, #0xf0]
0000ee68  ldr        x19, [sp, #0x10]
0000ee6c  ldp        x29, x30, [sp], #0x20
0000ee70  ret        
0000ee74  ldr        x8, [x0, #0xf0]
0000ee78  mov        x9, #0x40000000000
0000ee7c  movk       x9, #0x100, lsl #48
0000ee80  orr        x8, x8, x9
0000ee84  str        x8, [x0, #0xf0]
0000ee88  ret        
0000ee8c  sub        sp, sp, #0x160
0000ee90  str        d8, [sp, #0xf0]
0000ee94  stp        x29, x30, [sp, #0x100]
0000ee98  stp        x28, x27, [sp, #0x110]
0000ee9c  stp        x26, x25, [sp, #0x120]
0000eea0  stp        x24, x23, [sp, #0x130]
0000eea4  stp        x22, x21, [sp, #0x140]
0000eea8  stp        x20, x19, [sp, #0x150]
0000eeac  add        x29, sp, #0x100
0000eeb0  stp        x3, x4, [sp, #0x18]
0000eeb4  mov        x27, x0
0000eeb8  stur       x1, [x29, #-0x70]
0000eebc  mrs        x8, tpidr_el0
0000eec0  str        x8, [sp]
0000eec4  mov        x20, #0xe650
0000eec8  ldr        x8, [x8, #0x28]
0000eecc  mov        x0, x2
0000eed0  movk       x20, #0xf983, lsl #16
0000eed4  mov        x19, x2
0000eed8  movk       x20, #0x4d74, lsl #32
0000eedc  stur       x8, [x29, #-0x20]
0000eee0  adrp       x8, #0x3000
0000eee4  movk       x20, #0x9057, lsl #48
0000eee8  stp        xzr, xzr, [x29, #-0x30]
0000eeec  stp        xzr, xzr, [x29, #-0x40]
0000eef0  ldr        d8, [x8, #0x568]
0000eef4  stp        xzr, xzr, [x29, #-0x50]
0000eef8  stur       xzr, [x29, #-0x58]
0000eefc  fmov       d0, d8
0000ef00  bl         #0xdbb0
0000ef04  add        x8, x19, #0x20
0000ef08  stur       x19, [x29, #-0x60]
0000ef0c  mov        x26, #0x4534
0000ef10  mov        x22, #0x63ca
0000ef14  mov        x28, #0xe9bc
0000ef18  mov        x21, #0x6a77
0000ef1c  str        x8, [sp, #0x10]
0000ef20  mov        x19, #0x4a10
0000ef24  mov        x8, #0xe5d7
0000ef28  movk       x26, #0xafc6, lsl #16
0000ef2c  movk       x22, #0x507e, lsl #16
0000ef30  movk       x28, #0xf262, lsl #16
0000ef34  movk       x21, #0xff4c, lsl #16
0000ef38  movk       x19, #0x4a91, lsl #16
0000ef3c  movk       x8, #0x24ff, lsl #16
0000ef40  movk       x26, #0x9ae1, lsl #32
0000ef44  movk       x22, #0xf11d, lsl #32
0000ef48  movk       x28, #0x6463, lsl #32
0000ef4c  movk       x21, #0xf77f, lsl #32
0000ef50  movk       x19, #0xff05, lsl #32
0000ef54  movk       x8, #0x5c99, lsl #32
0000ef58  movk       x26, #0x80be, lsl #48
0000ef5c  movk       x22, #0x8da7, lsl #48
0000ef60  movk       x28, #0x8643, lsl #48
0000ef64  movk       x21, #0x8663, lsl #48
0000ef68  movk       x19, #0x8ae0, lsl #48
0000ef6c  movk       x8, #0xb54e, lsl #48
  ------
0000ef70  mov        w23, w0
0000ef74  mov        w25, w1
0000ef78  cmp        x8, x26
0000ef7c  b.eq       #0xf89c
0000ef80  mov        x9, x8
0000ef84  cmp        x8, x28
0000ef88  b.eq       #0xf47c
0000ef8c  cmp        x9, x21
0000ef90  b.eq       #0xf3ac
0000ef94  mov        x8, #0x1df8
0000ef98  mov        w1, w24
0000ef9c  movk       x8, #0x53de, lsl #16
0000efa0  mov        w0, w23
0000efa4  movk       x8, #0xeca8, lsl #32
0000efa8  cmp        x9, x19
0000efac  movk       x8, #0x7d6a, lsl #48
0000efb0  b.eq       #0xef70
0000efb4  cmp        x9, x22
0000efb8  b.eq       #0xf4ac
0000efbc  cmp        x9, x20
0000efc0  b.eq       #0xf914
0000efc4  mov        x8, #0x4338
0000efc8  mov        x10, #0x5e3a
0000efcc  movk       x8, #0x2970, lsl #16
0000efd0  movk       x10, #0xf4a0, lsl #16
0000efd4  movk       x8, #0x28c2, lsl #32
0000efd8  mov        w1, w25
0000efdc  mov        w0, w23
0000efe0  movk       x8, #0x18c, lsl #48
0000efe4  movk       x10, #0xe28, lsl #32
0000efe8  movk       x10, #0x90a0, lsl #48
0000efec  cmp        x9, x10
0000eff0  b.eq       #0xef70
0000eff4  mov        x8, #0x3a3b
0000eff8  mov        x10, #0xd62d
0000effc  movk       x8, #0xb9d6, lsl #16
0000f000  movk       x10, #0x5cb1, lsl #16
0000f004  movk       x8, #0x59ae, lsl #32
0000f008  mov        w1, w25
