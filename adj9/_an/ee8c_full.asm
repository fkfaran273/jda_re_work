0000ee8c sub    sp, sp, #0x160
0000ee90 str    d8, [sp, #0xf0]
0000ee94 stp    x29, x30, [sp, #0x100]
0000ee98 stp    x28, x27, [sp, #0x110]
0000ee9c stp    x26, x25, [sp, #0x120]
0000eea0 stp    x24, x23, [sp, #0x130]
0000eea4 stp    x22, x21, [sp, #0x140]
0000eea8 stp    x20, x19, [sp, #0x150]
0000eeac add    x29, sp, #0x100
0000eeb0 stp    x3, x4, [sp, #0x18]
0000eeb4 mov    x27, x0
0000eeb8 stur   x1, [x29, #-0x70]
0000eebc mrs    x8, tpidr_el0
0000eec0 str    x8, [sp]
0000eec4 mov    x20, #0xe650
0000eec8 ldr    x8, [x8, #0x28]
0000eecc mov    x0, x2
0000eed0 movk   x20, #0xf983, lsl #16
0000eed4 mov    x19, x2
0000eed8 movk   x20, #0x4d74, lsl #32
0000eedc stur   x8, [x29, #-0x20]
0000eee0 adrp   x8, #0x3000
0000eee4 movk   x20, #0x9057, lsl #48
0000eee8 stp    xzr, xzr, [x29, #-0x30]
0000eeec stp    xzr, xzr, [x29, #-0x40]
0000eef0 ldr    d8, [x8, #0x568]
0000eef4 stp    xzr, xzr, [x29, #-0x50]
0000eef8 stur   xzr, [x29, #-0x58]
0000eefc fmov   d0, d8
0000ef00 bl     #0xdbb0
0000ef04 add    x8, x19, #0x20
0000ef08 stur   x19, [x29, #-0x60]
0000ef0c mov    x26, #0x4534
0000ef10 mov    x22, #0x63ca
0000ef14 mov    x28, #0xe9bc
0000ef18 mov    x21, #0x6a77
0000ef1c str    x8, [sp, #0x10]
0000ef20 mov    x19, #0x4a10
0000ef24 mov    x8, #0xe5d7
0000ef28 movk   x26, #0xafc6, lsl #16
0000ef2c movk   x22, #0x507e, lsl #16
0000ef30 movk   x28, #0xf262, lsl #16
0000ef34 movk   x21, #0xff4c, lsl #16
0000ef38 movk   x19, #0x4a91, lsl #16
0000ef3c movk   x8, #0x24ff, lsl #16
0000ef40 movk   x26, #0x9ae1, lsl #32
0000ef44 movk   x22, #0xf11d, lsl #32
0000ef48 movk   x28, #0x6463, lsl #32
0000ef4c movk   x21, #0xf77f, lsl #32
0000ef50 movk   x19, #0xff05, lsl #32
0000ef54 movk   x8, #0x5c99, lsl #32
0000ef58 movk   x26, #0x80be, lsl #48
0000ef5c movk   x22, #0x8da7, lsl #48
0000ef60 movk   x28, #0x8643, lsl #48
0000ef64 movk   x21, #0x8663, lsl #48
0000ef68 movk   x19, #0x8ae0, lsl #48
0000ef6c movk   x8, #0xb54e, lsl #48
0000ef70 mov    w23, w0
0000ef74 mov    w25, w1
0000ef78 cmp    x8, x26
0000ef7c b.eq   #0xf89c
0000ef80 mov    x9, x8
0000ef84 cmp    x8, x28
0000ef88 b.eq   #0xf47c
0000ef8c cmp    x9, x21
0000ef90 b.eq   #0xf3ac
0000ef94 mov    x8, #0x1df8
0000ef98 mov    w1, w24
0000ef9c movk   x8, #0x53de, lsl #16
0000efa0 mov    w0, w23
0000efa4 movk   x8, #0xeca8, lsl #32
0000efa8 cmp    x9, x19
0000efac movk   x8, #0x7d6a, lsl #48
0000efb0 b.eq   #0xef70
0000efb4 cmp    x9, x22
0000efb8 b.eq   #0xf4ac
0000efbc cmp    x9, x20
0000efc0 b.eq   #0xf914
0000efc4 mov    x8, #0x4338
0000efc8 mov    x10, #0x5e3a
0000efcc movk   x8, #0x2970, lsl #16
0000efd0 movk   x10, #0xf4a0, lsl #16
0000efd4 movk   x8, #0x28c2, lsl #32
0000efd8 mov    w1, w25
0000efdc mov    w0, w23
0000efe0 movk   x8, #0x18c, lsl #48
0000efe4 movk   x10, #0xe28, lsl #32
0000efe8 movk   x10, #0x90a0, lsl #48
0000efec cmp    x9, x10
0000eff0 b.eq   #0xef70
0000eff4 mov    x8, #0x3a3b
0000eff8 mov    x10, #0xd62d
0000effc movk   x8, #0xb9d6, lsl #16
0000f000 movk   x10, #0x5cb1, lsl #16
0000f004 movk   x8, #0x59ae, lsl #32
0000f008 mov    w1, w25
0000f00c mov    w0, w23
0000f010 movk   x8, #0x510e, lsl #48
0000f014 movk   x10, #0xcda9, lsl #32
0000f018 movk   x10, #0x9fb5, lsl #48
0000f01c cmp    x9, x10
0000f020 b.eq   #0xef70
0000f024 mov    x8, #0xb8e4
0000f028 movk   x8, #0xf6f4, lsl #16
0000f02c movk   x8, #0x1f89, lsl #32
0000f030 movk   x8, #0xa52c, lsl #48
0000f034 cmp    x9, x8
0000f038 b.eq   #0xf6bc
0000f03c mov    x8, #0x2488
0000f040 movk   x8, #0xe03e, lsl #16
0000f044 movk   x8, #0x6c0e, lsl #32
0000f048 movk   x8, #0xacc4, lsl #48
0000f04c cmp    x9, x8
0000f050 b.eq   #0xf3ac
0000f054 mov    x8, #0xe5d7
0000f058 movk   x8, #0x24ff, lsl #16
0000f05c movk   x8, #0x5c99, lsl #32
0000f060 movk   x8, #0xb54e, lsl #48
0000f064 cmp    x9, x8
0000f068 b.eq   #0xf8c8
0000f06c mov    x8, #0x9a89
0000f070 mov    x10, #0xdaf5
0000f074 movk   x8, #0x559b, lsl #16
0000f078 movk   x10, #0x621, lsl #16
0000f07c movk   x8, #0x3537, lsl #32
0000f080 mov    w1, w25
0000f084 mov    w0, w23
0000f088 movk   x8, #0x6566, lsl #48
0000f08c movk   x10, #0xc035, lsl #32
0000f090 movk   x10, #0xc90d, lsl #48
0000f094 cmp    x9, x10
0000f098 b.eq   #0xef70
0000f09c mov    x8, #0xb101
0000f0a0 mov    x10, #0x88a8
0000f0a4 movk   x8, #0x7502, lsl #16
0000f0a8 movk   x10, #0x7ae6, lsl #16
0000f0ac movk   x8, #0xcf0b, lsl #32
0000f0b0 mov    w1, w25
0000f0b4 mov    w0, w23
0000f0b8 movk   x8, #0x312a, lsl #48
0000f0bc movk   x10, #0xea5, lsl #32
0000f0c0 movk   x10, #0xcda6, lsl #48
0000f0c4 cmp    x9, x10
0000f0c8 b.eq   #0xef70
0000f0cc mov    x8, #0x93f
0000f0d0 movk   x8, #0x235, lsl #16
0000f0d4 movk   x8, #0x9fda, lsl #32
0000f0d8 movk   x8, #0xd6ac, lsl #48
0000f0dc cmp    x9, x8
0000f0e0 b.eq   #0xf6e4
0000f0e4 mov    x8, #0xf2b4
0000f0e8 mov    x10, #0xca7
0000f0ec movk   x8, #0xcb03, lsl #16
0000f0f0 movk   x10, #0x9688, lsl #16
0000f0f4 movk   x8, #0x560, lsl #32
0000f0f8 mov    w1, w25
0000f0fc mov    w0, w23
0000f100 movk   x8, #0x6e9c, lsl #48
0000f104 movk   x10, #0x5d71, lsl #32
0000f108 movk   x10, #0xe653, lsl #48
0000f10c cmp    x9, x10
0000f110 b.eq   #0xef70
0000f114 mov    x8, #0xeea7
0000f118 movk   x8, #0xcfb3, lsl #16
0000f11c movk   x8, #0x23aa, lsl #32
0000f120 movk   x8, #0xf35c, lsl #48
0000f124 cmp    x9, x8
0000f128 b.eq   #0xf5ac
0000f12c mov    x8, #0x4338
0000f130 movk   x8, #0x2970, lsl #16
0000f134 movk   x8, #0x28c2, lsl #32
0000f138 movk   x8, #0x18c, lsl #48
0000f13c cmp    x9, x8
0000f140 b.eq   #0xf3cc
0000f144 mov    x8, #0xe650
0000f148 mov    x10, #0x45f3
0000f14c movk   x8, #0xf983, lsl #16
0000f150 movk   x10, #0xf638, lsl #16
0000f154 movk   x8, #0x4d74, lsl #32
0000f158 mov    w1, w25
0000f15c mov    w0, w23
0000f160 movk   x8, #0x9057, lsl #48
0000f164 movk   x10, #0xf954, lsl #32
0000f168 movk   x10, #0xa35, lsl #48
0000f16c cmp    x9, x10
0000f170 b.eq   #0xef70
0000f174 mov    x8, #0xa9b7
0000f178 movk   x8, #0xa325, lsl #16
0000f17c movk   x8, #0x8a2c, lsl #32
0000f180 movk   x8, #0xd7e, lsl #48
0000f184 cmp    x9, x8
0000f188 b.eq   #0xf57c
0000f18c mov    x8, #0x862
0000f190 movk   x8, #0x28d6, lsl #16
0000f194 movk   x8, #0xce29, lsl #32
0000f198 movk   x8, #0xfdc, lsl #48
0000f19c cmp    x9, x8
0000f1a0 b.eq   #0xf768
0000f1a4 mov    x8, #0xeacf
0000f1a8 movk   x8, #0x3a5e, lsl #16
0000f1ac movk   x8, #0xad42, lsl #32
0000f1b0 movk   x8, #0x1325, lsl #48
0000f1b4 cmp    x9, x8
0000f1b8 b.eq   #0xf410
0000f1bc mov    x8, #0x105a
0000f1c0 movk   x8, #0x459e, lsl #16
0000f1c4 movk   x8, #0x7a8, lsl #32
0000f1c8 movk   x8, #0x1a32, lsl #48
0000f1cc cmp    x9, x8
0000f1d0 b.eq   #0xf5dc
0000f1d4 mov    x8, #0xfd75
0000f1d8 mov    x10, #0xebbb
0000f1dc movk   x8, #0x2a44, lsl #16
0000f1e0 movk   x10, #0xdc1c, lsl #16
0000f1e4 movk   x8, #0xed8e, lsl #32
0000f1e8 mov    w1, w25
0000f1ec mov    w0, w24
0000f1f0 movk   x8, #0x2f85, lsl #48
0000f1f4 movk   x10, #0x83a6, lsl #32
0000f1f8 movk   x10, #0x1d52, lsl #48
0000f1fc cmp    x9, x10
0000f200 b.eq   #0xef70
0000f204 mov    x8, #0x9aa3
0000f208 movk   x8, #0x2124, lsl #16
0000f20c movk   x8, #0xd226, lsl #32
0000f210 movk   x8, #0x2ea5, lsl #48
0000f214 cmp    x9, x8
0000f218 b.eq   #0xf840
0000f21c mov    x8, #0xfd75
0000f220 movk   x8, #0x2a44, lsl #16
0000f224 movk   x8, #0xed8e, lsl #32
0000f228 movk   x8, #0x2f85, lsl #48
0000f22c cmp    x9, x8
0000f230 b.eq   #0xf878
0000f234 mov    x8, #0x177e
0000f238 movk   x8, #0x68f5, lsl #16
0000f23c movk   x8, #0x916b, lsl #32
0000f240 movk   x8, #0x33d1, lsl #48
0000f244 cmp    x9, x8
0000f248 b.eq   #0xf4ec
0000f24c mov    x8, #0x7f5a
0000f250 movk   x8, #0xd34b, lsl #16
0000f254 movk   x8, #0x836d, lsl #32
0000f258 movk   x8, #0x417b, lsl #48
0000f25c cmp    x9, x8
0000f260 b.eq   #0xf3ac
0000f264 mov    x8, #0x4c84
0000f268 movk   x8, #0xb78b, lsl #16
0000f26c movk   x8, #0x4e1a, lsl #32
0000f270 movk   x8, #0x4300, lsl #48
0000f274 cmp    x9, x8
0000f278 b.eq   #0xf818
0000f27c mov    x8, #0x319
0000f280 movk   x8, #0xa9b9, lsl #16
0000f284 movk   x8, #0x9e9e, lsl #32
0000f288 movk   x8, #0x4714, lsl #48
0000f28c cmp    x9, x8
0000f290 b.eq   #0xf530
0000f294 mov    x8, #0xf1bd
0000f298 movk   x8, #0x21c6, lsl #16
0000f29c movk   x8, #0xf358, lsl #32
0000f2a0 movk   x8, #0x4a3f, lsl #48
0000f2a4 cmp    x9, x8
0000f2a8 b.eq   #0xf54c
0000f2ac mov    x8, #0x378f
0000f2b0 movk   x8, #0x1b43, lsl #16
0000f2b4 movk   x8, #0xa367, lsl #32
0000f2b8 movk   x8, #0x4cd0, lsl #48
0000f2bc cmp    x9, x8
0000f2c0 b.eq   #0xf72c
0000f2c4 mov    x8, #0x3a3b
0000f2c8 movk   x8, #0xb9d6, lsl #16
0000f2cc movk   x8, #0x59ae, lsl #32
0000f2d0 movk   x8, #0x510e, lsl #48
0000f2d4 cmp    x9, x8
0000f2d8 b.eq   #0xf618
0000f2dc mov    x8, #0x1c14
0000f2e0 movk   x8, #0xbcaa, lsl #16
0000f2e4 movk   x8, #0xe79f, lsl #32
0000f2e8 movk   x8, #0x519c, lsl #48
0000f2ec cmp    x9, x8
0000f2f0 b.eq   #0xf3ac
0000f2f4 mov    x8, #0x3a3b
0000f2f8 mov    x10, #0xd409
0000f2fc movk   x8, #0xb9d6, lsl #16
0000f300 movk   x10, #0x4bc7, lsl #16
0000f304 movk   x8, #0x59ae, lsl #32
0000f308 mov    w1, w25
0000f30c mov    w0, w23
0000f310 movk   x8, #0x510e, lsl #48
0000f314 movk   x10, #0x365d, lsl #32
0000f318 movk   x10, #0x5c61, lsl #48
0000f31c cmp    x9, x10
0000f320 b.eq   #0xef70
0000f324 mov    x8, #0x9a89
0000f328 movk   x8, #0x559b, lsl #16
0000f32c movk   x8, #0x3537, lsl #32
0000f330 movk   x8, #0x6566, lsl #48
0000f334 cmp    x9, x8
0000f338 b.eq   #0xf7a4
0000f33c mov    x8, #0xf2b4
0000f340 movk   x8, #0xcb03, lsl #16
0000f344 movk   x8, #0x560, lsl #32
0000f348 movk   x8, #0x6e9c, lsl #48
0000f34c cmp    x9, x8
0000f350 b.eq   #0xf7d4
0000f354 mov    x8, #0xa065
0000f358 movk   x8, #0x5a49, lsl #16
0000f35c movk   x8, #0xa9ab, lsl #32
0000f360 movk   x8, #0x7a00, lsl #48
0000f364 cmp    x9, x8
0000f368 b.eq   #0xf658
0000f36c mov    x8, #0x1df8
0000f370 movk   x8, #0x53de, lsl #16
0000f374 movk   x8, #0xeca8, lsl #32
0000f378 movk   x8, #0x7d6a, lsl #48
0000f37c cmp    x9, x8
0000f380 b.eq   #0xf664
0000f384 mov    x10, #0xb101
0000f388 mov    w1, w25
0000f38c movk   x10, #0x7502, lsl #16
0000f390 mov    w0, w23
0000f394 mov    x8, x9
0000f398 movk   x10, #0xcf0b, lsl #32
0000f39c movk   x10, #0x312a, lsl #48
0000f3a0 cmp    x9, x10
0000f3a4 b.ne   #0xef70
0000f3a8 b      #0xf93c
0000f3ac stur   wzr, [x29, #-0x64]
0000f3b0 mov    x8, #0xf1bd
0000f3b4 mov    w1, w25
0000f3b8 movk   x8, #0x21c6, lsl #16
0000f3bc mov    w0, w23
0000f3c0 movk   x8, #0xf358, lsl #32
0000f3c4 movk   x8, #0x4a3f, lsl #48
0000f3c8 b      #0xef70
0000f3cc ldur   x8, [x29, #-0x28]
0000f3d0 mov    x9, #0xeea7
0000f3d4 movk   x9, #0xcfb3, lsl #16
0000f3d8 mov    w1, w25
0000f3dc movk   x9, #0x23aa, lsl #32
0000f3e0 mov    w0, w23
0000f3e4 str    x8, [sp, #0x38]
0000f3e8 cmp    x8, #0
0000f3ec mov    x8, #0x88a8
0000f3f0 ccmp   x27, #0, #4, ne
0000f3f4 movk   x8, #0x7ae6, lsl #16
0000f3f8 movk   x9, #0xf35c, lsl #48
0000f3fc movk   x8, #0xea5, lsl #32
0000f400 stur   xzr, [x29, #-0x50]
0000f404 movk   x8, #0xcda6, lsl #48
0000f408 csel   x8, x9, x8, ne
0000f40c b      #0xef70
0000f410 fmov   d0, d8
0000f414 ldur   x0, [x29, #-0x60]
0000f418 bl     #0xdbb0
0000f41c mov    x20, x27
0000f420 ldur   x27, [x29, #-0x70]
0000f424 sub    x3, x29, #0x40
0000f428 sub    x4, x29, #0x30
0000f42c mov    x1, x20
0000f430 ldr    x2, [sp, #0x20]
0000f434 mov    x0, x27
0000f438 bl     #0x9dc78
0000f43c ldr    w8, [x27]
0000f440 mov    x27, x20
0000f444 mov    x20, #0xe650
0000f448 mov    x9, #0x9aa3
0000f44c movk   x20, #0xf983, lsl #16
0000f450 movk   x9, #0x2124, lsl #16
0000f454 cmp    w8, #0
0000f458 mov    x8, #0x319
0000f45c movk   x8, #0xa9b9, lsl #16
0000f460 movk   x20, #0x4d74, lsl #32
0000f464 movk   x8, #0x9e9e, lsl #32
0000f468 movk   x9, #0xd226, lsl #32
0000f46c movk   x20, #0x9057, lsl #48
0000f470 movk   x8, #0x4714, lsl #48
0000f474 movk   x9, #0x2ea5, lsl #48
0000f478 b      #0xf868
0000f47c ldr    x8, [x27]
0000f480 mov    x0, x27
0000f484 ldr    x1, [sp, #0x50]
0000f488 ldr    x8, [x8, #0xb8]
0000f48c blr    x8
0000f490 mov    x8, #0xf2b4
0000f494 mov    w1, w25
0000f498 movk   x8, #0xcb03, lsl #16
0000f49c mov    w0, w23
0000f4a0 movk   x8, #0x560, lsl #32
0000f4a4 movk   x8, #0x6e9c, lsl #48
0000f4a8 b      #0xef70
0000f4ac ldr    x8, [sp, #0x30]
0000f4b0 mov    w1, w25
0000f4b4 mov    w0, w23
0000f4b8 sub    x8, x8, #1
0000f4bc str    x8, [sp, #0x70]
0000f4c0 ldur   x8, [x29, #-0x78]
0000f4c4 add    x8, x8, #1
0000f4c8 str    x8, [sp, #0x78]
0000f4cc ldr    x8, [sp, #0x80]
0000f4d0 add    x8, x8, #1
0000f4d4 str    x8, [sp, #0x68]
0000f4d8 mov    x8, #0x862
0000f4dc movk   x8, #0x28d6, lsl #16
0000f4e0 movk   x8, #0xce29, lsl #32
0000f4e4 movk   x8, #0xfdc, lsl #48
0000f4e8 b      #0xef70
0000f4ec sub    x3, x29, #0x58
0000f4f0 ldur   x0, [x29, #-0x70]
0000f4f4 mov    x1, x27
0000f4f8 ldr    x2, [sp, #0x40]
0000f4fc bl     #0xa4f50
0000f500 ldur   x8, [x29, #-0x58]
0000f504 mov    x9, #0x7f5a
0000f508 movk   x9, #0xd34b, lsl #16
0000f50c movk   x9, #0x836d, lsl #32
0000f510 str    x8, [sp, #0x58]
0000f514 cmp    x8, #0
0000f518 mov    x8, #0x93f
0000f51c movk   x9, #0x417b, lsl #48
0000f520 movk   x8, #0x235, lsl #16
0000f524 movk   x8, #0x9fda, lsl #32
0000f528 movk   x8, #0xd6ac, lsl #48
0000f52c b      #0xf868
0000f530 mov    x8, #0xfd75
0000f534 mov    w0, wzr
0000f538 movk   x8, #0x2a44, lsl #16
0000f53c mov    w1, w25
0000f540 movk   x8, #0xed8e, lsl #32
0000f544 movk   x8, #0x2f85, lsl #48
0000f548 b      #0xef70
0000f54c ldur   x8, [x29, #-0x70]
0000f550 mov    w1, w25
0000f554 ldur   w24, [x29, #-0x64]
0000f558 mov    w0, w23
0000f55c ldr    w8, [x8]
0000f560 cmp    w8, #0
0000f564 mov    x8, #0xebbb
0000f568 movk   x8, #0xdc1c, lsl #16
0000f56c movk   x8, #0x83a6, lsl #32
0000f570 movk   x8, #0x1d52, lsl #48
0000f574 csel   x8, x19, x8, eq
0000f578 b      #0xef70
0000f57c ldr    x8, [x27]
0000f580 mov    x0, x27
0000f584 ldr    x1, [sp, #0x48]
0000f588 ldr    x8, [x8, #0xb8]
0000f58c blr    x8
0000f590 mov    x8, #0x4338
0000f594 mov    w1, w25
0000f598 movk   x8, #0x2970, lsl #16
0000f59c mov    w0, w23
0000f5a0 movk   x8, #0x28c2, lsl #32
0000f5a4 movk   x8, #0x18c, lsl #48
0000f5a8 b      #0xef70
0000f5ac ldr    x8, [x27]
0000f5b0 mov    x0, x27
0000f5b4 ldr    x1, [sp, #0x38]
0000f5b8 ldr    x8, [x8, #0xb8]
0000f5bc blr    x8
0000f5c0 mov    x8, #0xb101
0000f5c4 mov    w1, w25
0000f5c8 movk   x8, #0x7502, lsl #16
0000f5cc mov    w0, w23
0000f5d0 movk   x8, #0xcf0b, lsl #32
0000f5d4 movk   x8, #0x312a, lsl #48
0000f5d8 b      #0xef70
0000f5dc ldur   x8, [x29, #-0x60]
0000f5e0 sub    x3, x29, #0x50
0000f5e4 ldur   x0, [x29, #-0x70]
0000f5e8 mov    x1, x27
0000f5ec ldr    x2, [x8, #0x10]
0000f5f0 bl     #0xa432c
0000f5f4 ldur   x8, [x29, #-0x50]
0000f5f8 str    x8, [sp, #0x40]
0000f5fc cmp    x8, #0
0000f600 mov    x8, #0x177e
0000f604 movk   x8, #0x68f5, lsl #16
0000f608 movk   x8, #0x916b, lsl #32
0000f60c movk   x8, #0x33d1, lsl #48
0000f610 csel   x8, x21, x8, eq
0000f614 b      #0xf86c
0000f618 ldr    x0, [sp, #0x10]
0000f61c mov    w1, #7
0000f620 bl     #0x1441e4
0000f624 ldur   x10, [x29, #-0x60]
0000f628 mov    w1, w25
0000f62c mov    w0, w23
0000f630 ldr    x8, [x10, #0xf0]
0000f634 orr    x9, x8, #1
0000f638 mov    w8, #1
0000f63c stur   w8, [x29, #-0x64]
0000f640 mov    x8, #0xf1bd
0000f644 movk   x8, #0x21c6, lsl #16
0000f648 str    x9, [x10, #0xf0]
0000f64c movk   x8, #0xf358, lsl #32
0000f650 movk   x8, #0x4a3f, lsl #48
0000f654 b      #0xef70
0000f658 mov    w8, #1
0000f65c stur   w8, [x29, #-0x64]
0000f660 b      #0xf3b0
0000f664 ldur   x10, [x29, #-0x60]
0000f668 mov    x11, #0x4c84
0000f66c ldur   x9, [x29, #-0x40]
0000f670 movk   x11, #0xb78b, lsl #16
0000f674 movk   x11, #0x4e1a, lsl #32
0000f678 mov    w1, w25
0000f67c ldr    x8, [x10, #0xf0]
0000f680 movk   x11, #0x4300, lsl #48
0000f684 str    x9, [sp, #0x28]
0000f688 cmp    x9, #0
0000f68c mov    x9, #0x80
0000f690 mov    w0, w23
0000f694 movk   x9, #8, lsl #48
0000f698 str    w25, [sp, #0xc]
0000f69c orr    x9, x8, x9
0000f6a0 mov    x8, #0xdaf5
0000f6a4 movk   x8, #0x621, lsl #16
0000f6a8 movk   x8, #0xc035, lsl #32
0000f6ac movk   x8, #0xc90d, lsl #48
0000f6b0 str    x9, [x10, #0xf0]
0000f6b4 csel   x8, x8, x11, eq
0000f6b8 b      #0xef70
0000f6bc ldr    x0, [sp, #0x60]
0000f6c0 bl     #0x148a00
0000f6c4 mov    x8, #0xe650
0000f6c8 mov    w1, w25
0000f6cc movk   x8, #0xf983, lsl #16
0000f6d0 mov    w0, w23
0000f6d4 movk   x8, #0x4d74, lsl #32
0000f6d8 stur   xzr, [x29, #-0x48]
0000f6dc movk   x8, #0x9057, lsl #48
0000f6e0 b      #0xef70
0000f6e4 ldur   x3, [x29, #-0x28]
0000f6e8 sub    x4, x29, #0x48
0000f6ec sub    x5, x29, #0x38
0000f6f0 mov    x0, x27
0000f6f4 ldur   x1, [x29, #-0x70]
0000f6f8 ldr    x2, [sp, #0x58]
0000f6fc bl     #0xd91d4
0000f700 mov    x8, #0x2488
0000f704 mov    x9, #0xeacf
0000f708 movk   x8, #0xe03e, lsl #16
0000f70c movk   x9, #0x3a5e, lsl #16
0000f710 movk   x8, #0x6c0e, lsl #32
0000f714 movk   x9, #0xad42, lsl #32
0000f718 mov    w1, w25
0000f71c tst    w0, #1
0000f720 movk   x8, #0xacc4, lsl #48
0000f724 movk   x9, #0x1325, lsl #48
0000f728 b      #0xf908
0000f72c fmov   d0, d8
0000f730 ldur   x0, [x29, #-0x60]
0000f734 bl     #0xdbb0
0000f738 ldur   x8, [x29, #-0x48]
0000f73c mov    w1, w25
0000f740 ldur   x9, [x29, #-0x40]
0000f744 mov    w0, w23
0000f748 str    x8, [sp, #0x68]
0000f74c ldur   x8, [x29, #-0x38]
0000f750 stp    x8, x9, [sp, #0x70]
0000f754 mov    x8, #0x862
0000f758 movk   x8, #0x28d6, lsl #16
0000f75c movk   x8, #0xce29, lsl #32
0000f760 movk   x8, #0xfdc, lsl #48
0000f764 b      #0xef70
0000f768 ldr    x9, [sp, #0x70]
0000f76c mov    x8, #0xa065
0000f770 movk   x8, #0x5a49, lsl #16
0000f774 mov    w1, w25
0000f778 movk   x8, #0xa9ab, lsl #32
0000f77c mov    w0, w23
0000f780 cmp    x9, #0
0000f784 str    x9, [sp, #0x30]
0000f788 ldr    x9, [sp, #0x78]
0000f78c movk   x8, #0x7a00, lsl #48
0000f790 csel   x8, x8, x26, eq
0000f794 stur   x9, [x29, #-0x78]
0000f798 ldr    x9, [sp, #0x68]
0000f79c str    x9, [sp, #0x80]
0000f7a0 b      #0xef70
0000f7a4 ldur   x8, [x29, #-0x48]
0000f7a8 mov    x9, #0x45f3
0000f7ac movk   x9, #0xf638, lsl #16
0000f7b0 movk   x9, #0xf954, lsl #32
0000f7b4 str    x8, [sp, #0x60]
0000f7b8 cmp    x8, #0
0000f7bc mov    x8, #0xb8e4
0000f7c0 movk   x9, #0xa35, lsl #48
0000f7c4 movk   x8, #0xf6f4, lsl #16
0000f7c8 movk   x8, #0x1f89, lsl #32
0000f7cc movk   x8, #0xa52c, lsl #48
0000f7d0 b      #0xf868
0000f7d4 ldur   x8, [x29, #-0x50]
0000f7d8 mov    x9, #0xa9b7
0000f7dc movk   x9, #0xa325, lsl #16
0000f7e0 mov    w1, w25
0000f7e4 movk   x9, #0x8a2c, lsl #32
0000f7e8 mov    w0, w23
0000f7ec str    x8, [sp, #0x48]
0000f7f0 cmp    x8, #0
0000f7f4 mov    x8, #0x5e3a
0000f7f8 ccmp   x27, #0, #4, ne
0000f7fc movk   x8, #0xf4a0, lsl #16
0000f800 movk   x9, #0xd7e, lsl #48
0000f804 movk   x8, #0xe28, lsl #32
0000f808 stur   xzr, [x29, #-0x58]
0000f80c movk   x8, #0x90a0, lsl #48
0000f810 csel   x8, x9, x8, ne
0000f814 b      #0xef70
0000f818 ldr    x0, [sp, #0x28]
0000f81c bl     #0x148a00
0000f820 mov    x8, #0x9a89
0000f824 mov    w1, w25
0000f828 movk   x8, #0x559b, lsl #16
0000f82c mov    w0, w23
0000f830 movk   x8, #0x3537, lsl #32
0000f834 stur   xzr, [x29, #-0x40]
0000f838 movk   x8, #0x6566, lsl #48
0000f83c b      #0xef70
0000f840 ldp    x8, x9, [x29, #-0x38]
0000f844 cmp    x8, x9
0000f848 mov    x8, #0xd409
0000f84c mov    x9, #0x378f
0000f850 movk   x8, #0x4bc7, lsl #16
0000f854 movk   x9, #0x1b43, lsl #16
0000f858 movk   x8, #0x365d, lsl #32
0000f85c movk   x9, #0xa367, lsl #32
0000f860 movk   x8, #0x5c61, lsl #48
0000f864 movk   x9, #0x4cd0, lsl #48
0000f868 csel   x8, x9, x8, eq
0000f86c mov    w1, w25
0000f870 mov    w0, w23
0000f874 b      #0xef70
0000f878 ldur   x0, [x29, #-0x60]
0000f87c bl     #0xf980
0000f880 mov    x8, #0x1df8
0000f884 mov    w1, w23
0000f888 movk   x8, #0x53de, lsl #16
0000f88c mov    w0, w23
0000f890 movk   x8, #0xeca8, lsl #32
0000f894 movk   x8, #0x7d6a, lsl #48
0000f898 b      #0xef70
0000f89c ldur   x8, [x29, #-0x78]
0000f8a0 ldr    x9, [sp, #0x80]
0000f8a4 ldrb   w8, [x8]
0000f8a8 ldrb   w9, [x9]
0000f8ac cmp    w8, w9
0000f8b0 mov    x8, #0xd62d
0000f8b4 movk   x8, #0x5cb1, lsl #16
0000f8b8 movk   x8, #0xcda9, lsl #32
0000f8bc movk   x8, #0x9fb5, lsl #48
0000f8c0 csel   x8, x22, x8, eq
0000f8c4 b      #0xf86c
0000f8c8 sub    x4, x29, #0x28
0000f8cc mov    x0, x27
0000f8d0 ldur   x1, [x29, #-0x70]
0000f8d4 ldur   x2, [x29, #-0x60]
0000f8d8 ldr    x3, [sp, #0x18]
0000f8dc bl     #0xd7aac
0000f8e0 mov    x8, #0x1c14
0000f8e4 mov    x9, #0x105a
0000f8e8 movk   x8, #0xbcaa, lsl #16
0000f8ec movk   x9, #0x459e, lsl #16
0000f8f0 movk   x8, #0xe79f, lsl #32
0000f8f4 movk   x9, #0x7a8, lsl #32
0000f8f8 mov    w1, w25
0000f8fc movk   x8, #0x519c, lsl #48
0000f900 movk   x9, #0x1a32, lsl #48
0000f904 tst    w0, #1
0000f908 csel   x8, x9, x8, ne
0000f90c mov    w0, w23
0000f910 b      #0xef70
0000f914 ldur   x8, [x29, #-0x58]
0000f918 str    x8, [sp, #0x50]
0000f91c cmp    x8, #0
0000f920 mov    x8, #0xca7
0000f924 ccmp   x27, #0, #4, ne
0000f928 movk   x8, #0x9688, lsl #16
0000f92c movk   x8, #0x5d71, lsl #32
0000f930 movk   x8, #0xe653, lsl #48
0000f934 csel   x8, x28, x8, ne
0000f938 b      #0xf86c
0000f93c ldr    x8, [sp]
0000f940 ldr    x8, [x8, #0x28]
0000f944 ldur   x9, [x29, #-0x20]
0000f948 cmp    x8, x9
0000f94c b.ne   #0xf97c
0000f950 ldp    x20, x19, [sp, #0x150]
0000f954 ldp    x22, x21, [sp, #0x140]
0000f958 ldp    x24, x23, [sp, #0x130]
0000f95c ldp    x26, x25, [sp, #0x120]
0000f960 ldp    x28, x27, [sp, #0x110]
0000f964 ldp    x29, x30, [sp, #0x100]
0000f968 ldr    w8, [sp, #0xc]
0000f96c ldr    d8, [sp, #0xf0]
0000f970 and    w0, w8, #1
0000f974 add    sp, sp, #0x160
0000f978 ret    
0000f97c bl     #0x148a10