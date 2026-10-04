==== 0x146400 0x146800
00146400 movk    x11, #0x9f87, lsl #32
00146404 cmp     w0, #0
00146408 movk    x30, #0xd078, lsl #48
0014640c movk    x7, #0xb6c1, lsl #48
00146410 movk    x17, #0xc20e, lsl #48
00146414 movk    x14, #0x24c0, lsl #48
00146418 movk    x13, #0x1704, lsl #48
0014641c movk    x12, #0xa7a4, lsl #48
00146420 movk    x11, #0xd5b5, lsl #48
00146424 mov     x1, x24
00146428 mov     x2, x23
0014642c mov     x0, x22
00146430 csel    x9, x16, x15, ge
00146434 mov     x4, x25
00146438 mov     x3, x19
0014643c mov     x5, x28
00146440 mov     x6, x21
00146444 b       #0x145e58
00146448 mov     x0, x19
0014644c ldp     x20, x19, [sp, #0x120]
00146450 ldp     x22, x21, [sp, #0x110]
00146454 ldp     x24, x23, [sp, #0x100]
00146458 ldp     x26, x25, [sp, #0xf0]
0014645c ldp     x28, x27, [sp, #0xe0]
00146460 ldp     x29, x30, [sp, #0xd0]
00146464 add     sp, sp, #0x130
00146468 ret     
0014646c b       #0x147548
00146470 b       #0x147630
00146474 b       #0x147620
00146478 b       #0x147734
0014647c b       #0x147c68
00146480 stp     x29, x30, [sp, #-0x20]!
00146484 stp     x20, x19, [sp, #0x10]
00146488 mov     x29, sp
0014648c mov     x19, x0
00146490 mov     x20, #0xd2d1
00146494 mov     w0, #1
00146498 mov     w1, #8
0014649c movk    x20, #0xf825, lsl #16
001464a0 movk    x20, #0xee0c, lsl #32
001464a4 movk    x20, #0x5c23, lsl #48
001464a8 bl      #0x148b90
001464ac mov     x8, #0x5dae
001464b0 mov     x9, #0xa74a
001464b4 movk    x8, #0xbd6e, lsl #16
001464b8 movk    x9, #0x5ea3, lsl #16
001464bc mov     x10, #0x8e81
001464c0 mov     x13, #0x8e81
001464c4 movk    x8, #0x6aaa, lsl #32
001464c8 movk    x9, #0xa04f, lsl #32
001464cc movk    x10, #0xe154, lsl #16
001464d0 movk    x13, #0xe154, lsl #16
001464d4 movk    x8, #0x28f0, lsl #48
001464d8 movk    x9, #0xfa1e, lsl #48
001464dc cmp     x0, #0
001464e0 movk    x10, #0x3b5e, lsl #32
001464e4 movk    x13, #0x3b5e, lsl #32
001464e8 movk    x10, #0x7cc5, lsl #48
001464ec csel    x11, x9, x8, eq
001464f0 mov     w12, #2
001464f4 movk    x13, #0x7cc5, lsl #48
001464f8 cmp     x13, x9
001464fc b.eq    #0x14652c
00146500 cmp     x13, x10
00146504 b.eq    #0x146544
00146508 cmp     x13, x20
0014650c b.eq    #0x14654c
00146510 cmp     x13, x8
00146514 b.ne    #0x1464f8
00146518 mov     x13, #0xd2d1
0014651c movk    x13, #0xf825, lsl #16
00146520 movk    x13, #0xee0c, lsl #32
00146524 movk    x13, #0x5c23, lsl #48
00146528 b       #0x1464f8
0014652c mov     x13, #0xd2d1
00146530 str     w12, [x19]
00146534 movk    x13, #0xf825, lsl #16
00146538 movk    x13, #0xee0c, lsl #32
0014653c movk    x13, #0x5c23, lsl #48
00146540 b       #0x1464f8
00146544 mov     x13, x11
00146548 b       #0x1464f8
0014654c ldp     x20, x19, [sp, #0x10]
00146550 ldp     x29, x30, [sp], #0x20
00146554 ret     
00146558 stp     x29, x30, [sp, #-0x30]!
0014655c stp     x22, x21, [sp, #0x10]
00146560 stp     x20, x19, [sp, #0x20]
00146564 mov     x29, sp
00146568 mov     x20, x1
0014656c mov     x21, x0
00146570 mov     x22, #0xdf4a
00146574 mov     w0, #1
00146578 mov     w1, #0x10
0014657c movk    x22, #0xbdc8, lsl #16
00146580 movk    x22, #0xceb, lsl #32
00146584 mov     w19, w2
00146588 movk    x22, #0xc8d5, lsl #48
0014658c bl      #0x148b90
00146590 mov     x8, #0xb7cc
00146594 mov     x9, #0xc335
00146598 movk    x8, #0xff64, lsl #16
0014659c movk    x9, #0x1484, lsl #16
001465a0 mov     x10, #0x9a1f
001465a4 mov     x13, #0x9a1f
001465a8 movk    x8, #0xf23e, lsl #32
001465ac movk    x9, #0x16b3, lsl #32
001465b0 movk    x10, #0xd6a5, lsl #16
001465b4 movk    x13, #0xd6a5, lsl #16
001465b8 movk    x8, #0x8f3d, lsl #48
001465bc movk    x9, #0xb3cc, lsl #48
001465c0 cmp     x0, #0
001465c4 movk    x10, #0xc885, lsl #32
001465c8 movk    x13, #0xc885, lsl #32
001465cc movk    x10, #0xf611, lsl #48
001465d0 csel    x11, x9, x8, eq
001465d4 mov     w12, #2
001465d8 movk    x13, #0xf611, lsl #48
001465dc cmp     x13, x8
001465e0 b.eq    #0x146614
001465e4 cmp     x13, x10
001465e8 b.eq    #0x146638
001465ec cmp     x13, x22
001465f0 b.eq    #0x146640
001465f4 cmp     x13, x9
001465f8 b.ne    #0x1465dc
001465fc mov     x13, #0xdf4a
00146600 str     w12, [x21]
00146604 movk    x13, #0xbdc8, lsl #16
00146608 movk    x13, #0xceb, lsl #32
0014660c movk    x13, #0xc8d5, lsl #48
00146610 b       #0x1465dc
00146614 ldr     x14, [x20]
00146618 mov     x13, #0xdf4a
0014661c movk    x13, #0xbdc8, lsl #16
00146620 str     w19, [x0]
00146624 movk    x13, #0xceb, lsl #32
00146628 str     x0, [x20]
0014662c movk    x13, #0xc8d5, lsl #48
00146630 str     x14, [x0, #8]
00146634 b       #0x1465dc
00146638 mov     x13, x11
0014663c b       #0x1465dc
00146640 ldp     x20, x19, [sp, #0x20]
00146644 ldp     x22, x21, [sp, #0x10]
00146648 ldp     x29, x30, [sp], #0x30
0014664c ret     
00146650 stp     x29, x30, [sp, #-0x50]!
00146654 stp     x26, x25, [sp, #0x10]
00146658 stp     x24, x23, [sp, #0x20]
0014665c stp     x22, x21, [sp, #0x30]
00146660 stp     x20, x19, [sp, #0x40]
00146664 mov     x29, sp
00146668 ldr     x20, [x0]
0014666c mov     x22, #0x3581
00146670 mov     x23, #0x2f9c
00146674 movk    x22, #0xbcba, lsl #16
00146678 movk    x23, #0xc396, lsl #16
0014667c mov     x24, #0xafb5
00146680 ldr     w8, [x20]
00146684 mov     x26, #0x7515
00146688 movk    x22, #0x133, lsl #32
0014668c movk    x23, #0x5e8f, lsl #32
00146690 movk    x24, #0xa12b, lsl #16
00146694 movk    x26, #0xb217, lsl #16
00146698 subs    w21, w8, #1
0014669c mov     x8, #0x7515
001466a0 movk    x8, #0xb217, lsl #16
001466a4 movk    x22, #0x761f, lsl #48
001466a8 movk    x23, #0xf2cd, lsl #48
001466ac movk    x24, #0xce93, lsl #32
001466b0 movk    x26, #0xdfc8, lsl #32
001466b4 movk    x8, #0xdfc8, lsl #32
001466b8 mov     x19, x0
001466bc movk    x24, #0xb225, lsl #48
001466c0 csel    x25, x23, x22, eq
001466c4 movk    x26, #0x768a, lsl #48
001466c8 movk    x8, #0x768a, lsl #48
001466cc str     w21, [x20]
001466d0 cmp     x8, x24
001466d4 b.eq    #0x146720
001466d8 cmp     x8, x23
001466dc b.eq    #0x1466f4
001466e0 cmp     x8, x26
001466e4 b.eq    #0x146718
001466e8 cmp     x8, x22
001466ec b.ne    #0x1466d0
001466f0 b       #0x146704
001466f4 ldr     x8, [x20, #8]
001466f8 mov     x0, x20
001466fc str     x8, [x19]
00146700 bl      #0x148a00
00146704 mov     x8, #0xafb5
00146708 movk    x8, #0xa12b, lsl #16
0014670c movk    x8, #0xce93, lsl #32
00146710 movk    x8, #0xb225, lsl #48
00146714 b       #0x1466d0
00146718 mov     x8, x25
0014671c b       #0x1466d0
00146720 mov     w0, w21
00146724 ldp     x20, x19, [sp, #0x40]
00146728 ldp     x22, x21, [sp, #0x30]
0014672c ldp     x24, x23, [sp, #0x20]
00146730 ldp     x26, x25, [sp, #0x10]
00146734 ldp     x29, x30, [sp], #0x50
00146738 ret     
0014673c stp     x29, x30, [sp, #-0x40]!
00146740 stp     x24, x23, [sp, #0x10]
00146744 stp     x22, x21, [sp, #0x20]
00146748 stp     x20, x19, [sp, #0x30]
0014674c mov     x29, sp
00146750 mov     x20, #0xee15
00146754 mov     x21, #0x8779
00146758 movk    x20, #0x1fe1, lsl #16
0014675c movk    x21, #0xf1b8, lsl #16
00146760 mov     x22, #0x7811
00146764 mov     x24, #0x28cc
00146768 mov     x8, #0x28cc
0014676c movk    x20, #0x5376, lsl #32
00146770 movk    x21, #0x3378, lsl #32
00146774 movk    x22, #0x740, lsl #16
00146778 movk    x24, #0xc3e2, lsl #16
0014677c movk    x8, #0xc3e2, lsl #16
00146780 movk    x20, #0x6aa9, lsl #48
00146784 movk    x21, #0xeb0, lsl #48
00146788 cmp     x0, #0
0014678c movk    x22, #0x67ad, lsl #32
00146790 movk    x24, #0x7819, lsl #32
00146794 movk    x8, #0x7819, lsl #32
00146798 mov     x19, x0
0014679c movk    x22, #0xf79c, lsl #48
001467a0 csel    x23, x21, x20, eq
001467a4 movk    x24, #0x6b85, lsl #48
001467a8 movk    x8, #0x6b85, lsl #48
001467ac cmp     x8, x22
001467b0 b.eq    #0x1467fc
001467b4 cmp     x8, x24
001467b8 b.eq    #0x1467d0
001467bc cmp     x8, x20
001467c0 b.eq    #0x1467d8
001467c4 cmp     x8, x21
001467c8 b.ne    #0x1467ac
001467cc b       #0x1467e8
001467d0 mov     x8, x23
001467d4 b       #0x1467ac
001467d8 ldr     x0, [x19, #8]
001467dc bl      #0x14673c
001467e0 mov     x0, x19
001467e4 bl      #0x148a00
001467e8 mov     x8, #0x7811
001467ec movk    x8, #0x740, lsl #16
001467f0 movk    x8, #0x67ad, lsl #32
001467f4 movk    x8, #0xf79c, lsl #48
001467f8 b       #0x1467ac
001467fc ldp     x20, x19, [sp, #0x30]
==== 0x146e00 0x147340
00146e00 ldr     w8, [x19]
00146e04 mov     x3, #0xee15
00146e08 movk    x2, #0x957d, lsl #16
00146e0c movk    x17, #0xb5f6, lsl #16
00146e10 mov     x16, #0x7408
00146e14 mov     x15, #0x2f9c
00146e18 mov     x14, #0x28cc
00146e1c mov     x12, #0x7811
00146e20 mov     x11, #0x8779
00146e24 movk    x3, #0x1fe1, lsl #16
00146e28 movk    x2, #0xadd, lsl #32
00146e2c movk    x17, #0xce8f, lsl #32
00146e30 movk    x16, #0x4e14, lsl #16
00146e34 movk    x15, #0xc396, lsl #16
00146e38 movk    x14, #0xc3e2, lsl #16
00146e3c movk    x12, #0x740, lsl #16
00146e40 movk    x11, #0xf1b8, lsl #16
00146e44 movk    x3, #0x5376, lsl #32
00146e48 movk    x2, #0x549f, lsl #48
00146e4c movk    x17, #0x62d5, lsl #48
00146e50 movk    x16, #0x43cd, lsl #32
00146e54 movk    x15, #0x5e8f, lsl #32
00146e58 movk    x14, #0x7819, lsl #32
00146e5c movk    x12, #0x67ad, lsl #32
00146e60 movk    x11, #0x3378, lsl #32
00146e64 cmp     w8, #0
00146e68 movk    x3, #0x6aa9, lsl #48
00146e6c movk    x16, #0x7f74, lsl #48
00146e70 movk    x15, #0xf2cd, lsl #48
00146e74 movk    x14, #0x6b85, lsl #48
00146e78 movk    x12, #0xf79c, lsl #48
00146e7c movk    x11, #0xeb0, lsl #48
00146e80 csel    x9, x2, x17, eq
00146e84 b       #0x146c9c
00146e88 ldr     w8, [x26]
00146e8c ldr     w9, [sp, #4]
00146e90 cmp     w8, w9
00146e94 csel    x9, x22, x3, lo
00146e98 b       #0x146c9c
00146e9c mov     x9, #0x1859
00146ea0 mov     w8, #6
00146ea4 movk    x9, #0x2b53, lsl #16
00146ea8 movk    x9, #0x6ffc, lsl #32
00146eac movk    x9, #0x930b, lsl #48
00146eb0 str     w8, [x19]
00146eb4 b       #0x146c9c
00146eb8 ldp     x20, x19, [sp, #0x70]
00146ebc ldp     x22, x21, [sp, #0x60]
00146ec0 ldp     x24, x23, [sp, #0x50]
00146ec4 ldp     x26, x25, [sp, #0x40]
00146ec8 ldp     x28, x27, [sp, #0x30]
00146ecc ldp     x29, x30, [sp, #0x20]
00146ed0 add     sp, sp, #0x80
00146ed4 ret     
00146ed8 sub     sp, sp, #0x80
00146edc stp     x29, x30, [sp, #0x20]
00146ee0 stp     x28, x27, [sp, #0x30]
00146ee4 stp     x26, x25, [sp, #0x40]
00146ee8 stp     x24, x23, [sp, #0x50]
00146eec stp     x22, x21, [sp, #0x60]
00146ef0 stp     x20, x19, [sp, #0x70]
00146ef4 add     x29, sp, #0x20
00146ef8 mov     x11, #0x5cb8
00146efc mov     x26, #0x1dac
00146f00 mov     x28, #0x1381
00146f04 mov     x24, #0x25ce
00146f08 mov     x19, #0x4c0d
00146f0c mov     x12, #0x6436
00146f10 mov     x22, #0xb3d0
00146f14 mov     x25, #0xb031
00146f18 mov     x9, #0x1dac
00146f1c movk    x11, #0x2795, lsl #16
00146f20 movk    x26, #0x9f5e, lsl #16
00146f24 movk    x28, #0xa58a, lsl #16
00146f28 movk    x24, #0x8c3e, lsl #16
00146f2c movk    x19, #0x52dd, lsl #16
00146f30 movk    x12, #0x2869, lsl #16
00146f34 movk    x22, #0x566, lsl #16
00146f38 movk    x25, #0x9cc1, lsl #16
00146f3c movk    x9, #0x9f5e, lsl #16
00146f40 movk    x11, #0x15f4, lsl #32
00146f44 movk    x26, #0xb762, lsl #32
00146f48 movk    x28, #0xb763, lsl #32
00146f4c movk    x24, #0xdec2, lsl #32
00146f50 movk    x19, #0x7dcf, lsl #32
00146f54 movk    x12, #0xc5df, lsl #32
00146f58 movk    x22, #0xa50d, lsl #32
00146f5c movk    x25, #0xffeb, lsl #32
00146f60 movk    x9, #0xb762, lsl #32
00146f64 mov     x21, x1
00146f68 movk    x11, #0x77a4, lsl #48
00146f6c movk    x26, #0x3b4a, lsl #48
00146f70 ldr     w27, [x1]
00146f74 movk    x28, #0xbbcd, lsl #48
00146f78 movk    x24, #0xf201, lsl #48
00146f7c movk    x19, #0x48fe, lsl #48
00146f80 movk    x12, #0x56de, lsl #48
00146f84 movk    x22, #0x204a, lsl #48
00146f88 movk    x25, #0x2516, lsl #48
00146f8c movk    x9, #0x3b4a, lsl #48
00146f90 stp     w2, w3, [x29, #-0xc]
00146f94 str     x0, [sp, #8]
00146f98 cmp     x9, x28
00146f9c b.eq    #0x14701c
00146fa0 mov     x8, x9
00146fa4 cmp     x9, x24
00146fa8 b.eq    #0x14703c
00146fac cmp     x8, x22
00146fb0 b.eq    #0x147054
00146fb4 cmp     x8, x25
00146fb8 b.eq    #0x147074
00146fbc mov     x9, #0x5cb8
00146fc0 cmp     x8, x26
00146fc4 movk    x9, #0x2795, lsl #16
00146fc8 movk    x9, #0x15f4, lsl #32
00146fcc movk    x9, #0x77a4, lsl #48
00146fd0 b.eq    #0x146f98
00146fd4 cmp     x8, x19
00146fd8 b.eq    #0x1470b8
00146fdc mov     x9, #0xe386
00146fe0 cmp     x8, x12
00146fe4 movk    x9, #0xeab8, lsl #16
00146fe8 movk    x9, #0xc1ec, lsl #32
00146fec movk    x9, #0x808f, lsl #48
00146ff0 b.eq    #0x146f98
00146ff4 cmp     x8, x11
00146ff8 b.eq    #0x1470d4
00146ffc mov     x10, #0xe386
00147000 mov     x9, x8
00147004 movk    x10, #0xeab8, lsl #16
00147008 movk    x10, #0xc1ec, lsl #32
0014700c movk    x10, #0x808f, lsl #48
00147010 cmp     x8, x10
00147014 b.ne    #0x146f98
00147018 b       #0x147100
0014701c ldr     w8, [x21]
00147020 mov     x9, #0x5cb8
00147024 movk    x9, #0x2795, lsl #16
00147028 movk    x9, #0x15f4, lsl #32
0014702c add     w27, w8, #0x80
00147030 movk    x9, #0x77a4, lsl #48
00147034 str     w27, [x21]
00147038 b       #0x146f98
0014703c ldur    w8, [x29, #-8]
00147040 str     w8, [x23, w20, uxtw #2]
00147044 ldr     w8, [x21, #0x10]
00147048 cmp     w8, w20
0014704c csel    x9, x12, x19, hi
00147050 b       #0x146f98
00147054 mov     x9, #0xe386
00147058 ldr     x8, [sp, #8]
0014705c mov     w10, #2
00147060 movk    x9, #0xeab8, lsl #16
00147064 movk    x9, #0xc1ec, lsl #32
00147068 movk    x9, #0x808f, lsl #48
0014706c str     w10, [x8]
00147070 b       #0x146f98
00147074 ldur    w8, [x29, #-4]
00147078 mov     x0, x23
0014707c add     w8, w8, #0x80
00147080 ubfiz   x1, x8, #2, #0x20
00147084 bl      #0x148c80
00147088 mov     x12, #0x6436
0014708c mov     x11, #0x5cb8
00147090 movk    x12, #0x2869, lsl #16
00147094 movk    x11, #0x2795, lsl #16
00147098 movk    x12, #0xc5df, lsl #32
0014709c movk    x11, #0x15f4, lsl #32
001470a0 cmp     x0, #0
001470a4 movk    x12, #0x56de, lsl #48
001470a8 movk    x11, #0x77a4, lsl #48
001470ac csel    x9, x22, x28, eq
001470b0 str     x0, [x21, #8]
001470b4 b       #0x146f98
001470b8 add     w8, w20, #1
001470bc mov     x9, #0xe386
001470c0 movk    x9, #0xeab8, lsl #16
001470c4 movk    x9, #0xc1ec, lsl #32
001470c8 movk    x9, #0x808f, lsl #48
001470cc str     w8, [x21, #0x10]
001470d0 b       #0x146f98
001470d4 ldr     w8, [x21, #0x14]
001470d8 stur    w27, [x29, #-4]
001470dc ldr     x9, [x21, #0x18]
001470e0 ldr     x23, [x21, #8]
001470e4 sub     w8, w8, #1
001470e8 ldr     w8, [x9, w8, uxtw #2]
001470ec ldur    w9, [x29, #-0xc]
001470f0 add     w20, w8, w9
001470f4 cmp     w20, w27
001470f8 csel    x9, x24, x25, lo
001470fc b       #0x146f98
00147100 ldp     x20, x19, [sp, #0x70]
00147104 ldp     x22, x21, [sp, #0x60]
00147108 ldp     x24, x23, [sp, #0x50]
0014710c ldp     x26, x25, [sp, #0x40]
00147110 ldp     x28, x27, [sp, #0x30]
00147114 ldp     x29, x30, [sp, #0x20]
00147118 add     sp, sp, #0x80
0014711c ret     
00147120 stp     x29, x30, [sp, #-0x30]!
00147124 str     x21, [sp, #0x10]
00147128 stp     x20, x19, [sp, #0x20]
0014712c mov     x29, sp
00147130 ldr     w8, [x1, #0x14]
00147134 mov     x19, x1
00147138 mov     x20, x0
0014713c mov     x21, #0x8d87
00147140 ldr     x0, [x1, #0x18]
00147144 movk    x21, #0xa2f3, lsl #16
00147148 add     w8, w8, #1
0014714c movk    x21, #0x8648, lsl #32
00147150 ubfiz   x1, x8, #2, #0x20
00147154 movk    x21, #0xa5e3, lsl #48
00147158 bl      #0x148c80
0014715c mov     x8, #0x865
00147160 mov     x9, #0xcdf8
00147164 movk    x8, #0x5362, lsl #16
00147168 movk    x9, #0xd72b, lsl #16
0014716c mov     x10, #0xc2a2
00147170 mov     x13, #0xc2a2
00147174 movk    x8, #0x98ea, lsl #32
00147178 movk    x9, #0x55aa, lsl #32
0014717c movk    x10, #0x1048, lsl #16
00147180 movk    x13, #0x1048, lsl #16
00147184 movk    x8, #0xabfd, lsl #48
00147188 movk    x9, #0xfe6b, lsl #48
0014718c cmp     x0, #0
00147190 movk    x10, #0x7104, lsl #32
00147194 movk    x13, #0x7104, lsl #32
00147198 movk    x10, #0x9ffe, lsl #48
0014719c csel    x11, x9, x8, eq
001471a0 mov     w12, #2
001471a4 movk    x13, #0x9ffe, lsl #48
001471a8 cmp     x13, x10
001471ac b.eq    #0x1471e0
001471b0 cmp     x13, x21
001471b4 b.eq    #0x147210
001471b8 cmp     x13, x8
001471bc b.eq    #0x1471e8
001471c0 cmp     x13, x9
001471c4 b.ne    #0x1471a8
001471c8 mov     x13, #0x8d87
001471cc str     w12, [x20]
001471d0 movk    x13, #0xa2f3, lsl #16
001471d4 movk    x13, #0x8648, lsl #32
001471d8 movk    x13, #0xa5e3, lsl #48
001471dc b       #0x1471a8
001471e0 mov     x13, x11
001471e4 b       #0x1471a8
001471e8 ldp     w15, w14, [x19, #0x10]
001471ec mov     x13, #0x8d87
001471f0 str     x0, [x19, #0x18]
001471f4 movk    x13, #0xa2f3, lsl #16
001471f8 movk    x13, #0x8648, lsl #32
001471fc add     w16, w14, #1
00147200 movk    x13, #0xa5e3, lsl #48
00147204 str     w15, [x0, x14, lsl #2]
00147208 str     w16, [x19, #0x14]
0014720c b       #0x1471a8
00147210 ldp     x20, x19, [sp, #0x20]
00147214 ldr     x21, [sp, #0x10]
00147218 ldp     x29, x30, [sp], #0x30
0014721c ret     
00147220 ldr     w12, [x1, #0x14]
00147224 mov     x9, #0x92
00147228 mov     x10, #0xcd53
0014722c mov     x8, #0x1471
00147230 movk    x9, #0x16d6, lsl #16
00147234 movk    x10, #0xade6, lsl #16
00147238 mov     x11, #0xea12
0014723c mov     x15, #0xea12
00147240 movk    x8, #0x4a0, lsl #16
00147244 movk    x9, #0x9d06, lsl #32
00147248 movk    x10, #0xefff, lsl #32
0014724c movk    x11, #0x2ac8, lsl #16
00147250 movk    x15, #0x2ac8, lsl #16
00147254 movk    x8, #0x5fd, lsl #32
00147258 movk    x9, #0x2680, lsl #48
0014725c movk    x10, #0x13d4, lsl #48
00147260 movk    x11, #0x1d60, lsl #32
00147264 cmp     w12, #0
00147268 movk    x15, #0x1d60, lsl #32
0014726c movk    x8, #0xa11a, lsl #48
00147270 movk    x11, #0x1023, lsl #48
00147274 sub     w12, w12, #1
00147278 csel    x13, x10, x9, eq
0014727c mov     w14, #7
00147280 movk    x15, #0x1023, lsl #48
00147284 cmp     x15, x8
00147288 b.eq    #0x1472e4
0014728c cmp     x15, x11
00147290 b.eq    #0x1472bc
00147294 cmp     x15, x9
00147298 b.eq    #0x1472c4
0014729c cmp     x15, x10
001472a0 b.ne    #0x147284
001472a4 mov     x15, #0x1471
001472a8 str     w14, [x0]
001472ac movk    x15, #0x4a0, lsl #16
001472b0 movk    x15, #0x5fd, lsl #32
001472b4 movk    x15, #0xa11a, lsl #48
001472b8 b       #0x147284
001472bc mov     x15, x13
001472c0 b       #0x147284
001472c4 ldr     x15, [x1, #0x18]
001472c8 ldr     w16, [x15, x12, lsl #2]
001472cc mov     x15, #0x1471
001472d0 movk    x15, #0x4a0, lsl #16
001472d4 movk    x15, #0x5fd, lsl #32
001472d8 movk    x15, #0xa11a, lsl #48
001472dc stp     w16, w12, [x1, #0x10]
001472e0 b       #0x147284
001472e4 ret     
001472e8 ldr     w8, [x0, #0x14]
001472ec ldr     x9, [x0, #0x18]
001472f0 sub     w8, w8, #1
001472f4 ldr     w8, [x9, w8, uxtw #2]
001472f8 ldr     w9, [x0, #0x10]
001472fc sub     w0, w9, w8
00147300 ret     
00147304 ldr     w8, [x0, #0x14]
00147308 mov     x9, #0x6dbb
0014730c ldr     x10, [x0, #0x18]
00147310 mov     x11, #0x1968
00147314 ldr     w12, [x0]
00147318 movk    x9, #0xc058, lsl #16
0014731c sub     w8, w8, #1
00147320 movk    x11, #0x5932, lsl #16
00147324 mov     x14, #0x7801
00147328 mov     x15, #0x754
0014732c movk    x9, #0xf56d, lsl #32
00147330 movk    x11, #0x8339, lsl #32
00147334 ldr     w8, [x10, w8, uxtw #2]
00147338 movk    x14, #0xa06d, lsl #16
0014733c movk    x15, #0xa078, lsl #16
==== 0x147100 0x1472a0
00147100 ldp     x20, x19, [sp, #0x70]
00147104 ldp     x22, x21, [sp, #0x60]
00147108 ldp     x24, x23, [sp, #0x50]
0014710c ldp     x26, x25, [sp, #0x40]
00147110 ldp     x28, x27, [sp, #0x30]
00147114 ldp     x29, x30, [sp, #0x20]
00147118 add     sp, sp, #0x80
0014711c ret     
00147120 stp     x29, x30, [sp, #-0x30]!
00147124 str     x21, [sp, #0x10]
00147128 stp     x20, x19, [sp, #0x20]
0014712c mov     x29, sp
00147130 ldr     w8, [x1, #0x14]
00147134 mov     x19, x1
00147138 mov     x20, x0
0014713c mov     x21, #0x8d87
00147140 ldr     x0, [x1, #0x18]
00147144 movk    x21, #0xa2f3, lsl #16
00147148 add     w8, w8, #1
0014714c movk    x21, #0x8648, lsl #32
00147150 ubfiz   x1, x8, #2, #0x20
00147154 movk    x21, #0xa5e3, lsl #48
00147158 bl      #0x148c80
0014715c mov     x8, #0x865
00147160 mov     x9, #0xcdf8
00147164 movk    x8, #0x5362, lsl #16
00147168 movk    x9, #0xd72b, lsl #16
0014716c mov     x10, #0xc2a2
00147170 mov     x13, #0xc2a2
00147174 movk    x8, #0x98ea, lsl #32
00147178 movk    x9, #0x55aa, lsl #32
0014717c movk    x10, #0x1048, lsl #16
00147180 movk    x13, #0x1048, lsl #16
00147184 movk    x8, #0xabfd, lsl #48
00147188 movk    x9, #0xfe6b, lsl #48
0014718c cmp     x0, #0
00147190 movk    x10, #0x7104, lsl #32
00147194 movk    x13, #0x7104, lsl #32
00147198 movk    x10, #0x9ffe, lsl #48
0014719c csel    x11, x9, x8, eq
001471a0 mov     w12, #2
001471a4 movk    x13, #0x9ffe, lsl #48
001471a8 cmp     x13, x10
001471ac b.eq    #0x1471e0
001471b0 cmp     x13, x21
001471b4 b.eq    #0x147210
001471b8 cmp     x13, x8
001471bc b.eq    #0x1471e8
001471c0 cmp     x13, x9
001471c4 b.ne    #0x1471a8
001471c8 mov     x13, #0x8d87
001471cc str     w12, [x20]
001471d0 movk    x13, #0xa2f3, lsl #16
001471d4 movk    x13, #0x8648, lsl #32
001471d8 movk    x13, #0xa5e3, lsl #48
001471dc b       #0x1471a8
001471e0 mov     x13, x11
001471e4 b       #0x1471a8
001471e8 ldp     w15, w14, [x19, #0x10]
001471ec mov     x13, #0x8d87
001471f0 str     x0, [x19, #0x18]
001471f4 movk    x13, #0xa2f3, lsl #16
001471f8 movk    x13, #0x8648, lsl #32
001471fc add     w16, w14, #1
00147200 movk    x13, #0xa5e3, lsl #48
00147204 str     w15, [x0, x14, lsl #2]
00147208 str     w16, [x19, #0x14]
0014720c b       #0x1471a8
00147210 ldp     x20, x19, [sp, #0x20]
00147214 ldr     x21, [sp, #0x10]
00147218 ldp     x29, x30, [sp], #0x30
0014721c ret     
00147220 ldr     w12, [x1, #0x14]
00147224 mov     x9, #0x92
00147228 mov     x10, #0xcd53
0014722c mov     x8, #0x1471
00147230 movk    x9, #0x16d6, lsl #16
00147234 movk    x10, #0xade6, lsl #16
00147238 mov     x11, #0xea12
0014723c mov     x15, #0xea12
00147240 movk    x8, #0x4a0, lsl #16
00147244 movk    x9, #0x9d06, lsl #32
00147248 movk    x10, #0xefff, lsl #32
0014724c movk    x11, #0x2ac8, lsl #16
00147250 movk    x15, #0x2ac8, lsl #16
00147254 movk    x8, #0x5fd, lsl #32
00147258 movk    x9, #0x2680, lsl #48
0014725c movk    x10, #0x13d4, lsl #48
00147260 movk    x11, #0x1d60, lsl #32
00147264 cmp     w12, #0
00147268 movk    x15, #0x1d60, lsl #32
0014726c movk    x8, #0xa11a, lsl #48
00147270 movk    x11, #0x1023, lsl #48
00147274 sub     w12, w12, #1
00147278 csel    x13, x10, x9, eq
0014727c mov     w14, #7
00147280 movk    x15, #0x1023, lsl #48
00147284 cmp     x15, x8
00147288 b.eq    #0x1472e4
0014728c cmp     x15, x11
00147290 b.eq    #0x1472bc
00147294 cmp     x15, x9
00147298 b.eq    #0x1472c4
0014729c cmp     x15, x10
==== 0x147600 0x147b00
00147600 movk    x13, #0xee0c, lsl #32
00147604 movk    x13, #0x5c23, lsl #48
00147608 b       #0x1475c0
0014760c mov     x13, x11
00147610 b       #0x1475c0
00147614 ldp     x20, x19, [sp, #0x10]
00147618 ldp     x29, x30, [sp], #0x20
0014761c ret     
00147620 ldr     w8, [x0]
00147624 cmp     w8, #0
00147628 cset    w0, eq
0014762c ret     
00147630 stp     x29, x30, [sp, #-0x30]!
00147634 stp     x22, x21, [sp, #0x10]
00147638 stp     x20, x19, [sp, #0x20]
0014763c mov     x29, sp
00147640 mov     x20, x1
00147644 mov     x21, x0
00147648 mov     x22, #0xdf4a
0014764c mov     w0, #1
00147650 mov     w1, #0x10
00147654 movk    x22, #0xbdc8, lsl #16
00147658 movk    x22, #0xceb, lsl #32
0014765c mov     w19, w2
00147660 movk    x22, #0xc8d5, lsl #48
00147664 bl      #0x148b90
00147668 mov     x8, #0xb7cc
0014766c mov     x9, #0xc335
00147670 movk    x8, #0xff64, lsl #16
00147674 movk    x9, #0x1484, lsl #16
00147678 mov     x10, #0x9a1f
0014767c mov     x13, #0x9a1f
00147680 movk    x8, #0xf23e, lsl #32
00147684 movk    x9, #0x16b3, lsl #32
00147688 movk    x10, #0xd6a5, lsl #16
0014768c movk    x13, #0xd6a5, lsl #16
00147690 movk    x8, #0x8f3d, lsl #48
00147694 movk    x9, #0xb3cc, lsl #48
00147698 cmp     x0, #0
0014769c movk    x10, #0xc885, lsl #32
001476a0 movk    x13, #0xc885, lsl #32
001476a4 movk    x10, #0xf611, lsl #48
001476a8 csel    x11, x9, x8, eq
001476ac mov     w12, #2
001476b0 movk    x13, #0xf611, lsl #48
001476b4 cmp     x13, x8
001476b8 b.eq    #0x1476ec
001476bc cmp     x13, x10
001476c0 b.eq    #0x14771c
001476c4 cmp     x13, x22
001476c8 b.eq    #0x147724
001476cc cmp     x13, x9
001476d0 b.ne    #0x1476b4
001476d4 mov     x13, #0xdf4a
001476d8 str     w12, [x21]
001476dc movk    x13, #0xbdc8, lsl #16
001476e0 movk    x13, #0xceb, lsl #32
001476e4 movk    x13, #0xc8d5, lsl #48
001476e8 b       #0x1476b4
001476ec ldr     w13, [x20]
001476f0 str     w19, [x0]
001476f4 ldr     x14, [x20, #8]
001476f8 str     x0, [x20, #8]
001476fc add     w15, w13, #1
00147700 mov     x13, #0xdf4a
00147704 movk    x13, #0xbdc8, lsl #16
00147708 str     x14, [x0, #8]
0014770c movk    x13, #0xceb, lsl #32
00147710 movk    x13, #0xc8d5, lsl #48
00147714 str     w15, [x20]
00147718 b       #0x1476b4
0014771c mov     x13, x11
00147720 b       #0x1476b4
00147724 ldp     x20, x19, [sp, #0x20]
00147728 ldp     x22, x21, [sp, #0x10]
0014772c ldp     x29, x30, [sp], #0x30
00147730 ret     
00147734 stp     x29, x30, [sp, #-0x60]!
00147738 stp     x28, x27, [sp, #0x10]
0014773c stp     x26, x25, [sp, #0x20]
00147740 stp     x24, x23, [sp, #0x30]
00147744 stp     x22, x21, [sp, #0x40]
00147748 stp     x20, x19, [sp, #0x50]
0014774c mov     x29, sp
00147750 ldr     w8, [x1]
00147754 mov     x22, #0x7811
00147758 mov     x23, #0x8779
0014775c movk    x22, #0x740, lsl #16
00147760 movk    x23, #0xf1b8, lsl #16
00147764 mov     x24, #0x28cc
00147768 mov     x25, #0xee15
0014776c cmp     w8, #0
00147770 sub     w26, w8, #1
00147774 mov     x8, #0x28cc
00147778 movk    x22, #0x67ad, lsl #32
0014777c movk    x23, #0x3378, lsl #32
00147780 movk    x24, #0xc3e2, lsl #16
00147784 movk    x25, #0x1fe1, lsl #16
00147788 movk    x8, #0xc3e2, lsl #16
0014778c movk    x22, #0xf79c, lsl #48
00147790 movk    x23, #0xeb0, lsl #48
00147794 movk    x24, #0x7819, lsl #32
00147798 movk    x25, #0x5376, lsl #32
0014779c movk    x8, #0x7819, lsl #32
001477a0 mov     x19, x1
001477a4 mov     x20, x0
001477a8 movk    x24, #0x6b85, lsl #48
001477ac movk    x25, #0x6aa9, lsl #48
001477b0 csel    x27, x23, x22, eq
001477b4 mov     w28, #3
001477b8 movk    x8, #0x6b85, lsl #48
001477bc cmp     x8, x22
001477c0 b.eq    #0x1477f8
001477c4 cmp     x8, x24
001477c8 b.eq    #0x147824
001477cc cmp     x8, x25
001477d0 b.eq    #0x14782c
001477d4 cmp     x8, x23
001477d8 b.ne    #0x1477bc
001477dc mov     x8, #0xee15
001477e0 mov     w21, wzr
001477e4 movk    x8, #0x1fe1, lsl #16
001477e8 str     w28, [x20]
001477ec movk    x8, #0x5376, lsl #32
001477f0 movk    x8, #0x6aa9, lsl #48
001477f4 b       #0x1477bc
001477f8 ldr     x0, [x19, #8]
001477fc str     w26, [x19]
00147800 ldr     x8, [x0, #8]
00147804 ldr     w21, [x0]
00147808 str     x8, [x19, #8]
0014780c bl      #0x148a00
00147810 mov     x8, #0xee15
00147814 movk    x8, #0x1fe1, lsl #16
00147818 movk    x8, #0x5376, lsl #32
0014781c movk    x8, #0x6aa9, lsl #48
00147820 b       #0x1477bc
00147824 mov     x8, x27
00147828 b       #0x1477bc
0014782c mov     w0, w21
00147830 ldp     x20, x19, [sp, #0x50]
00147834 ldp     x22, x21, [sp, #0x40]
00147838 ldp     x24, x23, [sp, #0x30]
0014783c ldp     x26, x25, [sp, #0x20]
00147840 ldp     x28, x27, [sp, #0x10]
00147844 ldp     x29, x30, [sp], #0x60
00147848 ret     
0014784c sub     sp, sp, #0xa0
00147850 stp     x29, x30, [sp, #0x40]
00147854 stp     x28, x27, [sp, #0x50]
00147858 stp     x26, x25, [sp, #0x60]
0014785c stp     x24, x23, [sp, #0x70]
00147860 stp     x22, x21, [sp, #0x80]
00147864 stp     x20, x19, [sp, #0x90]
00147868 add     x29, sp, #0x40
0014786c stur    x1, [x29, #-0x10]
00147870 mov     x24, #0x9bd
00147874 ldr     w8, [x1], #8
00147878 mov     x25, #0xd282
0014787c movk    x24, #0xb5f6, lsl #16
00147880 movk    x25, #0x957d, lsl #16
00147884 movk    x24, #0xce8f, lsl #32
00147888 movk    x25, #0xadd, lsl #32
0014788c movk    x24, #0x62d5, lsl #48
00147890 movk    x25, #0x549f, lsl #48
00147894 cmp     w8, w2
00147898 csel    x8, x25, x24, hi
0014789c mov     x22, #0xd05b
001478a0 mov     x26, #0x113f
001478a4 mov     x27, #0x8a0
001478a8 mov     x28, #0x7408
001478ac mov     x19, #0x507b
001478b0 str     x8, [sp, #0x20]
001478b4 mov     x8, #0x113f
001478b8 movk    x22, #0xef20, lsl #16
001478bc movk    x26, #0xceaf, lsl #16
001478c0 movk    x27, #0xbd15, lsl #16
001478c4 movk    x28, #0x4e14, lsl #16
001478c8 movk    x19, #0x2c50, lsl #16
001478cc movk    x8, #0xceaf, lsl #16
001478d0 movk    x22, #0x96cc, lsl #32
001478d4 movk    x26, #0x4fe6, lsl #32
001478d8 movk    x27, #0xb02c, lsl #32
001478dc movk    x28, #0x43cd, lsl #32
001478e0 movk    x19, #0x48ac, lsl #32
001478e4 movk    x8, #0x4fe6, lsl #32
001478e8 mov     x23, x0
001478ec movk    x22, #0x8753, lsl #48
001478f0 movk    x26, #0xe9ff, lsl #48
001478f4 movk    x27, #0x93e7, lsl #48
001478f8 movk    x28, #0x7f74, lsl #48
001478fc movk    x19, #0xc90b, lsl #48
00147900 movk    x8, #0xe9ff, lsl #48
00147904 stur    x1, [x29, #-0x18]
00147908 stur    w2, [x29, #-4]
0014790c add     x20, x21, #8
00147910 add     w14, w12, #1
00147914 cmp     x8, x22
00147918 b.eq    #0x1479f8
0014791c cmp     x8, x27
00147920 b.eq    #0x1479e4
00147924 cmp     x8, x19
00147928 b.eq    #0x147968
0014792c cmp     x8, x26
00147930 b.eq    #0x1479a4
00147934 cmp     x8, x25
00147938 b.eq    #0x1479c8
0014793c cmp     x8, x28
00147940 b.eq    #0x1479ac
00147944 cmp     x8, x24
00147948 b.ne    #0x147914
0014794c mov     x8, #0xd05b
00147950 mov     w9, #4
00147954 movk    x8, #0xef20, lsl #16
00147958 movk    x8, #0x96cc, lsl #32
0014795c movk    x8, #0x8753, lsl #48
00147960 str     w9, [x23]
00147964 b       #0x147914
00147968 ldr     w2, [x21]
0014796c mov     x0, x23
00147970 ldur    x1, [x29, #-0x10]
00147974 str     x10, [sp, #0x10]
00147978 str     w12, [sp, #0x1c]
0014797c str     w14, [sp, #0xc]
00147980 bl      #0x147630
00147984 mov     x8, #0xd05b
00147988 ldr     w14, [sp, #0xc]
0014798c ldr     w12, [sp, #0x1c]
00147990 movk    x8, #0xef20, lsl #16
00147994 ldr     x10, [sp, #0x10]
00147998 movk    x8, #0x96cc, lsl #32
0014799c movk    x8, #0x8753, lsl #48
001479a0 b       #0x147914
001479a4 ldr     x8, [sp, #0x20]
001479a8 b       #0x147914
001479ac mov     x8, #0x8a0
001479b0 mov     x10, x20
001479b4 movk    x8, #0xbd15, lsl #16
001479b8 mov     w12, w14
001479bc movk    x8, #0xb02c, lsl #32
001479c0 movk    x8, #0x93e7, lsl #48
001479c4 b       #0x147914
001479c8 mov     x8, #0x8a0
001479cc ldur    x10, [x29, #-0x18]
001479d0 movk    x8, #0xbd15, lsl #16
001479d4 mov     w12, wzr
001479d8 movk    x8, #0xb02c, lsl #32
001479dc movk    x8, #0x93e7, lsl #48
001479e0 b       #0x147914
001479e4 ldur    w8, [x29, #-4]
001479e8 ldr     x21, [x10]
001479ec cmp     w12, w8
001479f0 csel    x8, x19, x28, eq
001479f4 b       #0x14790c
001479f8 ldp     x20, x19, [sp, #0x90]
001479fc ldp     x22, x21, [sp, #0x80]
00147a00 ldp     x24, x23, [sp, #0x70]
00147a04 ldp     x26, x25, [sp, #0x60]
00147a08 ldp     x28, x27, [sp, #0x50]
00147a0c ldp     x29, x30, [sp, #0x40]
00147a10 add     sp, sp, #0xa0
00147a14 ret     
00147a18 mov     w2, wzr
00147a1c b       #0x14784c
00147a20 str     x21, [sp, #-0x20]!
00147a24 stp     x20, x19, [sp, #0x10]
00147a28 ldr     w14, [x1]
00147a2c mov     x10, #0x1dac
00147a30 mov     x11, #0x5cb8
00147a34 mov     x8, #0x25ce
00147a38 mov     x9, #0xb031
00147a3c movk    x10, #0x9f5e, lsl #16
00147a40 movk    x11, #0x2795, lsl #16
00147a44 mov     x12, #0x1859
00147a48 mov     x13, #0x4c0d
00147a4c cmp     w14, w2
00147a50 mov     x14, #0x6436
00147a54 mov     x19, #0x1859
00147a58 movk    x8, #0x8c3e, lsl #16
00147a5c movk    x9, #0x9cc1, lsl #16
00147a60 movk    x10, #0xb762, lsl #32
00147a64 movk    x11, #0x15f4, lsl #32
00147a68 movk    x12, #0x2b53, lsl #16
00147a6c movk    x13, #0x52dd, lsl #16
00147a70 movk    x14, #0x2869, lsl #16
00147a74 movk    x19, #0x2b53, lsl #16
00147a78 movk    x8, #0xdec2, lsl #32
00147a7c movk    x9, #0xffeb, lsl #32
00147a80 movk    x10, #0x3b4a, lsl #48
00147a84 movk    x11, #0x77a4, lsl #48
00147a88 movk    x12, #0x6ffc, lsl #32
00147a8c movk    x13, #0x7dcf, lsl #32
00147a90 movk    x14, #0xc5df, lsl #32
00147a94 movk    x19, #0x6ffc, lsl #32
00147a98 movk    x8, #0xf201, lsl #48
00147a9c movk    x9, #0x2516, lsl #48
00147aa0 movk    x12, #0x930b, lsl #48
00147aa4 movk    x13, #0x48fe, lsl #48
00147aa8 movk    x14, #0x56de, lsl #48
00147aac csel    x15, x11, x10, hi
00147ab0 mov     w16, #4
00147ab4 movk    x19, #0x930b, lsl #48
00147ab8 mov     w7, wzr
00147abc mov     x6, x17
00147ac0 add     w20, w5, #1
00147ac4 cmp     x19, x12
00147ac8 b.eq    #0x147b14
00147acc cmp     x19, x8
00147ad0 b.eq    #0x147b58
00147ad4 cmp     x19, x9
00147ad8 b.eq    #0x147b88
00147adc cmp     x19, x11
00147ae0 b.eq    #0x147b6c
00147ae4 cmp     x19, x13
00147ae8 b.eq    #0x147b1c
00147aec cmp     x19, x14
00147af0 b.eq    #0x147b38
00147af4 cmp     x19, x10
00147af8 b.ne    #0x147ac4
00147afc mov     x19, #0xb031
==== 0x148b00 0x148d60
00148b00 adrp    x16, #0x14d000
00148b04 ldr     x17, [x16, #0xa70]
00148b08 add     x16, x16, #0xa70
00148b0c br      x17
00148b10 adrp    x16, #0x14d000
00148b14 ldr     x17, [x16, #0xa78]
00148b18 add     x16, x16, #0xa78
00148b1c br      x17
00148b20 adrp    x16, #0x14d000
00148b24 ldr     x17, [x16, #0xa80]
00148b28 add     x16, x16, #0xa80
00148b2c br      x17
00148b30 adrp    x16, #0x14d000
00148b34 ldr     x17, [x16, #0xa88]
00148b38 add     x16, x16, #0xa88
00148b3c br      x17
00148b40 adrp    x16, #0x14d000
00148b44 ldr     x17, [x16, #0xa90]
00148b48 add     x16, x16, #0xa90
00148b4c br      x17
00148b50 adrp    x16, #0x14d000
00148b54 ldr     x17, [x16, #0xa98]
00148b58 add     x16, x16, #0xa98
00148b5c br      x17
00148b60 adrp    x16, #0x14d000
00148b64 ldr     x17, [x16, #0xaa0]
00148b68 add     x16, x16, #0xaa0
00148b6c br      x17
00148b70 adrp    x16, #0x14d000
00148b74 ldr     x17, [x16, #0xaa8]
00148b78 add     x16, x16, #0xaa8
00148b7c br      x17
00148b80 adrp    x16, #0x14d000
00148b84 ldr     x17, [x16, #0xab0]
00148b88 add     x16, x16, #0xab0
00148b8c br      x17
00148b90 adrp    x16, #0x14d000
00148b94 ldr     x17, [x16, #0xab8]
00148b98 add     x16, x16, #0xab8
00148b9c br      x17
00148ba0 adrp    x16, #0x14d000
00148ba4 ldr     x17, [x16, #0xac0]
00148ba8 add     x16, x16, #0xac0
00148bac br      x17
00148bb0 adrp    x16, #0x14d000
00148bb4 ldr     x17, [x16, #0xac8]
00148bb8 add     x16, x16, #0xac8
00148bbc br      x17
00148bc0 adrp    x16, #0x14d000
00148bc4 ldr     x17, [x16, #0xad0]
00148bc8 add     x16, x16, #0xad0
00148bcc br      x17
00148bd0 adrp    x16, #0x14d000
00148bd4 ldr     x17, [x16, #0xad8]
00148bd8 add     x16, x16, #0xad8
00148bdc br      x17
00148be0 adrp    x16, #0x14d000
00148be4 ldr     x17, [x16, #0xae0]
00148be8 add     x16, x16, #0xae0
00148bec br      x17
00148bf0 adrp    x16, #0x14d000
00148bf4 ldr     x17, [x16, #0xae8]
00148bf8 add     x16, x16, #0xae8
00148bfc br      x17
00148c00 adrp    x16, #0x14d000
00148c04 ldr     x17, [x16, #0xaf0]
00148c08 add     x16, x16, #0xaf0
00148c0c br      x17
00148c10 adrp    x16, #0x14d000
00148c14 ldr     x17, [x16, #0xaf8]
00148c18 add     x16, x16, #0xaf8
00148c1c br      x17
00148c20 adrp    x16, #0x14d000
00148c24 ldr     x17, [x16, #0xb00]
00148c28 add     x16, x16, #0xb00
00148c2c br      x17
00148c30 adrp    x16, #0x14d000
00148c34 ldr     x17, [x16, #0xb08]
00148c38 add     x16, x16, #0xb08
00148c3c br      x17
00148c40 adrp    x16, #0x14d000
00148c44 ldr     x17, [x16, #0xb10]
00148c48 add     x16, x16, #0xb10
00148c4c br      x17
00148c50 adrp    x16, #0x14d000
00148c54 ldr     x17, [x16, #0xb18]
00148c58 add     x16, x16, #0xb18
00148c5c br      x17
00148c60 adrp    x16, #0x14d000
00148c64 ldr     x17, [x16, #0xb20]
00148c68 add     x16, x16, #0xb20
00148c6c br      x17
00148c70 adrp    x16, #0x14d000
00148c74 ldr     x17, [x16, #0xb28]
00148c78 add     x16, x16, #0xb28
00148c7c br      x17
00148c80 adrp    x16, #0x14d000
00148c84 ldr     x17, [x16, #0xb30]
00148c88 add     x16, x16, #0xb30
00148c8c br      x17
00148c90 adrp    x16, #0x14d000
00148c94 ldr     x17, [x16, #0xb38]
00148c98 add     x16, x16, #0xb38
00148c9c br      x17
00148ca0 adrp    x16, #0x14d000
00148ca4 ldr     x17, [x16, #0xb40]
00148ca8 add     x16, x16, #0xb40
00148cac br      x17
00148cb0 adrp    x16, #0x14d000
00148cb4 ldr     x17, [x16, #0xb48]
00148cb8 add     x16, x16, #0xb48
00148cbc br      x17
00148cc0 adrp    x16, #0x14d000
00148cc4 ldr     x17, [x16, #0xb50]
00148cc8 add     x16, x16, #0xb50
00148ccc br      x17
00148cd0 adrp    x16, #0x14d000
00148cd4 ldr     x17, [x16, #0xb58]
00148cd8 add     x16, x16, #0xb58
00148cdc br      x17
00148ce0 adrp    x16, #0x14d000
00148ce4 ldr     x17, [x16, #0xb60]
00148ce8 add     x16, x16, #0xb60
00148cec br      x17
00148cf0 adrp    x16, #0x14d000
00148cf4 ldr     x17, [x16, #0xb68]
00148cf8 add     x16, x16, #0xb68
00148cfc br      x17
00148d00 adrp    x16, #0x14d000
00148d04 ldr     x17, [x16, #0xb70]
00148d08 add     x16, x16, #0xb70
00148d0c br      x17
00148d10 adrp    x16, #0x14d000
00148d14 ldr     x17, [x16, #0xb78]
00148d18 add     x16, x16, #0xb78
00148d1c br      x17
00148d20 adrp    x16, #0x14d000
00148d24 ldr     x17, [x16, #0xb80]
00148d28 add     x16, x16, #0xb80
00148d2c br      x17
00148d30 adrp    x16, #0x14d000
00148d34 ldr     x17, [x16, #0xb88]
00148d38 add     x16, x16, #0xb88
00148d3c br      x17
00148d40 adrp    x16, #0x14d000
00148d44 ldr     x17, [x16, #0xb90]
00148d48 add     x16, x16, #0xb90
00148d4c br      x17
00148d50 adrp    x16, #0x14d000
00148d54 ldr     x17, [x16, #0xb98]
00148d58 add     x16, x16, #0xb98
00148d5c br      x17
