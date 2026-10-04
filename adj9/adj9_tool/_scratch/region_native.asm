==== 0x143800 0x144600
00143800 stp     x22, x21, [sp, #0xa0]
00143804 stp     x20, x19, [sp, #0xb0]
00143808 add     x29, sp, #0x60
0014380c mrs     x8, tpidr_el0
00143810 add     x19, x0, #8
00143814 str     x8, [sp]
00143818 mov     x25, #0xdf4a
0014381c ldr     x8, [x8, #0x28]
00143820 mov     x26, #0xb7cc
00143824 mov     x9, x0
00143828 stur    x0, [x29, #-0x20]
0014382c mov     x0, x19
00143830 movk    x25, #0xbdc8, lsl #16
00143834 movk    x26, #0xff64, lsl #16
00143838 movk    x25, #0xceb, lsl #32
0014383c movk    x26, #0xf23e, lsl #32
00143840 movk    x25, #0xc8d5, lsl #48
00143844 movk    x26, #0x8f3d, lsl #48
00143848 stur    x8, [x29, #-8]
0014384c str     w1, [x9], #0x10
00143850 str     x9, [sp, #0x10]
00143854 bl      #0x13e030
00143858 sub     x0, x29, #0x18
0014385c mov     x1, x19
00143860 str     x19, [sp, #8]
00143864 bl      #0x143c88
00143868 mov     x28, #0xc335
0014386c mov     x21, #0x9a1f
00143870 mov     x19, #0xa74a
00143874 mov     x9, #0x8e81
00143878 movk    x28, #0x1484, lsl #16
0014387c movk    x21, #0xd6a5, lsl #16
00143880 movk    x19, #0x5ea3, lsl #16
00143884 movk    x9, #0xe154, lsl #16
00143888 movk    x28, #0x16b3, lsl #32
0014388c movk    x21, #0xc885, lsl #32
00143890 movk    x19, #0xa04f, lsl #32
00143894 movk    x9, #0x3b5e, lsl #32
00143898 movk    x28, #0xb3cc, lsl #48
0014389c movk    x21, #0xf611, lsl #48
001438a0 movk    x19, #0xfa1e, lsl #48
001438a4 movk    x9, #0x7cc5, lsl #48
001438a8 str     xzr, [sp, #0x30]
001438ac str     wzr, [sp, #0x2c]
001438b0 stur    xzr, [x29, #-0x28]
001438b4 cmp     x9, x26
001438b8 b.eq    #0x1439c4
001438bc mov     x8, x9
001438c0 cmp     x9, x28
001438c4 b.eq    #0x143970
001438c8 cmp     x8, x25
001438cc b.eq    #0x143994
001438d0 cmp     x8, x21
001438d4 b.eq    #0x143a54
001438d8 cmp     x8, x19
001438dc b.eq    #0x143ab8
001438e0 mov     x9, #0x5dae
001438e4 movk    x9, #0xbd6e, lsl #16
001438e8 movk    x9, #0x6aaa, lsl #32
001438ec movk    x9, #0x28f0, lsl #48
001438f0 cmp     x8, x9
001438f4 b.eq    #0x143a70
001438f8 mov     x9, #0xd2d1
001438fc movk    x9, #0xf825, lsl #16
00143900 movk    x9, #0xee0c, lsl #32
00143904 movk    x9, #0x5c23, lsl #48
00143908 cmp     x8, x9
0014390c b.eq    #0x143aa0
00143910 mov     x9, #0x3581
00143914 movk    x9, #0xbcba, lsl #16
00143918 movk    x9, #0x133, lsl #32
0014391c movk    x9, #0x761f, lsl #48
00143920 cmp     x8, x9
00143924 b.eq    #0x143a28
00143928 mov     x9, #0x5dae
0014392c mov     x10, #0x8e81
00143930 movk    x9, #0xbd6e, lsl #16
00143934 movk    x10, #0xe154, lsl #16
00143938 movk    x9, #0x6aaa, lsl #32
0014393c movk    x10, #0x3b5e, lsl #32
00143940 movk    x9, #0x28f0, lsl #48
00143944 movk    x10, #0x7cc5, lsl #48
00143948 cmp     x8, x10
0014394c b.eq    #0x1438b4
00143950 mov     x10, #0x7515
00143954 mov     x9, x8
00143958 movk    x10, #0xb217, lsl #16
0014395c movk    x10, #0xdfc8, lsl #32
00143960 movk    x10, #0x768a, lsl #48
00143964 cmp     x8, x10
00143968 b.ne    #0x1438b4
0014396c b       #0x143ad8
00143970 ldr     x0, [sp, #8]
00143974 bl      #0x13dfd0
00143978 mov     x9, #0xb7cc
0014397c mov     w23, w0
00143980 movk    x9, #0xff64, lsl #16
00143984 mov     w27, #1
00143988 movk    x9, #0xf23e, lsl #32
0014398c movk    x9, #0x8f3d, lsl #48
00143990 b       #0x1438b4
00143994 mov     x8, #0x3581
00143998 mov     x9, #0x7515
0014399c movk    x8, #0xbcba, lsl #16
001439a0 movk    x9, #0xb217, lsl #16
001439a4 movk    x8, #0x133, lsl #32
001439a8 movk    x9, #0xdfc8, lsl #32
001439ac cmp     x22, #0x48
001439b0 movk    x8, #0x761f, lsl #48
001439b4 movk    x9, #0x768a, lsl #48
001439b8 mov     x24, x22
001439bc csel    x9, x9, x8, eq
001439c0 b       #0x1438b4
001439c4 sub     x8, x29, #0x18
001439c8 mov     w9, #0xf
001439cc ldr     w10, [sp, #0x28]
001439d0 str     x27, [sp, #0x30]
001439d4 ldrb    w8, [x8, x20]
001439d8 str     w23, [sp, #0x2c]
001439dc tst     w10, #1
001439e0 mov     w10, #1
001439e4 sub     w8, w9, w8
001439e8 lsr     w9, w23, #0x10
001439ec csel    w9, w9, w23, ne
001439f0 lsl     w8, w10, w8
001439f4 sub     w10, w8, #1
001439f8 and     w9, w10, w9
001439fc ldur    x10, [x29, #-0x20]
00143a00 orr     w8, w9, w8
00143a04 add     x9, x20, #1
00143a08 add     x10, x10, x20, lsl #1
00143a0c stur    x9, [x29, #-0x28]
00143a10 mov     x9, #0x5dae
00143a14 movk    x9, #0xbd6e, lsl #16
00143a18 movk    x9, #0x6aaa, lsl #32
00143a1c strh    w8, [x10, #0x10]
00143a20 movk    x9, #0x28f0, lsl #48
00143a24 b       #0x1438b4
00143a28 mov     w1, #0x40
00143a2c ldur    x0, [x29, #-0x20]
00143a30 bfxil   w1, w24, #0, #3
00143a34 mov     x2, x24
00143a38 bl      #0x144074
00143a3c mov     x9, #0xdf4a
00143a40 add     x22, x24, #1
00143a44 movk    x9, #0xbdc8, lsl #16
00143a48 movk    x9, #0xceb, lsl #32
00143a4c movk    x9, #0xc8d5, lsl #48
00143a50 b       #0x1438b4
00143a54 mov     x9, #0xb7cc
00143a58 ldr     w23, [sp, #0x24]
00143a5c movk    x9, #0xff64, lsl #16
00143a60 mov     x27, xzr
00143a64 movk    x9, #0xf23e, lsl #32
00143a68 movk    x9, #0x8f3d, lsl #48
00143a6c b       #0x1438b4
00143a70 ldur    x20, [x29, #-0x28]
00143a74 mov     x8, #0xd2d1
00143a78 movk    x8, #0xf825, lsl #16
00143a7c movk    x8, #0xee0c, lsl #32
00143a80 cmp     x20, #0x10
00143a84 movk    x8, #0x5c23, lsl #48
00143a88 csel    x9, x19, x8, eq
00143a8c ldr     w8, [sp, #0x2c]
00143a90 str     w8, [sp, #0x24]
00143a94 ldr     x8, [sp, #0x30]
00143a98 str     x8, [sp, #0x18]
00143a9c b       #0x1438b4
00143aa0 ldr     x8, [sp, #0x18]
00143aa4 cmp     x8, #0
00143aa8 cset    w8, eq
00143aac csel    x9, x28, x21, eq
00143ab0 str     w8, [sp, #0x28]
00143ab4 b       #0x1438b4
00143ab8 ldr     x0, [sp, #0x10]
00143abc bl      #0x143d98
00143ac0 mov     x9, #0xdf4a
00143ac4 mov     x22, xzr
00143ac8 movk    x9, #0xbdc8, lsl #16
00143acc movk    x9, #0xceb, lsl #32
00143ad0 movk    x9, #0xc8d5, lsl #48
00143ad4 b       #0x1438b4
00143ad8 ldr     x8, [sp]
00143adc ldr     x8, [x8, #0x28]
00143ae0 ldur    x9, [x29, #-8]
00143ae4 cmp     x8, x9
00143ae8 b.ne    #0x143b1c
00143aec ldur    x9, [x29, #-0x20]
00143af0 ldp     x20, x19, [sp, #0xb0]
00143af4 add     x8, x9, #0x30
00143af8 ldp     x22, x21, [sp, #0xa0]
00143afc ldp     x24, x23, [sp, #0x90]
00143b00 ldp     x26, x25, [sp, #0x80]
00143b04 ldp     x28, x27, [sp, #0x70]
00143b08 ldp     x29, x30, [sp, #0x60]
00143b0c ldr     q0, [x8]
00143b10 str     q0, [x9, #0xc0]!
00143b14 add     sp, sp, #0xc0
00143b18 ret     
00143b1c bl      #0x148a10
00143b20 mov     x9, #0x2f9c
00143b24 mov     x11, #0xafb5
00143b28 mov     x12, #0x7811
00143b2c mov     x13, #0xee15
00143b30 mov     x14, #0x28cc
00143b34 mov     x15, #0x113f
00143b38 mov     x16, #0x8779
00143b3c mov     x2, #0x2f9c
00143b40 movk    x9, #0xc396, lsl #16
00143b44 movk    x11, #0xa12b, lsl #16
00143b48 movk    x12, #0x740, lsl #16
00143b4c movk    x13, #0x1fe1, lsl #16
00143b50 movk    x14, #0xc3e2, lsl #16
00143b54 movk    x15, #0xceaf, lsl #16
00143b58 movk    x16, #0xf1b8, lsl #16
00143b5c movk    x2, #0xc396, lsl #16
00143b60 movk    x9, #0x5e8f, lsl #32
00143b64 movk    x11, #0xce93, lsl #32
00143b68 movk    x12, #0x67ad, lsl #32
00143b6c movk    x13, #0x5376, lsl #32
00143b70 movk    x14, #0x7819, lsl #32
00143b74 movk    x15, #0x4fe6, lsl #32
00143b78 movk    x16, #0x3378, lsl #32
00143b7c movk    x2, #0x5e8f, lsl #32
00143b80 mov     x10, xzr
00143b84 movk    x9, #0xf2cd, lsl #48
00143b88 movk    x11, #0xb225, lsl #48
00143b8c movk    x12, #0xf79c, lsl #48
00143b90 movk    x13, #0x6aa9, lsl #48
00143b94 movk    x14, #0x6b85, lsl #48
00143b98 movk    x15, #0xe9ff, lsl #48
00143b9c movk    x16, #0xeb0, lsl #48
00143ba0 movk    x2, #0xf2cd, lsl #48
00143ba4 and     x3, x10, #7
00143ba8 add     x4, x0, x10, lsl #1
00143bac add     x5, x0, x3, lsl #1
00143bb0 add     x3, x4, #0x30
00143bb4 add     x4, x5, #0xc0
00143bb8 add     x5, x17, #1
00143bbc cmp     x5, #0x48
00143bc0 csel    x6, x13, x12, eq
00143bc4 cmp     x2, x14
00143bc8 b.eq    #0x143c20
00143bcc cmp     x2, x15
00143bd0 b.eq    #0x143c80
00143bd4 cmp     x2, x9
00143bd8 b.eq    #0x143c00
00143bdc cmp     x2, x12
00143be0 b.eq    #0x143c68
00143be4 cmp     x2, x16
00143be8 b.eq    #0x143c14
00143bec cmp     x2, x13
00143bf0 b.eq    #0x143c38
00143bf4 cmp     x2, x11
00143bf8 b.ne    #0x143bc4
00143bfc b       #0x143c50
00143c00 mov     x2, #0xafb5
00143c04 movk    x2, #0xa12b, lsl #16
00143c08 movk    x2, #0xce93, lsl #32
00143c0c movk    x2, #0xb225, lsl #48
00143c10 b       #0x143bc4
00143c14 mov     x1, x5
00143c18 mov     x2, x6
00143c1c b       #0x143bc4
00143c20 mov     x2, #0x113f
00143c24 mov     x8, x17
00143c28 movk    x2, #0xceaf, lsl #16
00143c2c movk    x2, #0x4fe6, lsl #32
00143c30 movk    x2, #0xe9ff, lsl #48
00143c34 b       #0x143bb8
00143c38 mov     x2, #0x113f
00143c3c mov     w8, #0x48
00143c40 movk    x2, #0xceaf, lsl #16
00143c44 movk    x2, #0x4fe6, lsl #32
00143c48 movk    x2, #0xe9ff, lsl #48
00143c4c b       #0x143bb8
00143c50 ldrh    w17, [x3]
00143c54 ldrh    w2, [x4]
00143c58 cmp     w17, w2
00143c5c mov     x17, x10
00143c60 csel    x2, x14, x16, eq
00143c64 b       #0x143bb8
00143c68 mov     x2, #0xafb5
00143c6c mov     x10, x1
00143c70 movk    x2, #0xa12b, lsl #16
00143c74 movk    x2, #0xce93, lsl #32
00143c78 movk    x2, #0xb225, lsl #48
00143c7c b       #0x143ba4
00143c80 mov     x0, x8
00143c84 ret     
00143c88 stp     x29, x30, [sp, #-0x50]!
00143c8c stp     x26, x25, [sp, #0x10]
00143c90 stp     x24, x23, [sp, #0x20]
00143c94 stp     x22, x21, [sp, #0x30]
00143c98 stp     x20, x19, [sp, #0x40]
00143c9c mov     x29, sp
00143ca0 mov     x21, #0xd282
00143ca4 mov     x22, #0x9bd
00143ca8 mov     x23, #0x8a0
00143cac mov     x24, #0x507b
00143cb0 mov     x9, #0x9bd
00143cb4 movk    x21, #0x957d, lsl #16
00143cb8 movk    x22, #0xb5f6, lsl #16
00143cbc movk    x23, #0xbd15, lsl #16
00143cc0 movk    x24, #0x2c50, lsl #16
00143cc4 movk    x9, #0xb5f6, lsl #16
00143cc8 movk    x21, #0xadd, lsl #32
00143ccc movk    x22, #0xce8f, lsl #32
00143cd0 movk    x23, #0xb02c, lsl #32
00143cd4 movk    x24, #0x48ac, lsl #32
00143cd8 movk    x9, #0xce8f, lsl #32
00143cdc mov     x19, x1
00143ce0 mov     x20, x0
00143ce4 mov     x8, xzr
00143ce8 movk    x21, #0x549f, lsl #48
00143cec movk    x22, #0x62d5, lsl #48
00143cf0 movk    x23, #0x93e7, lsl #48
00143cf4 movk    x24, #0xc90b, lsl #48
00143cf8 movk    x9, #0x62d5, lsl #48
00143cfc stp     xzr, xzr, [x0]
00143d00 add     x26, x25, #1
00143d04 cmp     x9, x23
00143d08 b.eq    #0x143d80
00143d0c cmp     x9, x24
00143d10 b.eq    #0x143d28
00143d14 cmp     x9, x22
00143d18 b.eq    #0x143d5c
00143d1c cmp     x9, x21
00143d20 b.ne    #0x143d04
00143d24 b       #0x143d70
00143d28 mov     x0, x19
00143d2c bl      #0x13dfd0
00143d30 udiv    w8, w0, w26
00143d34 mov     x9, #0xd282
00143d38 movk    x9, #0x957d, lsl #16
00143d3c movk    x9, #0xadd, lsl #32
00143d40 movk    x9, #0x549f, lsl #48
00143d44 msub    w10, w8, w26, w0
00143d48 mov     x8, x26
00143d4c ldrb    w11, [x20, w10, uxtw]
00143d50 strb    w11, [x20, x25]
00143d54 strb    w25, [x20, w10, uxtw]
00143d58 b       #0x143d04
00143d5c mov     x9, #0xd282
00143d60 movk    x9, #0x957d, lsl #16
00143d64 movk    x9, #0xadd, lsl #32
00143d68 movk    x9, #0x549f, lsl #48
00143d6c b       #0x143d04
00143d70 cmp     x8, #0x10
00143d74 mov     x25, x8
00143d78 csel    x9, x23, x24, eq
00143d7c b       #0x143d00
00143d80 ldp     x20, x19, [sp, #0x40]
00143d84 ldp     x22, x21, [sp, #0x30]
00143d88 ldp     x24, x23, [sp, #0x20]
00143d8c ldp     x26, x25, [sp, #0x10]
00143d90 ldp     x29, x30, [sp], #0x50
00143d94 ret     
00143d98 sub     sp, sp, #0x90
00143d9c stp     x29, x30, [sp, #0x30]
00143da0 stp     x28, x27, [sp, #0x40]
00143da4 stp     x26, x25, [sp, #0x50]
00143da8 stp     x24, x23, [sp, #0x60]
00143dac stp     x22, x21, [sp, #0x70]
00143db0 stp     x20, x19, [sp, #0x80]
00143db4 add     x29, sp, #0x30
00143db8 mrs     x8, tpidr_el0
00143dbc mov     x10, #0x1381
00143dc0 ldr     x14, [x8, #0x28]
00143dc4 mov     x11, #0xd05b
00143dc8 mov     x12, #0x5cb8
00143dcc mov     x13, #0xb3d0
00143dd0 mov     x15, #0x1dac
00143dd4 mov     x16, #0x1859
00143dd8 stur    x14, [x29, #-8]
00143ddc mov     x14, #0x7408
00143de0 mov     x17, #0xc2a2
00143de4 mov     x2, #0xe386
00143de8 mov     x3, #0x25ce
00143dec mov     x4, #0xb031
00143df0 mov     x7, #0x4c0d
00143df4 mov     x19, #0x6436
00143df8 mov     x28, #0x7408
00143dfc movk    x10, #0xa58a, lsl #16
00143e00 movk    x11, #0xef20, lsl #16
00143e04 movk    x12, #0x2795, lsl #16
00143e08 movk    x13, #0x566, lsl #16
00143e0c movk    x14, #0x4e14, lsl #16
00143e10 movk    x15, #0x9f5e, lsl #16
00143e14 movk    x16, #0x2b53, lsl #16
00143e18 movk    x17, #0x1048, lsl #16
00143e1c movk    x2, #0xeab8, lsl #16
00143e20 movk    x3, #0x8c3e, lsl #16
00143e24 movk    x4, #0x9cc1, lsl #16
00143e28 movk    x7, #0x52dd, lsl #16
00143e2c movk    x19, #0x2869, lsl #16
00143e30 movk    x28, #0x4e14, lsl #16
00143e34 movk    x10, #0xb763, lsl #32
00143e38 movk    x11, #0x96cc, lsl #32
00143e3c movk    x12, #0x15f4, lsl #32
00143e40 movk    x13, #0xa50d, lsl #32
00143e44 movk    x14, #0x43cd, lsl #32
00143e48 movi    v0.2d, #0000000000000000
00143e4c movk    x15, #0xb762, lsl #32
00143e50 movk    x16, #0x6ffc, lsl #32
00143e54 movk    x17, #0x7104, lsl #32
00143e58 movk    x2, #0xc1ec, lsl #32
00143e5c movk    x3, #0xdec2, lsl #32
00143e60 movk    x4, #0xffeb, lsl #32
00143e64 movk    x7, #0x7dcf, lsl #32
00143e68 movk    x19, #0xc5df, lsl #32
00143e6c movk    x28, #0x43cd, lsl #32
00143e70 mov     x9, xzr
00143e74 movk    x10, #0xbbcd, lsl #48
00143e78 movk    x11, #0x8753, lsl #48
00143e7c movk    x12, #0x77a4, lsl #48
00143e80 movk    x13, #0x204a, lsl #48
00143e84 movk    x14, #0x7f74, lsl #48
00143e88 movk    x15, #0x3b4a, lsl #48
00143e8c movk    x16, #0x930b, lsl #48
00143e90 movk    x17, #0x9ffe, lsl #48
00143e94 mov     x1, sp
00143e98 movk    x2, #0x808f, lsl #48
00143e9c movk    x3, #0xf201, lsl #48
00143ea0 movk    x4, #0x2516, lsl #48
00143ea4 mov     w5, #0xf
00143ea8 mov     w6, #1
00143eac movk    x7, #0x48fe, lsl #48
00143eb0 movk    x19, #0x56de, lsl #48
00143eb4 movk    x28, #0x7f74, lsl #48
00143eb8 stp     q0, q0, [sp]
00143ebc cmp     x28, x11
00143ec0 b.eq    #0x143fec
00143ec4 mov     x27, x28
00143ec8 cmp     x28, x16
00143ecc b.eq    #0x144028
00143ed0 cmp     x27, x17
00143ed4 b.eq    #0x143f50
00143ed8 cmp     x27, x10
00143edc b.eq    #0x143f70
00143ee0 cmp     x27, x3
00143ee4 b.eq    #0x143ffc
00143ee8 cmp     x27, x13
00143eec b.eq    #0x143f80
00143ef0 cmp     x27, x4
00143ef4 b.eq    #0x143fcc
00143ef8 cmp     x27, x15
00143efc b.eq    #0x143fa8
00143f00 mov     x28, #0xb3d0
00143f04 cmp     x27, x7
00143f08 movk    x28, #0x566, lsl #16
00143f0c movk    x28, #0xa50d, lsl #32
00143f10 movk    x28, #0x204a, lsl #48
00143f14 b.eq    #0x143ebc
00143f18 cmp     x27, x19
00143f1c b.eq    #0x144014
00143f20 cmp     x27, x12
00143f24 b.eq    #0x143f98
00143f28 mov     x28, #0xd05b
00143f2c cmp     x27, x14
00143f30 movk    x28, #0xef20, lsl #16
00143f34 movk    x28, #0x96cc, lsl #32
00143f38 movk    x28, #0x8753, lsl #48
00143f3c b.eq    #0x143ebc
00143f40 mov     x28, x27
00143f44 cmp     x27, x2
00143f48 b.ne    #0x143ebc
00143f4c b       #0x144040
00143f50 ldrh    w27, [x1, x26, lsl #1]
00143f54 mov     x28, #0x1381
00143f58 movk    x28, #0xa58a, lsl #16
00143f5c add     x25, x26, #1
00143f60 movk    x28, #0xb763, lsl #32
00143f64 movk    x28, #0xbbcd, lsl #48
00143f68 strh    w27, [x0, x26, lsl #1]
00143f6c b       #0x143ebc
00143f70 cmp     x25, #0x10
00143f74 mov     x26, x25
00143f78 csel    x28, x2, x17, eq
00143f7c b       #0x143ebc
00143f80 mov     x28, #0x5cb8
00143f84 add     x21, x24, #1
00143f88 movk    x28, #0x2795, lsl #16
00143f8c movk    x28, #0x15f4, lsl #32
00143f90 movk    x28, #0x77a4, lsl #48
00143f94 b       #0x143ebc
00143f98 cmp     x21, #0x10
00143f9c mov     x24, x21
00143fa0 csel    x28, x3, x19, eq
00143fa4 b       #0x143ebc
00143fa8 sub     w23, w5, w20
00143fac ldrh    w22, [x0, x20, lsl #1]
00143fb0 mov     x28, #0x5cb8
00143fb4 mov     x21, xzr
00143fb8 movk    x28, #0x2795, lsl #16
00143fbc movk    x28, #0x15f4, lsl #32
00143fc0 lsl     w23, w6, w23
00143fc4 movk    x28, #0x77a4, lsl #48
00143fc8 b       #0x143ebc
00143fcc ldrh    w27, [x1, x24, lsl #1]
00143fd0 mov     x28, #0xb3d0
00143fd4 movk    x28, #0x566, lsl #16
00143fd8 movk    x28, #0xa50d, lsl #32
00143fdc movk    x28, #0x204a, lsl #48
00143fe0 orr     w27, w27, w23
00143fe4 strh    w27, [x1, x24, lsl #1]
00143fe8 b       #0x143ebc
00143fec cmp     x9, #0x10
00143ff0 mov     x20, x9
00143ff4 csel    x28, x16, x15, eq
00143ff8 b       #0x143ebc
00143ffc mov     x28, #0xd05b
00144000 add     x9, x20, #1
00144004 movk    x28, #0xef20, lsl #16
00144008 movk    x28, #0x96cc, lsl #32
0014400c movk    x28, #0x8753, lsl #48
00144010 b       #0x143ebc
00144014 sub     w27, w5, w24
00144018 lsr     w27, w22, w27
0014401c tst     w27, #1
00144020 csel    x28, x7, x4, eq
00144024 b       #0x143ebc
00144028 mov     x28, #0x1381
0014402c mov     x25, xzr
00144030 movk    x28, #0xa58a, lsl #16
00144034 movk    x28, #0xb763, lsl #32
00144038 movk    x28, #0xbbcd, lsl #48
0014403c b       #0x143ebc
00144040 ldr     x8, [x8, #0x28]
00144044 ldur    x9, [x29, #-8]
00144048 cmp     x8, x9
0014404c b.ne    #0x144070
00144050 ldp     x20, x19, [sp, #0x80]
00144054 ldp     x22, x21, [sp, #0x70]
00144058 ldp     x24, x23, [sp, #0x60]
0014405c ldp     x26, x25, [sp, #0x50]
00144060 ldp     x28, x27, [sp, #0x40]
00144064 ldp     x29, x30, [sp, #0x30]
00144068 add     sp, sp, #0x90
0014406c ret     
00144070 bl      #0x148a10
00144074 str     x19, [sp, #-0x10]!
00144078 lsl     w10, w1, #1
0014407c mov     x8, #0x865
00144080 mov     x12, #0xcdf8
00144084 mov     x13, #0x92
00144088 mov     x14, #0xcd53
0014408c mov     x16, #0x1471
00144090 mov     x17, #0x8d87
00144094 mov     x1, #0xea12
00144098 mov     x5, #0xcdf8
0014409c movk    x8, #0x5362, lsl #16
001440a0 movk    x12, #0xd72b, lsl #16
001440a4 movk    x13, #0x16d6, lsl #16
001440a8 movk    x14, #0xade6, lsl #16
001440ac movk    x16, #0x4a0, lsl #16
001440b0 movk    x17, #0xa2f3, lsl #16
001440b4 movk    x1, #0x2ac8, lsl #16
001440b8 movk    x5, #0xd72b, lsl #16
001440bc movk    x8, #0x98ea, lsl #32
001440c0 add     w10, w10, #3
001440c4 movk    x12, #0x55aa, lsl #32
001440c8 movk    x13, #0x9d06, lsl #32
001440cc movk    x14, #0xefff, lsl #32
001440d0 movk    x16, #0x5fd, lsl #32
001440d4 movk    x17, #0x8648, lsl #32
001440d8 movk    x1, #0x1d60, lsl #32
001440dc movk    x5, #0x55aa, lsl #32
001440e0 mov     x9, xzr
001440e4 mov     w3, wzr
001440e8 movk    x8, #0xabfd, lsl #48
001440ec and     w10, w10, #0xffff
001440f0 add     x11, x0, x2, lsl #1
001440f4 movk    x12, #0xfe6b, lsl #48
001440f8 movk    x13, #0x2680, lsl #48
001440fc movk    x14, #0x13d4, lsl #48
00144100 mov     w15, #0xf
00144104 movk    x16, #0xa11a, lsl #48
00144108 movk    x17, #0xa5e3, lsl #48
0014410c movk    x1, #0x1023, lsl #48
00144110 movk    x5, #0xfe6b, lsl #48
00144114 strh    wzr, [x11, #0x30]!
00144118 sub     x7, x15, x9
0014411c lsr     w6, w10, w9
00144120 tst     w6, #1
00144124 add     x19, x0, x7, lsl #1
00144128 csel    x6, x14, x13, eq
0014412c add     x7, x9, #1
00144130 add     x19, x19, #0x10
00144134 cmp     x5, x16
00144138 b.eq    #0x144170
0014413c cmp     x5, x17
00144140 b.eq    #0x1441dc
00144144 cmp     x5, x13
00144148 b.eq    #0x14418c
0014414c cmp     x5, x12
00144150 b.eq    #0x144178
00144154 cmp     x5, x1
00144158 b.eq    #0x1441ac
0014415c cmp     x5, x14
00144160 b.eq    #0x1441b4
00144164 cmp     x5, x8
00144168 b.ne    #0x144134
0014416c b       #0x1441cc
00144170 mov     w3, w4
00144174 mov     x9, x7
00144178 mov     x5, #0x865
0014417c movk    x5, #0x5362, lsl #16
00144180 movk    x5, #0x98ea, lsl #32
00144184 movk    x5, #0xabfd, lsl #48
00144188 b       #0x144134
0014418c ldrh    w4, [x19]
00144190 mov     x5, #0x1471
00144194 movk    x5, #0x4a0, lsl #16
00144198 movk    x5, #0x5fd, lsl #32
0014419c eor     w4, w4, w2
001441a0 movk    x5, #0xa11a, lsl #48
001441a4 strh    w4, [x11]
001441a8 b       #0x144134
001441ac mov     x5, x6
001441b0 b       #0x144134
001441b4 mov     x5, #0x1471
001441b8 mov     w4, w2
001441bc movk    x5, #0x4a0, lsl #16
001441c0 movk    x5, #0x5fd, lsl #32
001441c4 movk    x5, #0xa11a, lsl #48
001441c8 b       #0x144134
001441cc cmp     x9, #0x10
001441d0 mov     w2, w3
001441d4 csel    x5, x17, x1, eq
001441d8 b       #0x144118
001441dc ldr     x19, [sp], #0x10
001441e0 ret     
001441e4 stp     x29, x30, [sp, #-0x20]!
001441e8 stp     x20, x19, [sp, #0x10]
001441ec mov     x29, sp
001441f0 mov     w19, w1
001441f4 mov     x20, x0
001441f8 bl      #0x143b20
001441fc mov     x2, x0
00144200 mov     x0, x20
00144204 mov     w1, w19
00144208 ldp     x20, x19, [sp, #0x10]
0014420c ldp     x29, x30, [sp], #0x20
00144210 b       #0x144074
00144214 sub     sp, sp, #0x80
00144218 stp     x29, x30, [sp, #0x20]
0014421c stp     x28, x27, [sp, #0x30]
00144220 stp     x26, x25, [sp, #0x40]
00144224 stp     x24, x23, [sp, #0x50]
00144228 stp     x22, x21, [sp, #0x60]
0014422c stp     x20, x19, [sp, #0x70]
00144230 add     x29, sp, #0x20
00144234 cmp     x2, #0
00144238 mov     x23, #0x6dbb
0014423c mov     x24, #0x1968
00144240 mov     x22, #0xe11a
00144244 ccmp    x1, #0, #4, ne
00144248 movk    x23, #0xc058, lsl #16
0014424c movk    x24, #0x5932, lsl #16
00144250 mov     x25, #0x754
00144254 mov     x26, #0x692
00144258 mov     x27, #0xfe0a
0014425c mov     x21, #0x7801
00144260 mov     x9, #0x754
00144264 movk    x22, #0xe707, lsl #16
00144268 movk    x23, #0xf56d, lsl #32
0014426c movk    x24, #0x8339, lsl #32
00144270 movk    x25, #0xa078, lsl #16
00144274 movk    x26, #0x8807, lsl #16
00144278 movk    x27, #0x69fd, lsl #16
0014427c movk    x21, #0xa06d, lsl #16
00144280 movk    x9, #0xa078, lsl #16
00144284 movk    x22, #0x5296, lsl #32
00144288 movk    x23, #0x7e88, lsl #48
0014428c movk    x24, #0xb13, lsl #48
00144290 movk    x25, #0x1f94, lsl #32
00144294 movk    x26, #0xfbe3, lsl #32
00144298 movk    x27, #0x5f3a, lsl #32
0014429c movk    x21, #0xab5f, lsl #32
001442a0 movk    x9, #0x1f94, lsl #32
001442a4 mov     x20, x1
001442a8 movk    x22, #0x1df3, lsl #48
001442ac movk    x25, #0x3282, lsl #48
001442b0 movk    x26, #0xa1b3, lsl #48
001442b4 movk    x27, #0xbdc7, lsl #48
001442b8 csel    x8, x24, x23, ne
001442bc movk    x21, #0x22db, lsl #48
001442c0 movk    x9, #0x3282, lsl #48
001442c4 str     x0, [sp, #0x10]
001442c8 stur    x2, [x29, #-8]
001442cc str     x8, [sp, #8]
001442d0 add     x19, x28, #1
001442d4 cmp     x9, x26
001442d8 b.eq    #0x144320
001442dc cmp     x9, x27
001442e0 b.eq    #0x14430c
001442e4 cmp     x9, x24
001442e8 b.eq    #0x144344
001442ec cmp     x9, x22
001442f0 b.eq    #0x144378
001442f4 cmp     x9, x21
001442f8 b.eq    #0x144364
001442fc cmp     x9, x25
00144300 b.eq    #0x14435c
00144304 cmp     x9, x23
00144308 b.ne    #0x1442d4
0014430c mov     x9, #0xe11a
00144310 movk    x9, #0xe707, lsl #16
00144314 movk    x9, #0x5296, lsl #32
00144318 movk    x9, #0x1df3, lsl #48
0014431c b       #0x1442d4
00144320 ldrh    w1, [x20, x28, lsl #1]
00144324 ldr     x0, [sp, #0x10]
00144328 bl      #0x1441e4
0014432c mov     x9, #0x7801
00144330 mov     x8, x19
00144334 movk    x9, #0xa06d, lsl #16
00144338 movk    x9, #0xab5f, lsl #32
0014433c movk    x9, #0x22db, lsl #48
00144340 b       #0x1442d4
00144344 mov     x9, #0x7801
00144348 mov     x8, xzr
0014434c movk    x9, #0xa06d, lsl #16
00144350 movk    x9, #0xab5f, lsl #32
00144354 movk    x9, #0x22db, lsl #48
00144358 b       #0x1442d4
0014435c ldr     x9, [sp, #8]
00144360 b       #0x1442d4
00144364 ldur    x9, [x29, #-8]
00144368 mov     x28, x8
0014436c cmp     x8, x9
00144370 csel    x9, x27, x26, eq
00144374 b       #0x1442d0
00144378 ldp     x20, x19, [sp, #0x70]
0014437c ldp     x22, x21, [sp, #0x60]
00144380 ldp     x24, x23, [sp, #0x50]
00144384 ldp     x26, x25, [sp, #0x40]
00144388 ldp     x28, x27, [sp, #0x30]
0014438c ldp     x29, x30, [sp, #0x20]
00144390 add     sp, sp, #0x80
00144394 ret     
00144398 sub     sp, sp, #0x1b0
0014439c stp     x29, x30, [sp, #0x150]
001443a0 stp     x28, x27, [sp, #0x160]
001443a4 stp     x26, x25, [sp, #0x170]
001443a8 stp     x24, x23, [sp, #0x180]
001443ac stp     x22, x21, [sp, #0x190]
001443b0 stp     x20, x19, [sp, #0x1a0]
001443b4 add     x29, sp, #0x150
001443b8 str     x6, [sp, #0xa0]
001443bc mov     x16, x1
001443c0 stp     x4, x5, [sp, #0x20]
001443c4 mov     x1, #0x507b
001443c8 stp     x2, x3, [sp, #0x10]
001443cc mov     x2, #0xc335
001443d0 mov     x3, #0x865
001443d4 mov     x4, #0x8d87
001443d8 mov     x5, #0xc2a2
001443dc mov     x6, #0x1859
001443e0 mov     x19, #0xe386
001443e4 mov     x30, #0xd05b
001443e8 mov     x17, #0xb7cc
001443ec mov     x15, #0x8e81
001443f0 str     x0, [sp, #8]
001443f4 movk    x1, #0x2c50, lsl #16
001443f8 stur    wzr, [x29, #-0x34]
001443fc movk    x2, #0x1484, lsl #16
00144400 str     wzr, [sp, #0x94]
00144404 movk    x3, #0x5362, lsl #16
00144408 stur    wzr, [x29, #-0x4c]
0014440c mrs     x8, tpidr_el0
00144410 movk    x4, #0xa2f3, lsl #16
00144414 movk    x5, #0x1048, lsl #16
00144418 movk    x6, #0x2b53, lsl #16
0014441c movk    x19, #0xeab8, lsl #16
00144420 movk    x30, #0xef20, lsl #16
00144424 movk    x17, #0xff64, lsl #16
00144428 movk    x15, #0xe154, lsl #16
0014442c str     x8, [sp]
00144430 movk    x1, #0x48ac, lsl #32
00144434 movk    x2, #0x16b3, lsl #32
00144438 movk    x3, #0x98ea, lsl #32
0014443c movk    x4, #0x8648, lsl #32
00144440 movk    x5, #0x7104, lsl #32
00144444 movk    x6, #0x6ffc, lsl #32
00144448 movk    x19, #0xc1ec, lsl #32
0014444c movk    x30, #0x96cc, lsl #32
00144450 movk    x17, #0xf23e, lsl #32
00144454 movk    x15, #0x3b5e, lsl #32
00144458 mov     w11, wzr
0014445c ldr     x8, [x8, #0x28]
00144460 movk    x1, #0xc90b, lsl #48
00144464 movk    x2, #0xb3cc, lsl #48
00144468 movk    x3, #0xabfd, lsl #48
0014446c movk    x4, #0xa5e3, lsl #48
00144470 movk    x5, #0x9ffe, lsl #48
00144474 movk    x6, #0x930b, lsl #48
00144478 movk    x19, #0x808f, lsl #48
0014447c movk    x30, #0x8753, lsl #48
00144480 movk    x17, #0x8f3d, lsl #48
00144484 movk    x15, #0x7cc5, lsl #48
00144488 stur    x8, [x29, #-0x10]
0014448c stur    wzr, [x29, #-0x18]
00144490 stur    xzr, [x29, #-0x20]
00144494 str     x16, [sp, #0x98]
00144498 mov     x14, x15
0014449c mov     x15, #0xc2a2
001444a0 movk    x15, #0x1048, lsl #16
001444a4 cmp     x14, x19
001444a8 movk    x15, #0x7104, lsl #32
001444ac movk    x15, #0x9ffe, lsl #48
001444b0 b.eq    #0x144498
001444b4 mov     x24, x16
001444b8 mov     x21, x13
001444bc mov     w28, w11
001444c0 mov     x25, x10
001444c4 mov     x27, x9
001444c8 mov     x20, x8
001444cc cmp     x14, x30
001444d0 b.eq    #0x145578
001444d4 mov     x23, x12
001444d8 cmp     x14, x17
001444dc b.eq    #0x144e40
001444e0 cmp     x14, x6
001444e4 b.eq    #0x144c64
001444e8 mov     x8, #0x8a0
001444ec movk    x8, #0xbd15, lsl #16
001444f0 movk    x8, #0xb02c, lsl #32
001444f4 movk    x8, #0x93e7, lsl #48
001444f8 cmp     x14, x8
001444fc b.eq    #0x1455c0
00144500 cmp     x14, x5
00144504 b.eq    #0x144bf4
00144508 mov     x15, #0x754
0014450c mov     x7, #0x1471
00144510 movk    x15, #0xa078, lsl #16
00144514 movk    x7, #0x4a0, lsl #16
00144518 movk    x15, #0x1f94, lsl #32
0014451c mov     x8, x20
00144520 mov     x9, x27
00144524 mov     x10, x25
00144528 mov     w11, w28
0014452c mov     x12, x23
00144530 mov     x13, x21
00144534 mov     x16, x24
00144538 movk    x15, #0x3282, lsl #48
0014453c movk    x7, #0x5fd, lsl #32
00144540 movk    x7, #0xa11a, lsl #48
00144544 cmp     x14, x7
00144548 b.eq    #0x144498
0014454c cmp     x14, x4
00144550 b.eq    #0x1453d0
00144554 mov     x15, #0x8d87
00144558 mov     x8, x20
0014455c movk    x15, #0xa2f3, lsl #16
00144560 mov     x9, x27
00144564 movk    x15, #0x8648, lsl #32
00144568 mov     x10, x25
0014456c mov     w11, w28
00144570 mov     x12, x23
00144574 mov     x13, x21
00144578 mov     x16, x24
0014457c movk    x15, #0xa5e3, lsl #48
00144580 cmp     x14, x3
00144584 b.eq    #0x144498
00144588 mov     x8, #0xafb5
0014458c movk    x8, #0xa12b, lsl #16
00144590 movk    x8, #0xce93, lsl #32
00144594 movk    x8, #0xb225, lsl #48
00144598 cmp     x14, x8
0014459c b.eq    #0x145070
001445a0 cmp     x14, x2
001445a4 b.eq    #0x144c24
001445a8 mov     x8, #0x1381
001445ac movk    x8, #0xa58a, lsl #16
001445b0 movk    x8, #0xb763, lsl #32
001445b4 movk    x8, #0xbbcd, lsl #48
001445b8 cmp     x14, x8
001445bc b.eq    #0x144d08
001445c0 mov     x15, #0x28cc
001445c4 mov     x7, #0xfe0a
001445c8 movk    x15, #0xc3e2, lsl #16
001445cc movk    x7, #0x69fd, lsl #16
001445d0 movk    x15, #0x7819, lsl #32
001445d4 mov     x8, x20
001445d8 mov     x9, x27
001445dc mov     x10, x25
001445e0 mov     w11, w28
001445e4 mov     x12, x23
001445e8 mov     x13, x21
001445ec mov     x16, x24
001445f0 movk    x15, #0x6b85, lsl #48
001445f4 movk    x7, #0x5f3a, lsl #32
001445f8 movk    x7, #0xbdc7, lsl #48
001445fc cmp     x14, x7
==== 0x144600 0x144c00
00144600 b.eq    #0x144498
00144604 mov     x8, #0xdf4a
00144608 movk    x8, #0xbdc8, lsl #16
0014460c movk    x8, #0xceb, lsl #32
00144610 movk    x8, #0xc8d5, lsl #48
00144614 cmp     x14, x8
00144618 b.eq    #0x14502c
0014461c cmp     x14, x1
00144620 b.eq    #0x145254
00144624 mov     x8, #0x113f
00144628 movk    x8, #0xceaf, lsl #16
0014462c movk    x8, #0x4fe6, lsl #32
00144630 movk    x8, #0xe9ff, lsl #48
00144634 cmp     x14, x8
00144638 b.eq    #0x1450e0
0014463c mov     x15, #0x8d87
00144640 mov     x7, #0x25ce
00144644 movk    x15, #0xa2f3, lsl #16
00144648 movk    x7, #0x8c3e, lsl #16
0014464c movk    x15, #0x8648, lsl #32
00144650 mov     x8, x20
00144654 mov     x9, x27
00144658 mov     x10, x25
0014465c mov     w11, w28
00144660 mov     x12, x23
00144664 mov     x13, x21
00144668 mov     x16, x24
0014466c movk    x15, #0xa5e3, lsl #48
00144670 movk    x7, #0xdec2, lsl #32
00144674 movk    x7, #0xf201, lsl #48
00144678 cmp     x14, x7
0014467c b.eq    #0x144498
00144680 mov     x15, #0x3581
00144684 mov     x7, #0x2f9c
00144688 movk    x15, #0xbcba, lsl #16
0014468c movk    x7, #0xc396, lsl #16
00144690 movk    x15, #0x133, lsl #32
00144694 mov     x8, x20
00144698 mov     x9, x27
0014469c mov     x10, x25
001446a0 mov     w11, w28
001446a4 mov     x12, x23
001446a8 mov     x13, x21
001446ac mov     x16, x24
001446b0 movk    x15, #0x761f, lsl #48
001446b4 movk    x7, #0x5e8f, lsl #32
001446b8 movk    x7, #0xf2cd, lsl #48
001446bc cmp     x14, x7
001446c0 b.eq    #0x144498
001446c4 mov     x8, #0x9a1f
001446c8 movk    x8, #0xd6a5, lsl #16
001446cc movk    x8, #0xc885, lsl #32
001446d0 movk    x8, #0xf611, lsl #48
001446d4 cmp     x14, x8
001446d8 b.eq    #0x144f2c
001446dc mov     x8, #0x7811
001446e0 movk    x8, #0x740, lsl #16
001446e4 movk    x8, #0x67ad, lsl #32
001446e8 movk    x8, #0xf79c, lsl #48
001446ec cmp     x14, x8
001446f0 b.eq    #0x145494
001446f4 mov     x15, #0x5dae
001446f8 mov     x7, #0xa74a
001446fc movk    x15, #0xbd6e, lsl #16
00144700 movk    x7, #0x5ea3, lsl #16
00144704 movk    x15, #0x6aaa, lsl #32
00144708 mov     x8, x20
0014470c mov     x9, x27
00144710 mov     x10, x25
00144714 mov     w11, w28
00144718 mov     x12, x23
0014471c mov     x13, x21
00144720 mov     x16, x22
00144724 movk    x15, #0x28f0, lsl #48
00144728 movk    x7, #0xa04f, lsl #32
0014472c movk    x7, #0xfa1e, lsl #48
00144730 cmp     x14, x7
00144734 b.eq    #0x144498
00144738 mov     x15, #0x865
0014473c mov     x7, #0xcdf8
00144740 movk    x15, #0x5362, lsl #16
00144744 movk    x7, #0xd72b, lsl #16
00144748 movk    x15, #0x98ea, lsl #32
0014474c mov     x8, x20
00144750 mov     x9, x27
00144754 mov     x10, x25
00144758 mov     w11, w28
0014475c mov     x12, x23
00144760 mov     x13, x21
00144764 mov     x16, x24
00144768 movk    x15, #0xabfd, lsl #48
0014476c movk    x7, #0x55aa, lsl #32
00144770 movk    x7, #0xfe6b, lsl #48
00144774 cmp     x14, x7
00144778 b.eq    #0x144498
0014477c mov     x8, #0x8779
00144780 movk    x8, #0xf1b8, lsl #16
00144784 movk    x8, #0x3378, lsl #32
00144788 movk    x8, #0xeb0, lsl #48
0014478c cmp     x14, x8
00144790 b.eq    #0x144ee4
00144794 mov     x15, #0x1859
00144798 mov     x7, #0xea12
0014479c movk    x15, #0x2b53, lsl #16
001447a0 movk    x7, #0x2ac8, lsl #16
001447a4 movk    x15, #0x6ffc, lsl #32
001447a8 mov     x8, x20
001447ac mov     x9, x27
001447b0 mov     x10, x25
001447b4 mov     w11, w28
001447b8 mov     x12, x0
001447bc mov     x13, x21
001447c0 mov     x16, x24
001447c4 movk    x15, #0x930b, lsl #48
001447c8 movk    x7, #0x1d60, lsl #32
001447cc movk    x7, #0x1023, lsl #48
001447d0 cmp     x14, x7
001447d4 b.eq    #0x144498
001447d8 mov     x15, #0x754
001447dc mov     x7, #0xcd53
001447e0 movk    x15, #0xa078, lsl #16
001447e4 movk    x7, #0xade6, lsl #16
001447e8 movk    x15, #0x1f94, lsl #32
001447ec mov     x8, x20
001447f0 mov     x9, x27
001447f4 mov     x10, x25
001447f8 mov     w11, w28
001447fc mov     x12, x23
00144800 mov     x13, x21
00144804 mov     x16, x24
00144808 movk    x15, #0x3282, lsl #48
0014480c movk    x7, #0xefff, lsl #32
00144810 movk    x7, #0x13d4, lsl #48
00144814 cmp     x14, x7
00144818 b.eq    #0x144498
0014481c mov     x15, #0xc2a2
00144820 mov     x7, #0xb3d0
00144824 movk    x15, #0x1048, lsl #16
00144828 movk    x7, #0x566, lsl #16
0014482c movk    x15, #0x7104, lsl #32
00144830 mov     x8, x20
00144834 mov     x9, x27
00144838 mov     x10, x25
0014483c mov     w11, w28
00144840 mov     x12, x23
00144844 mov     x13, x21
00144848 mov     x16, x24
0014484c movk    x15, #0x9ffe, lsl #48
00144850 movk    x7, #0xa50d, lsl #32
00144854 movk    x7, #0x204a, lsl #48
00144858 cmp     x14, x7
0014485c b.eq    #0x144498
00144860 mov     x8, #0x7801
00144864 movk    x8, #0xa06d, lsl #16
00144868 movk    x8, #0xab5f, lsl #32
0014486c movk    x8, #0x22db, lsl #48
00144870 cmp     x14, x8
00144874 b.eq    #0x14529c
00144878 mov     x8, #0xb031
0014487c movk    x8, #0x9cc1, lsl #16
00144880 movk    x8, #0xffeb, lsl #32
00144884 movk    x8, #0x2516, lsl #48
00144888 cmp     x14, x8
0014488c b.eq    #0x144ccc
00144890 mov     x8, #0x92
00144894 movk    x8, #0x16d6, lsl #16
00144898 movk    x8, #0x9d06, lsl #32
0014489c movk    x8, #0x2680, lsl #48
001448a0 cmp     x14, x8
001448a4 b.eq    #0x144f8c
001448a8 mov     x8, #0x5dae
001448ac movk    x8, #0xbd6e, lsl #16
001448b0 movk    x8, #0x6aaa, lsl #32
001448b4 movk    x8, #0x28f0, lsl #48
001448b8 cmp     x14, x8
001448bc b.eq    #0x145448
001448c0 mov     x8, #0x754
001448c4 movk    x8, #0xa078, lsl #16
001448c8 movk    x8, #0x1f94, lsl #32
001448cc movk    x8, #0x3282, lsl #48
001448d0 cmp     x14, x8
001448d4 b.eq    #0x145394
001448d8 mov     x15, #0x5cb8
001448dc mov     x7, #0x1dac
001448e0 ldp     x9, x10, [x29, #-0x30]
001448e4 movk    x15, #0x2795, lsl #16
001448e8 movk    x7, #0x9f5e, lsl #16
001448ec movk    x15, #0x15f4, lsl #32
001448f0 ldur    x8, [x29, #-0x40]
001448f4 ldur    w11, [x29, #-0x34]
001448f8 mov     x12, x23
001448fc mov     x13, x21
00144900 mov     x16, x24
00144904 movk    x15, #0x77a4, lsl #48
00144908 movk    x7, #0xb762, lsl #32
0014490c movk    x7, #0x3b4a, lsl #48
00144910 cmp     x14, x7
00144914 b.eq    #0x144498
00144918 mov     x15, #0x865
0014491c mov     x7, #0x4c0d
00144920 movk    x15, #0x5362, lsl #16
00144924 movk    x7, #0x52dd, lsl #16
00144928 movk    x15, #0x98ea, lsl #32
0014492c mov     x8, x20
00144930 mov     x9, x27
00144934 mov     x10, x25
00144938 mov     w11, w28
0014493c mov     x12, x23
00144940 mov     x13, x21
00144944 mov     x16, x24
00144948 movk    x15, #0xabfd, lsl #48
0014494c movk    x7, #0x7dcf, lsl #32
00144950 movk    x7, #0x48fe, lsl #48
00144954 cmp     x14, x7
00144958 b.eq    #0x144498
0014495c mov     x8, #0xd282
00144960 movk    x8, #0x957d, lsl #16
00144964 movk    x8, #0xadd, lsl #32
00144968 movk    x8, #0x549f, lsl #48
0014496c cmp     x14, x8
00144970 b.eq    #0x14520c
00144974 mov     x8, #0x6436
00144978 movk    x8, #0x2869, lsl #16
0014497c movk    x8, #0xc5df, lsl #32
00144980 movk    x8, #0x56de, lsl #48
00144984 cmp     x14, x8
00144988 b.eq    #0x145348
0014498c mov     x8, #0xd2d1
00144990 movk    x8, #0xf825, lsl #16
00144994 movk    x8, #0xee0c, lsl #32
00144998 movk    x8, #0x5c23, lsl #48
0014499c cmp     x14, x8
001449a0 b.eq    #0x144d54
001449a4 mov     x8, #0x9bd
001449a8 movk    x8, #0xb5f6, lsl #16
001449ac movk    x8, #0xce8f, lsl #32
001449b0 movk    x8, #0x62d5, lsl #48
001449b4 cmp     x14, x8
001449b8 b.eq    #0x144e90
001449bc mov     x8, #0xee15
001449c0 movk    x8, #0x1fe1, lsl #16
001449c4 movk    x8, #0x5376, lsl #32
001449c8 movk    x8, #0x6aa9, lsl #48
001449cc cmp     x14, x8
001449d0 b.eq    #0x145214
001449d4 mov     x8, #0x28cc
001449d8 mov     x26, x0
001449dc movk    x8, #0xc3e2, lsl #16
001449e0 movk    x8, #0x7819, lsl #32
001449e4 movk    x8, #0x6b85, lsl #48
001449e8 cmp     x14, x8
001449ec b.eq    #0x144fc4
001449f0 mov     x8, #0x3581
001449f4 movk    x8, #0xbcba, lsl #16
001449f8 movk    x8, #0x133, lsl #32
001449fc movk    x8, #0x761f, lsl #48
00144a00 cmp     x14, x8
00144a04 b.eq    #0x1450fc
00144a08 mov     x17, #0x7515
00144a0c mov     x15, #0x3581
00144a10 movk    x17, #0xb217, lsl #16
00144a14 mov     x1, #0x507b
00144a18 movk    x17, #0xdfc8, lsl #32
00144a1c mov     x2, #0xc335
00144a20 movk    x17, #0x768a, lsl #48
00144a24 mov     x3, #0x865
00144a28 cmp     x14, x17
00144a2c mov     x4, #0x8d87
00144a30 mov     x5, #0xc2a2
00144a34 mov     x6, #0x1859
00144a38 mov     x30, #0xd05b
00144a3c mov     x17, #0xb7cc
00144a40 mov     x19, #0xe386
00144a44 movk    x15, #0xbcba, lsl #16
00144a48 movk    x1, #0x2c50, lsl #16
00144a4c movk    x2, #0x1484, lsl #16
00144a50 movk    x3, #0x5362, lsl #16
00144a54 movk    x4, #0xa2f3, lsl #16
00144a58 movk    x5, #0x1048, lsl #16
00144a5c movk    x6, #0x2b53, lsl #16
00144a60 movk    x30, #0xef20, lsl #16
00144a64 movk    x17, #0xff64, lsl #16
00144a68 movk    x19, #0xeab8, lsl #16
00144a6c movk    x15, #0x133, lsl #32
00144a70 movk    x1, #0x48ac, lsl #32
00144a74 movk    x2, #0x16b3, lsl #32
00144a78 movk    x3, #0x98ea, lsl #32
00144a7c movk    x4, #0x8648, lsl #32
00144a80 movk    x5, #0x7104, lsl #32
00144a84 movk    x6, #0x6ffc, lsl #32
00144a88 movk    x30, #0x96cc, lsl #32
00144a8c movk    x17, #0xf23e, lsl #32
00144a90 movk    x19, #0xc1ec, lsl #32
00144a94 mov     x8, x20
00144a98 mov     x9, x27
00144a9c mov     x10, x25
00144aa0 mov     w11, w28
00144aa4 mov     x12, x23
00144aa8 mov     x13, x21
00144aac mov     x16, x24
00144ab0 movk    x15, #0x761f, lsl #48
00144ab4 movk    x1, #0xc90b, lsl #48
00144ab8 movk    x2, #0xb3cc, lsl #48
00144abc movk    x3, #0xabfd, lsl #48
00144ac0 movk    x4, #0xa5e3, lsl #48
00144ac4 movk    x5, #0x9ffe, lsl #48
00144ac8 movk    x6, #0x930b, lsl #48
00144acc movk    x30, #0x8753, lsl #48
00144ad0 movk    x17, #0x8f3d, lsl #48
00144ad4 movk    x19, #0x808f, lsl #48
00144ad8 mov     x0, x26
00144adc b.eq    #0x144498
00144ae0 mov     x8, #0x5cb8
00144ae4 movk    x8, #0x2795, lsl #16
00144ae8 movk    x8, #0x15f4, lsl #32
00144aec movk    x8, #0x77a4, lsl #48
00144af0 cmp     x14, x8
00144af4 b.eq    #0x1452e4
00144af8 mov     x17, #0x8e81
00144afc mov     x15, #0x5dae
00144b00 movk    x17, #0xe154, lsl #16
00144b04 movk    x15, #0xbd6e, lsl #16
00144b08 movk    x17, #0x3b5e, lsl #32
00144b0c movk    x15, #0x6aaa, lsl #32
00144b10 movk    x17, #0x7cc5, lsl #48
00144b14 mov     x8, x20
00144b18 cmp     x14, x17
00144b1c mov     x17, #0xb7cc
00144b20 movk    x17, #0xff64, lsl #16
00144b24 mov     x9, x27
00144b28 movk    x17, #0xf23e, lsl #32
00144b2c mov     x10, x25
00144b30 mov     w11, w28
00144b34 mov     x12, x23
00144b38 mov     x13, x21
00144b3c mov     x16, x24
00144b40 movk    x15, #0x28f0, lsl #48
00144b44 movk    x17, #0x8f3d, lsl #48
00144b48 b.eq    #0x144498
00144b4c mov     x8, #0x6dbb
00144b50 movk    x8, #0xc058, lsl #16
00144b54 movk    x8, #0xf56d, lsl #32
00144b58 movk    x8, #0x7e88, lsl #48
00144b5c cmp     x14, x8
00144b60 b.eq    #0x1451ec
00144b64 mov     x15, #0x507b
00144b68 mov     x7, #0x7408
00144b6c movk    x15, #0x2c50, lsl #16
00144b70 movk    x7, #0x4e14, lsl #16
00144b74 movk    x15, #0x48ac, lsl #32
00144b78 mov     x8, x20
00144b7c mov     x9, x27
00144b80 mov     x10, x25
00144b84 mov     w11, w28
00144b88 mov     x12, x23
00144b8c ldur    x13, [x29, #-0x70]
00144b90 mov     x16, x24
00144b94 movk    x15, #0xc90b, lsl #48
00144b98 movk    x7, #0x43cd, lsl #32
00144b9c movk    x7, #0x7f74, lsl #48
00144ba0 cmp     x14, x7
00144ba4 b.eq    #0x144498
00144ba8 mov     x17, #0x1968
00144bac mov     x8, x20
00144bb0 movk    x17, #0x5932, lsl #16
00144bb4 mov     x9, x27
00144bb8 movk    x17, #0x8339, lsl #32
00144bbc mov     x10, x25
00144bc0 movk    x17, #0xb13, lsl #48
00144bc4 mov     w11, w28
00144bc8 cmp     x14, x17
00144bcc mov     x17, #0xb7cc
00144bd0 movk    x17, #0xff64, lsl #16
00144bd4 mov     x12, x23
00144bd8 movk    x17, #0xf23e, lsl #32
00144bdc mov     x13, x21
00144be0 mov     x16, x24
00144be4 mov     x15, x14
00144be8 movk    x17, #0x8f3d, lsl #48
00144bec b.ne    #0x144498
00144bf0 b       #0x145600
00144bf4 ldp     x8, x9, [sp, #0x30]
00144bf8 mov     x15, #0x5cb8
00144bfc mov     x12, x23
