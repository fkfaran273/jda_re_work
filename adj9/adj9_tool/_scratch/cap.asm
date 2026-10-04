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
00147b00 str     w16, [x0]
00147b04 movk    x19, #0x9cc1, lsl #16
00147b08 movk    x19, #0xffeb, lsl #32
00147b0c movk    x19, #0x2516, lsl #48
00147b10 b       #0x147ac4
00147b14 mov     x19, x15
00147b18 b       #0x147ac4
00147b1c mov     x19, #0x25ce
00147b20 ldr     x6, [x4, #8]
00147b24 movk    x19, #0x8c3e, lsl #16
00147b28 mov     w7, w20
00147b2c movk    x19, #0xdec2, lsl #32
00147b30 movk    x19, #0xf201, lsl #48
00147b34 b       #0x147ac4
00147b38 ldr     w21, [x4]
00147b3c mov     x19, #0xb031
00147b40 movk    x19, #0x9cc1, lsl #16
00147b44 movk    x19, #0xffeb, lsl #32
00147b48 movk    x19, #0x2516, lsl #48
00147b4c str     w21, [x17]
00147b50 str     w3, [x4]
00147b54 b       #0x147ac4
00147b58 cmp     w7, w2
00147b5c mov     x4, x6
00147b60 csel    x19, x14, x13, eq
00147b64 mov     w5, w7
00147b68 b       #0x147ac0
00147b6c ldr     x17, [x1, #8]
00147b70 mov     x19, #0x25ce
00147b74 movk    x19, #0x8c3e, lsl #16
00147b78 movk    x19, #0xdec2, lsl #32
00147b7c ldr     w3, [x17]
00147b80 movk    x19, #0xf201, lsl #48
00147b84 b       #0x147ab8
00147b88 ldp     x20, x19, [sp, #0x10]
00147b8c ldr     x21, [sp], #0x20
00147b90 ret     
00147b94 stp     x29, x30, [sp, #-0x40]!
00147b98 stp     x24, x23, [sp, #0x10]
00147b9c stp     x22, x21, [sp, #0x20]
00147ba0 stp     x20, x19, [sp, #0x30]
00147ba4 mov     x29, sp
00147ba8 mov     x20, #0xc2a2
00147bac mov     x21, #0x1381
00147bb0 movk    x20, #0x1048, lsl #16
00147bb4 movk    x21, #0xa58a, lsl #16
00147bb8 mov     x22, #0xe386
00147bbc mov     x24, #0xb3d0
00147bc0 mov     x8, #0xb3d0
00147bc4 movk    x20, #0x7104, lsl #32
00147bc8 movk    x21, #0xb763, lsl #32
00147bcc movk    x22, #0xeab8, lsl #16
00147bd0 movk    x24, #0x566, lsl #16
00147bd4 movk    x8, #0x566, lsl #16
00147bd8 movk    x20, #0x9ffe, lsl #48
00147bdc movk    x21, #0xbbcd, lsl #48
00147be0 cmp     x0, #0
00147be4 movk    x22, #0xc1ec, lsl #32
00147be8 movk    x24, #0xa50d, lsl #32
00147bec movk    x8, #0xa50d, lsl #32
00147bf0 mov     x19, x0
00147bf4 movk    x22, #0x808f, lsl #48
00147bf8 csel    x23, x21, x20, eq
00147bfc movk    x24, #0x204a, lsl #48
00147c00 movk    x8, #0x204a, lsl #48
00147c04 cmp     x8, x22
00147c08 b.eq    #0x147c54
00147c0c cmp     x8, x20
00147c10 b.eq    #0x147c28
00147c14 cmp     x8, x24
00147c18 b.eq    #0x147c4c
00147c1c cmp     x8, x21
00147c20 b.ne    #0x147c04
00147c24 b       #0x147c38
00147c28 ldr     x0, [x19, #8]
00147c2c bl      #0x147b94
00147c30 mov     x0, x19
00147c34 bl      #0x148a00
00147c38 mov     x8, #0xe386
00147c3c movk    x8, #0xeab8, lsl #16
00147c40 movk    x8, #0xc1ec, lsl #32
00147c44 movk    x8, #0x808f, lsl #48
00147c48 b       #0x147c04
00147c4c mov     x8, x23
00147c50 b       #0x147c04
00147c54 ldp     x20, x19, [sp, #0x30]
00147c58 ldp     x22, x21, [sp, #0x20]
00147c5c ldp     x24, x23, [sp, #0x10]
00147c60 ldp     x29, x30, [sp], #0x40
00147c64 ret     
