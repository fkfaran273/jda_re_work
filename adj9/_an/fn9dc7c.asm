0009dc7c stp    x29, x30, [sp, #0x60]
0009dc80 stp    x28, x27, [sp, #0x70]
0009dc84 stp    x26, x25, [sp, #0x80]
0009dc88 stp    x24, x23, [sp, #0x90]
0009dc8c stp    x22, x21, [sp, #0xa0]
0009dc90 stp    x20, x19, [sp, #0xb0]
0009dc94 add    x29, sp, #0x60
0009dc98 mov    x19, #0xf5ac
0009dc9c mov    x9, #0xdd29
0009dca0 movk   x19, #0xee3a, lsl #16
0009dca4 movk   x9, #0x2afc, lsl #16
0009dca8 stur   x4, [x29, #-0x28]
0009dcac movk   x19, #0x9045, lsl #32
0009dcb0 stp    x2, x3, [sp, #0x28]
0009dcb4 movk   x9, #0x8922, lsl #32
0009dcb8 str    x1, [sp, #0x20]
0009dcbc mrs    x8, tpidr_el0
0009dcc0 cmp    x2, #0
0009dcc4 movk   x19, #0xa100, lsl #48
0009dcc8 movk   x9, #0x63b5, lsl #48
0009dccc str    x8, [sp, #8]
0009dcd0 mov    x22, #0x9c7c
0009dcd4 csel   x21, x9, x19, eq
0009dcd8 mov    x20, #0x4bf8
0009dcdc mov    x24, #0xe43f
0009dce0 mov    x25, #0xdf88
0009dce4 mov    x11, #0x8155
0009dce8 mov    x23, #0xbfa7
0009dcec mov    x12, #0xc8a
0009dcf0 mov    x9, #0x4bf8
0009dcf4 ldr    x8, [x8, #0x28]
0009dcf8 movk   x22, #0x9609, lsl #16
0009dcfc movk   x20, #0xd702, lsl #16
0009dd00 movk   x24, #0xaa44, lsl #16
0009dd04 movk   x25, #0x5913, lsl #16
0009dd08 movk   x11, #0xdbdc, lsl #16
0009dd0c movk   x23, #0x6166, lsl #16
0009dd10 movk   x12, #0x63fc, lsl #16
0009dd14 movk   x9, #0xd702, lsl #16
0009dd18 movk   x22, #0xe576, lsl #32
0009dd1c movk   x20, #0x9db9, lsl #32
0009dd20 movk   x24, #0x4c6b, lsl #32
0009dd24 movk   x25, #0xeeb7, lsl #32
0009dd28 movk   x11, #0xbf21, lsl #32
0009dd2c movk   x23, #0xb898, lsl #32
0009dd30 movk   x12, #0xf487, lsl #32
0009dd34 movk   x9, #0x9db9, lsl #32
0009dd38 mov    x28, x0
0009dd3c movk   x22, #0xe5b7, lsl #48
0009dd40 movk   x20, #0xdbda, lsl #48
0009dd44 movk   x24, #0x83ec, lsl #48
0009dd48 movk   x25, #0x95d6, lsl #48
0009dd4c movk   x11, #0xe5f2, lsl #48
0009dd50 movk   x23, #0xd021, lsl #48
0009dd54 movk   x12, #0xef77, lsl #48
0009dd58 movk   x9, #0xdbda, lsl #48
0009dd5c stur   x8, [x29, #-8]
0009dd60 str    x8, [sp, #0x18]
0009dd64 stur   wzr, [x29, #-0xc]
0009dd68 cmp    x9, x24
0009dd6c b.eq   #0x9df88
0009dd70 mov    x8, x9
0009dd74 mov    x27, x1
0009dd78 cmp    x9, x25
0009dd7c b.eq   #0x9de6c
0009dd80 cmp    x8, x19
0009dd84 b.eq   #0x9df38
0009dd88 cmp    x8, x23
0009dd8c b.eq   #0x9e064
0009dd90 mov    x1, x27
0009dd94 mov    x9, x21
0009dd98 cmp    x8, x20
0009dd9c b.eq   #0x9dd68
0009dda0 cmp    x8, x22
0009dda4 b.eq   #0x9dfac
0009dda8 cmp    x8, x11
0009ddac b.eq   #0x9e01c
0009ddb0 cmp    x8, x12
0009ddb4 b.eq   #0x9dee0
0009ddb8 mov    x9, #0x8d
0009ddbc movk   x9, #0x4632, lsl #16
0009ddc0 movk   x9, #0x2f89, lsl #32
0009ddc4 movk   x9, #0x105, lsl #48
0009ddc8 cmp    x8, x9
0009ddcc b.eq   #0x9dfcc
0009ddd0 mov    x10, #0x8811
0009ddd4 mov    x1, x26
0009ddd8 movk   x10, #0xc2d7, lsl #16
0009dddc movk   x10, #0x2795, lsl #32
0009dde0 movk   x10, #0x1a49, lsl #48
0009dde4 cmp    x8, x10
0009dde8 b.eq   #0x9dd68
0009ddec mov    x9, #0x3d3b
0009ddf0 movk   x9, #0x34ee, lsl #16
0009ddf4 movk   x9, #0x8516, lsl #32
0009ddf8 movk   x9, #0x2267, lsl #48
0009ddfc cmp    x8, x9
0009de00 b.eq   #0x9df7c
0009de04 mov    x9, #0x4463
0009de08 mov    x10, #0xe5bc
0009de0c movk   x9, #0xf17b, lsl #16
0009de10 movk   x10, #0x4d4c, lsl #16
0009de14 movk   x9, #0x8ffe, lsl #32
0009de18 mov    x1, x27
0009de1c movk   x9, #0x4f72, lsl #48
0009de20 movk   x10, #0xcc69, lsl #32
0009de24 movk   x10, #0x60bf, lsl #48
0009de28 cmp    x8, x10
0009de2c b.eq   #0x9dd68
0009de30 mov    x9, #0xdd29
0009de34 movk   x9, #0x2afc, lsl #16
0009de38 movk   x9, #0x8922, lsl #32
0009de3c movk   x9, #0x63b5, lsl #48
0009de40 cmp    x8, x9
0009de44 b.eq   #0x9dfa0
0009de48 mov    x10, #0x4463
0009de4c mov    x1, x27
0009de50 movk   x10, #0xf17b, lsl #16
0009de54 mov    x9, x8
0009de58 movk   x10, #0x8ffe, lsl #32
0009de5c movk   x10, #0x4f72, lsl #48
0009de60 cmp    x8, x10
0009de64 b.ne   #0x9dd68
0009de68 b      #0x9e088
0009de6c mov    x22, x28
0009de70 mov    w2, wzr
0009de74 ldp    x28, x1, [sp, #0x20]
0009de78 mov    x4, x26
0009de7c ldr    x3, [sp, #0x18]
0009de80 ldr    x8, [x28]
0009de84 mov    x0, x28
0009de88 ldr    x8, [x8, #0x640]
0009de8c blr    x8
0009de90 mov    x0, x28
0009de94 mov    x28, x22
0009de98 mov    x22, #0x9c7c
0009de9c mov    x1, xzr
0009dea0 movk   x22, #0x9609, lsl #16
0009dea4 movk   x22, #0xe576, lsl #32
0009dea8 movk   x22, #0xe5b7, lsl #48
0009deac bl     #0x9afa4
0009deb0 mov    x11, #0x8155
0009deb4 mov    x12, #0xc8a
0009deb8 movk   x11, #0xdbdc, lsl #16
0009debc movk   x12, #0x63fc, lsl #16
0009dec0 movk   x11, #0xbf21, lsl #32
0009dec4 movk   x12, #0xf487, lsl #32
0009dec8 movk   x11, #0xe5f2, lsl #48
0009decc tst    w0, #1
0009ded0 movk   x12, #0xef77, lsl #48
0009ded4 mov    x1, x27
0009ded8 csel   x9, x23, x11, ne
0009dedc b      #0x9dd68
0009dee0 ldur   w8, [x29, #-0xc]
0009dee4 mov    w1, #1
0009dee8 sxtw   x0, w8
0009deec stp    x0, x8, [sp, #0x10]
0009def0 bl     #0x148b90
0009def4 mov    x8, #0x3d3b
0009def8 mov    x12, #0xc8a
0009defc mov    x11, #0x8155
0009df00 movk   x8, #0x34ee, lsl #16
0009df04 movk   x12, #0x63fc, lsl #16
0009df08 movk   x11, #0xdbdc, lsl #16
0009df0c movk   x8, #0x8516, lsl #32
0009df10 movk   x12, #0xf487, lsl #32
0009df14 movk   x11, #0xbf21, lsl #32
0009df18 cmp    x0, #0
0009df1c movk   x8, #0x2267, lsl #48
0009df20 movk   x12, #0xef77, lsl #48
0009df24 movk   x11, #0xe5f2, lsl #48
0009df28 mov    x26, x0
0009df2c mov    x1, x27
0009df30 csel   x9, x8, x25, eq
0009df34 b      #0x9dd68
0009df38 ldp    x1, x2, [sp, #0x20]
0009df3c sub    x3, x29, #0xc
0009df40 mov    x0, x28
0009df44 bl     #0x9c724
0009df48 mov    x12, #0xc8a
0009df4c ldr    w8, [x28]
0009df50 movk   x12, #0x63fc, lsl #16
0009df54 mov    x11, #0x8155
0009df58 movk   x12, #0xf487, lsl #32
0009df5c movk   x11, #0xdbdc, lsl #16
0009df60 movk   x12, #0xef77, lsl #48
0009df64 movk   x11, #0xbf21, lsl #32
0009df68 cmp    w8, #0
0009df6c movk   x11, #0xe5f2, lsl #48
0009df70 csel   x9, x12, x24, eq
0009df74 mov    x1, x27
0009df78 b      #0x9dd68
0009df7c stur   xzr, [x29, #-0x18]
0009df80 mov    w8, #2
0009df84 b      #0x9e06c
0009df88 mov    x9, #0x8d
0009df8c mov    x1, xzr
0009df90 movk   x9, #0x4632, lsl #16
0009df94 movk   x9, #0x2f89, lsl #32
0009df98 movk   x9, #0x105, lsl #48
0009df9c b      #0x9dd68
0009dfa0 mov    w8, #3
0009dfa4 stur   xzr, [x29, #-0x18]
0009dfa8 b      #0x9e06c
0009dfac mov    x9, #0x8d
0009dfb0 ldur   w8, [x29, #-0x1c]
0009dfb4 ldur   x1, [x29, #-0x18]
0009dfb8 movk   x9, #0x4632, lsl #16
0009dfbc movk   x9, #0x2f89, lsl #32
0009dfc0 movk   x9, #0x105, lsl #48
0009dfc4 str    w8, [x28]
0009dfc8 b      #0x9dd68
0009dfcc ldur   x8, [x29, #-0x28]
0009dfd0 mov    x0, x27
0009dfd4 str    xzr, [x8]
0009dfd8 ldr    x8, [sp, #0x30]
0009dfdc str    xzr, [x8]
0009dfe0 bl     #0x148a00
0009dfe4 mov    x12, #0xc8a
0009dfe8 mov    x11, #0x8155
0009dfec mov    x9, #0x4463
0009dff0 movk   x12, #0x63fc, lsl #16
0009dff4 movk   x11, #0xdbdc, lsl #16
0009dff8 movk   x9, #0xf17b, lsl #16
0009dffc movk   x12, #0xf487, lsl #32
0009e000 movk   x11, #0xbf21, lsl #32
0009e004 movk   x9, #0x8ffe, lsl #32
0009e008 movk   x12, #0xef77, lsl #48
0009e00c movk   x11, #0xe5f2, lsl #48
0009e010 mov    x1, x27
0009e014 movk   x9, #0x4f72, lsl #48
0009e018 b      #0x9dd68
0009e01c ldur   x8, [x29, #-0x28]
0009e020 mov    x1, x27
0009e024 ldr    x9, [sp, #0x10]
0009e028 str    x9, [x8]
0009e02c ldr    x8, [sp, #0x30]
0009e030 mov    x9, #0xe5bc
0009e034 movk   x9, #0x4d4c, lsl #16
0009e038 str    x26, [x8]
0009e03c movk   x9, #0xcc69, lsl #32
0009e040 ldr    w8, [x28]
0009e044 movk   x9, #0x60bf, lsl #48
0009e048 cmp    w8, #0
0009e04c mov    x8, #0x8811
0009e050 movk   x8, #0xc2d7, lsl #16
0009e054 movk   x8, #0x2795, lsl #32
0009e058 movk   x8, #0x1a49, lsl #48
0009e05c csel   x9, x9, x8, eq
0009e060 b      #0x9dd68
0009e064 mov    w8, #0x1c
0009e068 stur   x26, [x29, #-0x18]
0009e06c stur   w8, [x29, #-0x1c]
0009e070 mov    x9, #0x9c7c
0009e074 mov    x1, x27
0009e078 movk   x9, #0x9609, lsl #16
0009e07c movk   x9, #0xe576, lsl #32
0009e080 movk   x9, #0xe5b7, lsl #48
0009e084 b      #0x9dd68
0009e088 ldr    x8, [sp, #8]
0009e08c ldr    x8, [x8, #0x28]
0009e090 ldur   x9, [x29, #-8]
0009e094 cmp    x8, x9
0009e098 b.ne   #0x9e0bc
0009e09c ldp    x20, x19, [sp, #0xb0]
0009e0a0 ldp    x22, x21, [sp, #0xa0]
0009e0a4 ldp    x24, x23, [sp, #0x90]
0009e0a8 ldp    x26, x25, [sp, #0x80]
0009e0ac ldp    x28, x27, [sp, #0x70]
0009e0b0 ldp    x29, x30, [sp, #0x60]
0009e0b4 add    sp, sp, #0xc0
0009e0b8 ret    
0009e0bc bl     #0x148a10