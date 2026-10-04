--- 0x13e030 0x13e0e4
0x13e030  mov      x9, #0xa74a
0x13e034  mov      x10, #0x5dae
0x13e038  mov      x8, #0xd2d1
0x13e03c  movk     x9, #0x5ea3, lsl #16
0x13e040  movk     x10, #0xbd6e, lsl #16
0x13e044  mov      x13, #0x8e81
0x13e048  mov      x14, #0x8e81
0x13e04c  movk     x8, #0xf825, lsl #16
0x13e050  movk     x9, #0xa04f, lsl #32
0x13e054  movk     x10, #0x6aaa, lsl #32
0x13e058  movk     x13, #0xe154, lsl #16
0x13e05c  movk     x14, #0xe154, lsl #16
0x13e060  movk     x8, #0xee0c, lsl #32
0x13e064  cmp      x0, #0
0x13e068  movk     x9, #0xfa1e, lsl #48
0x13e06c  movk     x10, #0x28f0, lsl #48
0x13e070  movk     x13, #0x3b5e, lsl #32
0x13e074  movk     x14, #0x3b5e, lsl #32
0x13e078  movk     x8, #0x5c23, lsl #48
0x13e07c  mov      w11, w1
0x13e080  csel     x12, x10, x9, eq
0x13e084  movk     x13, #0x7cc5, lsl #48
0x13e088  movk     x14, #0x7cc5, lsl #48
0x13e08c  cmp      x14, x9
0x13e090  b.eq     #0x13e0c0
0x13e094  cmp      x14, x13
0x13e098  b.eq     #0x13e0d8
0x13e09c  cmp      x14, x8
0x13e0a0  b.eq     #0x13e0e0
0x13e0a4  cmp      x14, x10
0x13e0a8  b.ne     #0x13e08c
0x13e0ac  mov      x14, #0xd2d1
0x13e0b0  movk     x14, #0xf825, lsl #16
0x13e0b4  movk     x14, #0xee0c, lsl #32
0x13e0b8  movk     x14, #0x5c23, lsl #48
0x13e0bc  b        #0x13e08c
0x13e0c0  mov      x14, #0xd2d1
0x13e0c4  str      x11, [x0]
0x13e0c8  movk     x14, #0xf825, lsl #16
0x13e0cc  movk     x14, #0xee0c, lsl #32
0x13e0d0  movk     x14, #0x5c23, lsl #48
0x13e0d4  b        #0x13e08c
0x13e0d8  mov      x14, x12
0x13e0dc  b        #0x13e08c
0x13e0e0  ret      
--- 0x13dfd0 0x13e030
0x13dfd0  b        #0x13dfd4
0x13dfd4  ldr      x10, [x0]
0x13dfd8  mov      w9, #0xd924
0x13dfdc  movk     w9, #0x75b, lsl #16
0x13dfe0  mov      x11, #-0xf31d
0x13dfe4  movk     x11, #0xfffe, lsl #16
0x13dfe8  mov      x12, #-0xb14
0x13dfec  cmp      x10, #0
0x13dff0  mov      x8, x0
0x13dff4  csel     x9, x9, x10, eq
0x13dff8  mov      w10, #0xf31d
0x13dffc  movk     w10, #1, lsl #16
0x13e000  udiv     x10, x9, x10
0x13e004  madd     x9, x10, x11, x9
0x13e008  mov      w11, #0x41a7
0x13e00c  mul      x10, x10, x12
0x13e010  madd     x9, x9, x11, x10
0x13e014  mov      w10, #0x7fffffff
0x13e018  add      x10, x9, x10
0x13e01c  cmp      x9, #0
0x13e020  csel     x9, x10, x9, lt
0x13e024  and      w0, w9, #0x7fffffff
0x13e028  str      x9, [x8]
0x13e02c  ret      
