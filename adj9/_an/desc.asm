0012cb74  stp        x29, x30, [sp, #-0x60]!
0012cb78  stp        x28, x27, [sp, #0x10]
0012cb7c  stp        x26, x25, [sp, #0x20]
0012cb80  stp        x24, x23, [sp, #0x30]
0012cb84  stp        x22, x21, [sp, #0x40]
0012cb88  stp        x20, x19, [sp, #0x50]
0012cb8c  mov        x29, sp
0012cb90  sub        sp, sp, #0x250
0012cb94  stp        x0, x1, [sp, #0x78]
0012cb98  mrs        x8, tpidr_el0
0012cb9c  str        x8, [sp, #0x38]
0012cba0  sub        x0, x29, #0x40
0012cba4  ldr        x8, [x8, #0x28]
0012cba8  mov        x19, x2
0012cbac  stur       x8, [x29, #-0x10]
0012cbb0  stp        xzr, xzr, [x29, #-0x20]
0012cbb4  stp        xzr, xzr, [x29, #-0x30]
0012cbb8  stur       wzr, [x29, #-0x34]
0012cbbc  bl         #0x148d20   ; time@plt
0012cbc0  bl         #0x148d30   ; srand@plt
0012cbc4  add        x8, x19, #0x20
0012cbc8  add        x2, x19, #0x50
0012cbcc  sub        x0, x29, #0x18
0012cbd0  mov        w1, #0x90
0012cbd4  str        x8, [sp, #0x58]
0012cbd8  bl         #0x147d3c
0012cbdc  str        x0, [sp, #0x60]
0012cbe0  add        x10, x19, #0x30
0012cbe4  add        x9, x19, #0xf0
0012cbe8  ldur       w8, [x29, #-0x18]
0012cbec  mov        x6, #0xc59
0012cbf0  movk       x6, #0x6b1, lsl #16
0012cbf4  stp        x9, x10, [sp, #0x48]
0012cbf8  add        x9, x19, #0x100
0012cbfc  mov        x10, #0xf039
0012cc00  cmp        w8, #0
0012cc04  movk       x10, #0x4336, lsl #16
0012cc08  movk       x6, #0xace6, lsl #32
0012cc0c  str        x9, [sp, #0x40]
0012cc10  mov        x9, #0xde08
0012cc14  movk       x9, #0xc909, lsl #16
0012cc18  movk       x10, #0xfc62, lsl #32
0012cc1c  movk       x9, #0x3343, lsl #32
0012cc20  movk       x10, #0xd078, lsl #48
0012cc24  movk       x9, #0xa7a4, lsl #48
0012cc28  movk       x6, #0x316a, lsl #48
0012cc2c  csel       x8, x10, x9, eq
0012cc30  stp        x19, x8, [sp, #0x88]
  ------
0012cc34  stp        x9, x8, [x29, #-0x68]
0012cc38  ldur       x8, [x29, #-0x48]
0012cc3c  mov        x25, x5
0012cc40  mov        x19, x28
0012cc44  mov        x28, x26
0012cc48  mov        x22, x21
0012cc4c  stp        x8, x7, [x29, #-0x78]
0012cc50  mov        x8, #0x47de
0012cc54  movk       x8, #0xf36d, lsl #16
0012cc58  mov        x20, x27
0012cc5c  movk       x8, #0xe159, lsl #32
0012cc60  stp        x3, x4, [x29, #-0x88]
0012cc64  movk       x8, #0x8b44, lsl #48
0012cc68  stp        x1, x2, [x29, #-0x98]
0012cc6c  cmp        x6, x8
0012cc70  stp        x17, x30, [x29, #-0xa8]
0012cc74  stp        x15, x16, [x29, #-0xb8]
0012cc78  stp        x13, x14, [x29, #-0xc8]
0012cc7c  stur       x12, [x29, #-0xd0]
0012cc80  stp        x11, x10, [x29, #-0x58]
0012cc84  b.eq       #0x12d744
0012cc88  mov        x8, #0x70c6
0012cc8c  mov        x0, x6
0012cc90  movk       x8, #0x8723, lsl #16
0012cc94  movk       x8, #0x9926, lsl #32
0012cc98  movk       x8, #0x99f3, lsl #48
0012cc9c  cmp        x6, x8
0012cca0  b.eq       #0x12daec
0012cca4  mov        x8, #0x3f0f
0012cca8  movk       x8, #0x7643, lsl #16
0012ccac  movk       x8, #0xf97a, lsl #32
0012ccb0  movk       x8, #0x9e6d, lsl #48
0012ccb4  cmp        x0, x8
0012ccb8  b.eq       #0x12d264
0012ccbc  mov        x8, #0x33c
0012ccc0  movk       x8, #0x58ee, lsl #16
0012ccc4  movk       x8, #0x22f3, lsl #32
0012ccc8  movk       x8, #0xa520, lsl #48
0012cccc  cmp        x0, x8
0012ccd0  b.eq       #0x12d1a0
0012ccd4  mov        x8, #0xde08
0012ccd8  movk       x8, #0xc909, lsl #16
0012ccdc  movk       x8, #0x3343, lsl #32
0012cce0  movk       x8, #0xa7a4, lsl #48
0012cce4  cmp        x0, x8
0012cce8  b.eq       #0x12dd34
0012ccec  mov        x8, #0xb5fd
0012ccf0  movk       x8, #0x5ecd, lsl #16
0012ccf4  movk       x8, #0x10d4, lsl #32
0012ccf8  movk       x8, #0xc150, lsl #48
0012ccfc  cmp        x0, x8
0012cd00  b.eq       #0x12d9f8
0012cd04  mov        x8, #0x4654
0012cd08  movk       x8, #0x6d04, lsl #16
0012cd0c  movk       x8, #0xc0d1, lsl #32
0012cd10  movk       x8, #0xcf0c, lsl #48
0012cd14  cmp        x0, x8
0012cd18  b.eq       #0x12dc18
0012cd1c  mov        x8, #0xf039
0012cd20  movk       x8, #0x4336, lsl #16
0012cd24  movk       x8, #0xfc62, lsl #32
0012cd28  movk       x8, #0xd078, lsl #48
0012cd2c  cmp        x0, x8
0012cd30  b.eq       #0x12db40
0012cd34  mov        x8, #0xdfb
0012cd38  movk       x8, #0x2958, lsl #16
0012cd3c  movk       x8, #0x9f87, lsl #32
0012cd40  movk       x8, #0xd5b5, lsl #48
0012cd44  cmp        x0, x8
0012cd48  b.eq       #0x12dcd4
0012cd4c  mov        x8, #0xe1c0
0012cd50  movk       x8, #0x4541, lsl #16
0012cd54  movk       x8, #0xd3cd, lsl #32
0012cd58  movk       x8, #0xd8f0, lsl #48
0012cd5c  cmp        x0, x8
0012cd60  b.eq       #0x12d1bc
0012cd64  mov        x8, #0xa361
0012cd68  movk       x8, #0x3249, lsl #16
0012cd6c  movk       x8, #0xda90, lsl #32
0012cd70  movk       x8, #0xe522, lsl #48
0012cd74  cmp        x0, x8
0012cd78  b.eq       #0x12da54
0012cd7c  mov        x8, #0xa9a2
0012cd80  movk       x8, #0xc240, lsl #16
0012cd84  movk       x8, #0x7d94, lsl #32
0012cd88  movk       x8, #0xe929, lsl #48
0012cd8c  cmp        x0, x8
0012cd90  b.eq       #0x12d210
0012cd94  mov        x8, #0xb575
0012cd98  movk       x8, #0xeaa8, lsl #16
0012cd9c  movk       x8, #0xd6e9, lsl #32
0012cda0  movk       x8, #0xe94f, lsl #48
0012cda4  cmp        x0, x8
0012cda8  b.eq       #0x12dc7c
0012cdac  mov        x8, #0xd633
0012cdb0  movk       x8, #0x7667, lsl #16
0012cdb4  movk       x8, #0x6dc6, lsl #32
0012cdb8  movk       x8, #0xeebd, lsl #48
0012cdbc  cmp        x0, x8
0012cdc0  b.eq       #0x12d1a0
0012cdc4  mov        x8, #0xc65f
0012cdc8  movk       x8, #0x71bc, lsl #16
0012cdcc  movk       x8, #0x1c29, lsl #32
0012cdd0  movk       x8, #0xf47c, lsl #48
0012cdd4  cmp        x0, x8
0012cdd8  b.eq       #0x12db90
0012cddc  mov        x8, #0xa19b
0012cde0  movk       x8, #0xe897, lsl #16
0012cde4  movk       x8, #0x49dc, lsl #32
0012cde8  movk       x8, #0xf78d, lsl #48
0012cdec  cmp        x0, x8
0012cdf0  b.eq       #0x12d670
0012cdf4  mov        x8, #0x634e
0012cdf8  movk       x8, #0xe191, lsl #16
0012cdfc  movk       x8, #0x1a1d, lsl #32
0012ce00  movk       x8, #0xf89c, lsl #48
0012ce04  cmp        x0, x8
0012ce08  b.eq       #0x12d360
0012ce0c  mov        x8, #0x14ed
0012ce10  movk       x8, #0xed0, lsl #16
0012ce14  movk       x8, #0x391e, lsl #32
0012ce18  movk       x8, #0xfac5, lsl #48
0012ce1c  cmp        x0, x8
0012ce20  b.eq       #0x12da9c
0012ce24  mov        x8, #0xf322
0012ce28  movk       x8, #0x95eb, lsl #16
0012ce2c  movk       x8, #0x19e4, lsl #32
0012ce30  movk       x8, #0x193, lsl #48
0012ce34  cmp        x0, x8
0012ce38  b.eq       #0x12d304
0012ce3c  mov        x8, #0x673a
0012ce40  movk       x8, #0x8699, lsl #16
0012ce44  movk       x8, #0x489d, lsl #32
0012ce48  movk       x8, #0x45d, lsl #48
0012ce4c  cmp        x0, x8
0012ce50  b.eq       #0x12d9a0
0012ce54  mov        x8, #0x208a
0012ce58  movk       x8, #0x45c, lsl #16
0012ce5c  movk       x8, #0xb244, lsl #32
0012ce60  movk       x8, #0x1876, lsl #48
0012ce64  cmp        x0, x8
0012ce68  b.eq       #0x12d3e8
0012ce6c  mov        x8, #0x6c7b
0012ce70  movk       x8, #0xdbb6, lsl #16
0012ce74  movk       x8, #0x615, lsl #32
0012ce78  movk       x8, #0x1904, lsl #48
0012ce7c  cmp        x0, x8
0012ce80  b.eq       #0x12d798
0012ce84  mov        x8, #0xc708
0012ce88  movk       x8, #0x27d8, lsl #16
0012ce8c  movk       x8, #0x694f, lsl #32
0012ce90  movk       x8, #0x1e6e, lsl #48
0012ce94  cmp        x0, x8
0012ce98  b.eq       #0x12d888
0012ce9c  mov        x8, #0xb550
0012cea0  movk       x8, #0x51c5, lsl #16
0012cea4  movk       x8, #0x9d7c, lsl #32
0012cea8  movk       x8, #0x2481, lsl #48
0012ceac  cmp        x0, x8
0012ceb0  b.eq       #0x12d940
0012ceb4  mov        x8, #0x57
0012ceb8  movk       x8, #0x430f, lsl #16
0012cebc  movk       x8, #0x16c3, lsl #32
0012cec0  movk       x8, #0x24f8, lsl #48
0012cec4  cmp        x0, x8
0012cec8  b.eq       #0x12d49c
0012cecc  mov        x8, #0xd7bb
0012ced0  movk       x8, #0xd9f9, lsl #16
0012ced4  movk       x8, #0xffd, lsl #32
0012ced8  movk       x8, #0x302e, lsl #48
0012cedc  cmp        x0, x8
0012cee0  b.eq       #0x12d2b4
0012cee4  ldp        x8, x7, [x29, #-0x78]
0012cee8  mov        x27, #0xc59
0012ceec  mov        x21, x20
0012cef0  movk       x27, #0x6b1, lsl #16
0012cef4  mov        x26, x22
0012cef8  ldp        x11, x10, [x29, #-0x58]
0012cefc  stur       x8, [x29, #-0x48]
0012cf00  movk       x27, #0xace6, lsl #32
0012cf04  ldp        x9, x8, [x29, #-0x68]
0012cf08  movk       x27, #0x316a, lsl #48
0012cf0c  stp        x28, x24, [x29, #-0xe0]
0012cf10  ldp        x12, x13, [x29, #-0xd0]
0012cf14  mov        x5, x25
0012cf18  cmp        x0, x27
0012cf1c  ldp        x14, x15, [x29, #-0xc0]
0012cf20  mov        x27, x20
0012cf24  mov        x21, x22
0012cf28  ldp        x16, x17, [x29, #-0xb0]
0012cf2c  mov        x26, x28
0012cf30  mov        x28, x19
0012cf34  ldp        x30, x1, [x29, #-0xa0]
0012cf38  stur       x19, [x29, #-0xf8]
0012cf3c  mov        x25, x19
0012cf40  ldp        x2, x3, [x29, #-0x90]
0012cf44  str        x5, [sp, #0x130]
0012cf48  ldur       x4, [x29, #-0x80]
0012cf4c  ldr        x6, [sp, #0x90]
0012cf50  b.eq       #0x12cc34
0012cf54  ldp        x8, x7, [x29, #-0x78]
0012cf58  mov        x19, x23
0012cf5c  mov        x27, #0x76fc
0012cf60  ldp        x3, x23, [x29, #-0x100]
0012cf64  mov        x26, x22
0012cf68  mov        x24, x19
0012cf6c  mov        x6, #0xa19b
0012cf70  movk       x27, #0x52b4, lsl #16
0012cf74  ldp        x26, x24, [x29, #-0xe0]
0012cf78  stur       x8, [x29, #-0x48]
0012cf7c  movk       x6, #0xe897, lsl #16
0012cf80  ldp        x9, x8, [x29, #-0x68]
0012cf84  movk       x27, #0xdab3, lsl #32
0012cf88  mov        x21, x20
0012cf8c  ldp        x11, x10, [x29, #-0x58]
0012cf90  movk       x6, #0x49dc, lsl #32
0012cf94  movk       x27, #0x44ee, lsl #48
0012cf98  ldp        x12, x14, [sp, #0x100]
0012cf9c  movk       x6, #0xf78d, lsl #48
0012cfa0  cmp        x0, x27
0012cfa4  ldp        x15, x13, [sp, #0x110]
0012cfa8  mov        x27, x20
0012cfac  mov        x21, x22
0012cfb0  ldp        x16, x17, [sp, #0x120]
0012cfb4  mov        x28, x23
0012cfb8  mov        x23, x19
0012cfbc  ldp        x30, x1, [sp, #0x138]
0012cfc0  ldp        x4, x5, [x29, #-0xf0]
0012cfc4  ldr        x2, [sp, #0x148]
0012cfc8  b.eq       #0x12cc34
0012cfcc  mov        x8, #0x5e5d
0012cfd0  movk       x8, #0xe6ee, lsl #16
0012cfd4  movk       x8, #0xcd9a, lsl #32
0012cfd8  movk       x8, #0x450f, lsl #48
0012cfdc  cmp        x0, x8
0012cfe0  b.eq       #0x12d6e0
0012cfe4  mov        x8, #0xa791
0012cfe8  mov        x23, x19
0012cfec  ldp        x26, x24, [x29, #-0xe0]
0012cff0  movk       x8, #0x3c47, lsl #16
0012cff4  movk       x8, #0x5e65, lsl #32
0012cff8  movk       x8, #0x554b, lsl #48
0012cffc  cmp        x0, x8
0012d000  b.eq       #0x12d7fc
0012d004  mov        x8, #0xbd96
0012d008  movk       x8, #0x4b9b, lsl #16
0012d00c  movk       x8, #0x9445, lsl #32
0012d010  movk       x8, #0x5c58, lsl #48
0012d014  cmp        x0, x8
0012d018  b.eq       #0x12d5c8
0012d01c  ldp        x8, x25, [sp, #0x120]
0012d020  mov        x27, #0xbf16
0012d024  mov        x6, #0x9dcf
0012d028  ldp        x23, x28, [sp, #0x140]
0012d02c  movk       x27, #0xb73c, lsl #16
0012d030  movk       x6, #0x3090, lsl #16
0012d034  ldp        x21, x11, [x29, #-0xf0]
0012d038  stur       x8, [x29, #-0x48]
0012d03c  movk       x27, #0x8d1a, lsl #32
0012d040  ldur       x26, [x29, #-0x100]
0012d044  movk       x6, #0x846e, lsl #32
0012d048  ldr        x24, [sp, #0x138]
0012d04c  movk       x27, #0x634a, lsl #48
0012d050  ldp        x8, x7, [sp, #0x108]
0012d054  movk       x6, #0x8f48, lsl #48
0012d058  cmp        x0, x27
0012d05c  ldp        x12, x13, [x29, #-0xd0]
0012d060  mov        x27, x21
0012d064  mov        x21, x26
0012d068  ldp        x14, x15, [x29, #-0xc0]
0012d06c  mov        x26, x28
0012d070  mov        x28, x23
0012d074  ldp        x16, x17, [x29, #-0xb0]
0012d078  mov        x23, x24
0012d07c  mov        x24, x25
0012d080  ldp        x30, x1, [x29, #-0xa0]
0012d084  ldp        x2, x3, [x29, #-0x90]
0012d088  ldr        x9, [sp, #0x118]
0012d08c  ldr        x10, [sp, #0x100]
0012d090  ldur       x4, [x29, #-0x80]
0012d094  ldr        x5, [sp, #0x130]
0012d098  b.eq       #0x12cc34
0012d09c  mov        x8, #0x63e0
0012d0a0  movk       x8, #0x9588, lsl #16
0012d0a4  movk       x8, #0xab50, lsl #32
0012d0a8  movk       x8, #0x6525, lsl #48
0012d0ac  cmp        x0, x8
0012d0b0  b.eq       #0x12d620
0012d0b4  mov        x8, #0xbb81
0012d0b8  ldr        x25, [sp, #0x130]
0012d0bc  ldp        x28, x24, [x29, #-0xe0]
0012d0c0  movk       x8, #0x8da3, lsl #16
0012d0c4  mov        x23, x19
0012d0c8  movk       x8, #0x7388, lsl #32
0012d0cc  movk       x8, #0x655b, lsl #48
0012d0d0  cmp        x0, x8
0012d0d4  b.eq       #0x12d440
0012d0d8  mov        x8, #0x178
0012d0dc  movk       x8, #0x6e1b, lsl #16
0012d0e0  movk       x8, #0xa1, lsl #32
0012d0e4  movk       x8, #0x709d, lsl #48
0012d0e8  cmp        x0, x8
0012d0ec  b.eq       #0x12d53c
0012d0f0  mov        x8, #0x830b
0012d0f4  movk       x8, #0xa8ee, lsl #16
0012d0f8  movk       x8, #0x9027, lsl #32
0012d0fc  movk       x8, #0x7b7e, lsl #48
0012d100  cmp        x0, x8
0012d104  b.eq       #0x12d58c
0012d108  mov        x8, #0xe526
0012d10c  movk       x8, #0xc774, lsl #16
0012d110  movk       x8, #0xaacf, lsl #32
0012d114  movk       x8, #0x7d8f, lsl #48
0012d118  cmp        x0, x8
0012d11c  b.eq       #0x12d4ec
0012d120  ldp        x8, x7, [x29, #-0x78]
0012d124  mov        x27, #0x9dcf
0012d128  mov        x2, x23
0012d12c  ldur       x23, [x29, #-0xf8]
0012d130  mov        x1, x24
0012d134  movk       x27, #0x3090, lsl #16
0012d138  mov        x24, x2
0012d13c  mov        x5, x25
0012d140  mov        x25, x1
0012d144  stur       x8, [x29, #-0x48]
0012d148  movk       x27, #0x846e, lsl #32
0012d14c  ldp        x9, x8, [x29, #-0x68]
0012d150  mov        x21, x20
0012d154  mov        x26, x22
0012d158  ldp        x11, x10, [x29, #-0x58]
0012d15c  movk       x27, #0x8f48, lsl #48
0012d160  mov        x6, x0
0012d164  ldp        x12, x13, [x29, #-0xd0]
0012d168  cmp        x0, x27
0012d16c  mov        x27, x20
0012d170  ldp        x14, x15, [x29, #-0xc0]
0012d174  mov        x21, x22
0012d178  mov        x26, x28
0012d17c  ldp        x16, x17, [x29, #-0xb0]
0012d180  mov        x28, x23
0012d184  mov        x23, x24
0012d188  ldp        x30, x1, [x29, #-0xa0]
0012d18c  mov        x24, x25
0012d190  ldp        x2, x3, [x29, #-0x90]
0012d194  ldur       x4, [x29, #-0x80]
0012d198  b.ne       #0x12cc34
0012d19c  b          #0x12dda8
  ------
0012d1a0  mov        w8, #4
0012d1a4  mov        x27, x20
0012d1a8  mov        x21, x22
0012d1ac  mov        x26, x28
0012d1b0  mov        x28, x19
0012d1b4  str        xzr, [sp, #0xf8]
0012d1b8  b          #0x12d5a4
  ------
0012d1bc  mov        w8, #4
0012d1c0  ldur       x4, [x29, #-0x80]
0012d1c4  ldp        x11, x10, [x29, #-0x58]
0012d1c8  stp        xzr, xzr, [sp, #0xf0]
0012d1cc  mov        x27, x20
0012d1d0  str        w8, [sp, #0xe4]
0012d1d4  mov        x21, x22
0012d1d8  ldp        x8, x7, [x29, #-0x78]
0012d1dc  str        xzr, [sp, #0xe8]
0012d1e0  mov        x26, x28
0012d1e4  ldp        x12, x13, [x29, #-0xd0]
0012d1e8  str        xzr, [sp, #0xd8]
0012d1ec  mov        x28, x19
0012d1f0  stur       x8, [x29, #-0x48]
0012d1f4  mov        x5, x25
0012d1f8  ldp        x9, x8, [x29, #-0x68]
0012d1fc  ldp        x14, x15, [x29, #-0xc0]
0012d200  ldp        x16, x17, [x29, #-0xb0]
0012d204  ldp        x30, x1, [x29, #-0xa0]
0012d208  ldp        x2, x3, [x29, #-0x90]
0012d20c  b          #0x12d8ec
  ------
0012d210  sub        x0, x29, #0x18
0012d214  mov        w1, wzr
0012d218  mov        x2, xzr
0012d21c  bl         #0x147d3c
0012d220  ldur       w8, [x29, #-0x18]
0012d224  mov        x9, #0x63e0
0012d228  movk       x9, #0x9588, lsl #16
0012d22c  str        x0, [sp, #0x108]
0012d230  movk       x9, #0xab50, lsl #32
0012d234  mov        x27, x20
0012d238  cmp        w8, #0
0012d23c  mov        x8, #0xa361
0012d240  movk       x8, #0x3249, lsl #16
0012d244  movk       x9, #0x6525, lsl #48
0012d248  movk       x8, #0xda90, lsl #32
0012d24c  mov        x21, x22
0012d250  movk       x8, #0xe522, lsl #48
0012d254  mov        x26, x28
0012d258  mov        x28, x19
0012d25c  csel       x6, x8, x9, eq
0012d260  b          #0x12dbe4
  ------
0012d264  mov        w8, #4
0012d268  ldur       x4, [x29, #-0x80]
0012d26c  ldp        x11, x10, [x29, #-0x58]
0012d270  stp        xzr, xzr, [sp, #0xf0]
0012d274  mov        x27, x20
0012d278  str        w8, [sp, #0xe4]
0012d27c  mov        x21, x22
0012d280  ldp        x8, x7, [x29, #-0x78]
0012d284  str        xzr, [sp, #0xe8]
0012d288  mov        x26, x28
0012d28c  ldp        x12, x13, [x29, #-0xd0]
0012d290  mov        x28, x19
0012d294  mov        x5, x25
0012d298  stur       x8, [x29, #-0x48]
0012d29c  ldp        x9, x8, [x29, #-0x68]
0012d2a0  ldp        x14, x15, [x29, #-0xc0]
0012d2a4  ldp        x16, x17, [x29, #-0xb0]
0012d2a8  ldp        x30, x1, [x29, #-0xa0]
0012d2ac  ldp        x2, x3, [x29, #-0x90]
0012d2b0  b          #0x12d8e4
  ------
0012d2b4  sub        x0, x29, #0x18
0012d2b8  mov        w1, #4
0012d2bc  ldr        x2, [sp, #0x58]
0012d2c0  bl         #0x147d3c
0012d2c4  ldur       w8, [x29, #-0x18]
0012d2c8  mov        x9, #0xa791
0012d2cc  movk       x9, #0x3c47, lsl #16
0012d2d0  str        x0, [sp, #0x148]
0012d2d4  movk       x9, #0x5e65, lsl #32
0012d2d8  mov        x27, x20
0012d2dc  cmp        w8, #0
0012d2e0  mov        x8, #0xbd96
0012d2e4  movk       x8, #0x4b9b, lsl #16
0012d2e8  mov        x21, x22
0012d2ec  movk       x8, #0x9445, lsl #32
0012d2f0  mov        x26, x28
0012d2f4  mov        x28, x19
0012d2f8  movk       x8, #0x5c58, lsl #48
0012d2fc  movk       x9, #0x554b, lsl #48
0012d300  b          #0x12dbe0
  ------
0012d304  ldp        x8, x7, [x29, #-0x78]
0012d308  mov        x26, x28
0012d30c  mov        x28, x19
0012d310  ldp        x11, x10, [x29, #-0x58]
0012d314  mov        x6, #0xa19b
0012d318  mov        x27, x20
0012d31c  stur       x8, [x29, #-0x48]
0012d320  ldr        x0, [sp, #0x80]
0012d324  ldp        x9, x8, [x29, #-0x68]
0012d328  movk       x6, #0xe897, lsl #16
0012d32c  mov        x21, x22
0012d330  ldp        x13, x12, [sp, #0xf0]
0012d334  movk       x6, #0x49dc, lsl #32
0012d338  ldp        x16, x15, [sp, #0xd0]
0012d33c  movk       x6, #0xf78d, lsl #48
0012d340  ldp        x30, x17, [sp, #0xc0]
0012d344  ldp        x2, x1, [sp, #0xb0]
0012d348  ldp        x4, x3, [sp, #0xa0]
0012d34c  ldr        w19, [sp, #0xe4]
0012d350  ldr        x14, [sp, #0xe8]
0012d354  ldr        x5, [sp, #0x98]
0012d358  str        w19, [x0]
0012d35c  b          #0x12cc34
  ------
0012d360  ldp        x8, x1, [sp, #0x110]
0012d364  sub        x0, x29, #0x18
0012d368  mov        w2, #0xb
0012d36c  ldr        x9, [sp, #0x108]
0012d370  ldp        x5, x4, [x29, #-0xf0]
0012d374  stp        x8, x9, [sp, #0x20]
0012d378  ldr        x8, [sp, #0x120]
0012d37c  ldr        x9, [sp, #0x128]
0012d380  ldr        x3, [sp, #0x60]
0012d384  str        x8, [sp, #0x18]
0012d388  ldr        x8, [sp, #0x138]
0012d38c  ldur       x6, [x29, #-0x100]
0012d390  stp        x8, x9, [sp, #8]
0012d394  ldp        x8, x7, [sp, #0x140]
0012d398  str        x8, [sp]
0012d39c  bl         #0x100094
0012d3a0  ldur       w8, [x29, #-0x18]
0012d3a4  mov        x9, #0xd633
0012d3a8  movk       x9, #0x7667, lsl #16
0012d3ac  mov        x27, x20
0012d3b0  movk       x9, #0x6dc6, lsl #32
0012d3b4  mov        x21, x22
0012d3b8  cmp        w8, #0
0012d3bc  ldur       x8, [x29, #-0x78]
0012d3c0  movk       x9, #0xeebd, lsl #48
0012d3c4  mov        x26, x28
0012d3c8  mov        x28, x19
0012d3cc  stur       x8, [x29, #-0x48]
0012d3d0  mov        x8, #0xb575
0012d3d4  movk       x8, #0xeaa8, lsl #16
0012d3d8  movk       x8, #0xd6e9, lsl #32
0012d3dc  movk       x8, #0xe94f, lsl #48
0012d3e0  csel       x6, x8, x9, eq
0012d3e4  b          #0x12dbec
  ------
0012d3e8  ldp        x8, x7, [x29, #-0x78]
0012d3ec  mov        w0, #4
0012d3f0  stp        xzr, xzr, [sp, #0xf0]
0012d3f4  ldp        x11, x10, [x29, #-0x58]
0012d3f8  str        xzr, [sp, #0xe8]
0012d3fc  mov        x27, x20
0012d400  stur       x8, [x29, #-0x48]
0012d404  ldur       x4, [x29, #-0x80]
0012d408  ldp        x9, x8, [x29, #-0x68]
0012d40c  stp        xzr, xzr, [sp, #0xd0]
0012d410  mov        x21, x22
0012d414  ldp        x12, x13, [x29, #-0xd0]
0012d418  stp        xzr, xzr, [sp, #0xc0]
0012d41c  mov        x26, x28
0012d420  ldp        x14, x15, [x29, #-0xc0]
0012d424  mov        x28, x19
0012d428  mov        x5, x25
0012d42c  ldp        x16, x17, [x29, #-0xb0]
0012d430  str        w0, [sp, #0xe4]
0012d434  ldp        x30, x1, [x29, #-0xa0]
0012d438  ldp        x2, x3, [x29, #-0x90]
0012d43c  b          #0x12d904
  ------
0012d440  ldp        x1, x27, [sp, #0x78]
0012d444  ldr        x2, [sp, #0x88]
0012d448  ldr        x3, [sp, #0x68]
0012d44c  ldr        x4, [sp, #0x100]
0012d450  mov        x0, x27
0012d454  bl         #0xbac8
0012d458  ldr        w8, [x27]
0012d45c  mov        x9, #0xbf16
0012d460  mov        x26, x28
0012d464  ldur       x28, [x29, #-0xf8]
0012d468  movk       x9, #0xb73c, lsl #16
0012d46c  mov        x27, x20
0012d470  cmp        w8, #0
0012d474  ldur       x8, [x29, #-0x78]
0012d478  movk       x9, #0x8d1a, lsl #32
0012d47c  mov        x21, x22
0012d480  movk       x9, #0x634a, lsl #48
0012d484  stur       x8, [x29, #-0x48]
0012d488  mov        x8, #0x76fc
0012d48c  movk       x8, #0x52b4, lsl #16
0012d490  movk       x8, #0xdab3, lsl #32
0012d494  movk       x8, #0x44ee, lsl #48
0012d498  b          #0x12d7f4
  ------
0012d49c  ldur       x2, [x29, #-0x20]
0012d4a0  sub        x0, x29, #0x18
0012d4a4  ldr        w1, [sp, #0x74]
0012d4a8  bl         #0x147d3c
0012d4ac  ldur       w8, [x29, #-0x18]
0012d4b0  mov        x9, #0xb550
0012d4b4  movk       x9, #0x51c5, lsl #16
0012d4b8  str        x0, [sp, #0x138]
0012d4bc  movk       x9, #0x9d7c, lsl #32
0012d4c0  mov        x27, x20
0012d4c4  cmp        w8, #0
0012d4c8  mov        x8, #0x673a
0012d4cc  movk       x8, #0x8699, lsl #16
0012d4d0  mov        x21, x22
0012d4d4  movk       x8, #0x489d, lsl #32
0012d4d8  mov        x26, x28
0012d4dc  mov        x28, x19
0012d4e0  movk       x8, #0x45d, lsl #48
0012d4e4  movk       x9, #0x2481, lsl #48
0012d4e8  b          #0x12dbe0
  ------
0012d4ec  sub        x0, x29, #0x18
0012d4f0  mov        w1, #0x20
0012d4f4  ldr        x2, [sp, #0x50]
0012d4f8  bl         #0x147d3c
0012d4fc  ldur       w8, [x29, #-0x18]
0012d500  mov        x9, #0xd7bb
0012d504  mov        x26, x28
0012d508  ldur       x28, [x29, #-0xf8]
0012d50c  movk       x9, #0xd9f9, lsl #16
0012d510  stur       x0, [x29, #-0x100]
0012d514  cmp        w8, #0
0012d518  mov        x8, #0xb5fd
0012d51c  movk       x8, #0x5ecd, lsl #16
0012d520  movk       x9, #0xffd, lsl #32
0012d524  movk       x8, #0x10d4, lsl #32
0012d528  mov        x27, x20
0012d52c  mov        x21, x22
0012d530  movk       x8, #0xc150, lsl #48
0012d534  movk       x9, #0x302e, lsl #48
0012d538  b          #0x12dbe0
  ------
0012d53c  sub        x0, x29, #0x18
0012d540  sub        x2, x29, #0x34
0012d544  mov        w1, #4
0012d548  bl         #0x147d3c
0012d54c  ldur       w8, [x29, #-0x18]
0012d550  mov        x9, #0xa9a2
0012d554  mov        x26, x28
0012d558  ldur       x28, [x29, #-0xf8]
0012d55c  movk       x9, #0xc240, lsl #16
0012d560  str        x0, [sp, #0x110]
0012d564  cmp        w8, #0
0012d568  mov        x8, #0x3f0f
0012d56c  movk       x8, #0x7643, lsl #16
0012d570  movk       x9, #0x7d94, lsl #32
0012d574  movk       x8, #0xf97a, lsl #32
0012d578  mov        x27, x20
0012d57c  mov        x21, x22
0012d580  movk       x8, #0x9e6d, lsl #48
0012d584  movk       x9, #0xe929, lsl #48
0012d588  b          #0x12dbe0
  ------
0012d58c  mov        w8, #2
0012d590  mov        x26, x28
0012d594  ldur       x28, [x29, #-0xf8]
0012d598  str        xzr, [sp, #0xf8]
0012d59c  mov        x27, x20
0012d5a0  mov        x21, x22
  ------
0012d5a4  str        w8, [sp, #0xe4]
0012d5a8  ldp        x8, x7, [x29, #-0x78]
0012d5ac  mov        x5, x25
0012d5b0  ldp        x11, x10, [x29, #-0x58]
0012d5b4  stur       x8, [x29, #-0x48]
0012d5b8  ldur       x4, [x29, #-0x80]
0012d5bc  ldp        x9, x8, [x29, #-0x68]
0012d5c0  ldp        x12, x13, [x29, #-0xd0]
0012d5c4  b          #0x12d8c4
  ------
0012d5c8  ldp        x8, x7, [x29, #-0x78]
0012d5cc  mov        w0, #4
0012d5d0  stp        xzr, xzr, [sp, #0xf0]
0012d5d4  ldp        x11, x10, [x29, #-0x58]
0012d5d8  str        xzr, [sp, #0xe8]
0012d5dc  mov        x27, x20
0012d5e0  stur       x8, [x29, #-0x48]
0012d5e4  ldur       x28, [x29, #-0xf8]
0012d5e8  ldp        x9, x8, [x29, #-0x68]
0012d5ec  stp        xzr, xzr, [sp, #0xd0]
0012d5f0  mov        x21, x22
0012d5f4  ldp        x12, x13, [x29, #-0xd0]
0012d5f8  stp        xzr, xzr, [sp, #0xc0]
0012d5fc  ldp        x14, x15, [x29, #-0xc0]
0012d600  str        xzr, [sp, #0xb8]
0012d604  ldp        x16, x17, [x29, #-0xb0]
0012d608  str        w0, [sp, #0xe4]
0012d60c  ldp        x30, x1, [x29, #-0xa0]
0012d610  ldp        x2, x3, [x29, #-0x90]
0012d614  ldur       x4, [x29, #-0x80]
0012d618  ldr        x5, [sp, #0x130]
0012d61c  b          #0x12d90c
  ------
0012d620  mov        w8, #4
0012d624  ldur       x28, [x29, #-0xf8]
0012d628  ldp        x26, x24, [x29, #-0xe0]
0012d62c  stp        xzr, xzr, [sp, #0xf0]
0012d630  mov        x27, x20
0012d634  str        w8, [sp, #0xe4]
0012d638  ldur       x4, [x29, #-0x80]
0012d63c  ldp        x8, x7, [x29, #-0x78]
0012d640  mov        x21, x22
0012d644  mov        x23, x19
0012d648  ldp        x11, x10, [x29, #-0x58]
0012d64c  stur       x8, [x29, #-0x48]
0012d650  ldr        x5, [sp, #0x130]
0012d654  ldp        x9, x8, [x29, #-0x68]
0012d658  ldp        x12, x13, [x29, #-0xd0]
0012d65c  ldp        x14, x15, [x29, #-0xc0]
0012d660  ldp        x16, x17, [x29, #-0xb0]
0012d664  ldp        x30, x1, [x29, #-0xa0]
0012d668  ldp        x2, x3, [x29, #-0x90]
0012d66c  b          #0x12d8dc
  ------
0012d670  sub        x0, x29, #0x14
0012d674  ldr        x1, [sp, #0x78]
0012d678  ldr        x2, [sp, #0x88]
0012d67c  bl         #0xae94
0012d680  ldp        x3, x4, [x29, #-0x88]
0012d684  mov        x6, #0x9dcf
0012d688  mov        x11, x25
0012d68c  ldp        x1, x2, [x29, #-0x98]
0012d690  movk       x6, #0x3090, lsl #16
0012d694  mov        x5, x25
0012d698  ldp        x17, x30, [x29, #-0xa8]
0012d69c  movk       x6, #0x846e, lsl #32
0012d6a0  mov        x27, x4
0012d6a4  ldp        x15, x16, [x29, #-0xb8]
0012d6a8  mov        x21, x3
0012d6ac  mov        x26, x2
0012d6b0  ldp        x13, x14, [x29, #-0xc8]
0012d6b4  mov        x28, x1
0012d6b8  mov        x23, x30
0012d6bc  ldur       x12, [x29, #-0xd0]
0012d6c0  mov        x24, x17
0012d6c4  stur       x16, [x29, #-0x48]
0012d6c8  mov        x7, x15
0012d6cc  mov        x9, x13
0012d6d0  movk       x6, #0x8f48, lsl #48
0012d6d4  mov        x8, x14
0012d6d8  mov        x10, x12
0012d6dc  b          #0x12cc34
  ------
0012d6e0  ldp        x8, x7, [x29, #-0x78]
0012d6e4  mov        w0, #4
0012d6e8  stp        xzr, xzr, [sp, #0xf0]
0012d6ec  ldp        x26, x24, [x29, #-0xe0]
0012d6f0  str        xzr, [sp, #0xe8]
0012d6f4  mov        x27, x20
0012d6f8  stur       x8, [x29, #-0x48]
0012d6fc  ldur       x28, [x29, #-0xf8]
0012d700  ldp        x9, x8, [x29, #-0x68]
0012d704  stp        xzr, xzr, [sp, #0xd0]
0012d708  mov        x21, x22
0012d70c  ldp        x11, x10, [x29, #-0x58]
0012d710  stp        xzr, xzr, [sp, #0xc0]
0012d714  mov        x23, x19
0012d718  ldp        x12, x13, [x29, #-0xd0]
0012d71c  stp        xzr, xzr, [sp, #0xb0]
0012d720  ldp        x14, x15, [x29, #-0xc0]
0012d724  str        xzr, [sp, #0xa8]
0012d728  ldp        x16, x17, [x29, #-0xb0]
0012d72c  str        w0, [sp, #0xe4]
0012d730  ldp        x30, x1, [x29, #-0xa0]
0012d734  ldp        x2, x3, [x29, #-0x90]
0012d738  ldur       x4, [x29, #-0x80]
0012d73c  ldr        x5, [sp, #0x130]
0012d740  b          #0x12d91c
  ------
0012d744  sub        x0, x29, #0x18
0012d748  ldr        x1, [sp, #0x118]
0012d74c  ldr        x2, [sp, #0x100]
0012d750  bl         #0x147e3c
0012d754  ldur       w8, [x29, #-0x18]
0012d758  mov        x9, #0xbb81
0012d75c  movk       x9, #0x8da3, lsl #16
0012d760  mov        x27, x20
0012d764  movk       x9, #0x7388, lsl #32
0012d768  mov        x21, x22
0012d76c  cmp        w8, #0
0012d770  ldur       x8, [x29, #-0x78]
0012d774  mov        x26, x28
0012d778  mov        x28, x19
0012d77c  movk       x9, #0x655b, lsl #48
0012d780  stur       x8, [x29, #-0x48]
0012d784  mov        x8, #0xc708
0012d788  movk       x8, #0x27d8, lsl #16
0012d78c  movk       x8, #0x694f, lsl #32
0012d790  movk       x8, #0x1e6e, lsl #48
0012d794  b          #0x12d7f4
  ------
0012d798  ldp        x27, x8, [sp, #0x80]
0012d79c  sub        x3, x29, #0x20
0012d7a0  sub        x4, x29, #0x28
0012d7a4  ldr        x1, [sp, #0x78]
0012d7a8  mov        x0, x27
0012d7ac  ldr        x2, [x8, #0x10]
0012d7b0  bl         #0x12c8a8
0012d7b4  ldr        w8, [x27]
0012d7b8  mov        x9, #0x14ed
0012d7bc  movk       x9, #0xed0, lsl #16
0012d7c0  mov        x27, x20
0012d7c4  movk       x9, #0x391e, lsl #32
0012d7c8  mov        x21, x22
0012d7cc  cmp        w8, #0
0012d7d0  ldur       x8, [x29, #-0x78]
0012d7d4  mov        x26, x28
0012d7d8  mov        x28, x19
0012d7dc  movk       x9, #0xfac5, lsl #48
0012d7e0  stur       x8, [x29, #-0x48]
0012d7e4  mov        x8, #0x4654
0012d7e8  movk       x8, #0x6d04, lsl #16
0012d7ec  movk       x8, #0xc0d1, lsl #32
0012d7f0  movk       x8, #0xcf0c, lsl #48
  ------
0012d7f4  csel       x6, x9, x8, eq
0012d7f8  b          #0x12dbec
  ------
0012d7fc  ldur       w8, [x29, #-0x28]
0012d800  sub        x0, x29, #0x18
0012d804  sub        x2, x29, #0x2c
0012d808  mov        w1, #4
0012d80c  str        w8, [sp, #0x74]
0012d810  rev        w8, w8
0012d814  stur       w8, [x29, #-0x2c]
0012d818  bl         #0x147d3c
0012d81c  ldur       w8, [x29, #-0x18]
0012d820  mov        x9, #0x57
0012d824  movk       x9, #0x430f, lsl #16
0012d828  ldur       x28, [x29, #-0xf8]
0012d82c  movk       x9, #0x16c3, lsl #32
0012d830  ldur       x4, [x29, #-0x80]
0012d834  cmp        w8, #0
0012d838  mov        x8, #0x208a
0012d83c  movk       x8, #0x45c, lsl #16
0012d840  movk       x9, #0x24f8, lsl #48
0012d844  movk       x8, #0xb244, lsl #32
0012d848  ldr        x5, [sp, #0x130]
0012d84c  movk       x8, #0x1876, lsl #48
0012d850  str        x0, [sp, #0x140]
0012d854  csel       x6, x9, x8, eq
0012d858  mov        x27, x20
0012d85c  ldp        x8, x7, [x29, #-0x78]
0012d860  mov        x21, x22
0012d864  ldp        x11, x10, [x29, #-0x58]
0012d868  stur       x8, [x29, #-0x48]
0012d86c  ldp        x9, x8, [x29, #-0x68]
0012d870  ldp        x12, x13, [x29, #-0xd0]
0012d874  ldp        x14, x15, [x29, #-0xc0]
0012d878  ldp        x16, x17, [x29, #-0xb0]
0012d87c  ldp        x30, x1, [x29, #-0xa0]
0012d880  ldp        x2, x3, [x29, #-0x90]
0012d884  b          #0x12cc34
  ------
0012d888  mov        w8, #4
0012d88c  ldr        x0, [sp, #0x100]
0012d890  ldp        x11, x10, [x29, #-0x58]
0012d894  mov        x27, x20
0012d898  mov        x21, x22
0012d89c  str        w8, [sp, #0xe4]
0012d8a0  ldur       x4, [x29, #-0x80]
0012d8a4  ldp        x8, x7, [x29, #-0x78]
0012d8a8  mov        x26, x28
0012d8ac  mov        x28, x19
0012d8b0  ldp        x12, x13, [x29, #-0xd0]
0012d8b4  mov        x5, x25
0012d8b8  str        x0, [sp, #0xf8]
0012d8bc  stur       x8, [x29, #-0x48]
0012d8c0  ldp        x9, x8, [x29, #-0x68]
  ------
0012d8c4  ldp        x14, x15, [x29, #-0xc0]
0012d8c8  ldp        x16, x17, [x29, #-0xb0]
0012d8cc  ldp        x30, x1, [x29, #-0xa0]
0012d8d0  ldp        x2, x3, [x29, #-0x90]
0012d8d4  ldr        x0, [sp, #0x118]
0012d8d8  str        x0, [sp, #0xf0]
  ------
0012d8dc  ldr        x0, [sp, #0x108]
0012d8e0  str        x0, [sp, #0xe8]
  ------
0012d8e4  ldr        x0, [sp, #0x110]
0012d8e8  str        x0, [sp, #0xd8]
  ------
0012d8ec  ldr        x0, [sp, #0x120]
0012d8f0  str        x0, [sp, #0xd0]
  ------
0012d8f4  ldr        x0, [sp, #0x128]
0012d8f8  str        x0, [sp, #0xc8]
  ------
0012d8fc  ldr        x0, [sp, #0x138]
0012d900  str        x0, [sp, #0xc0]
  ------
0012d904  ldr        x0, [sp, #0x140]
0012d908  str        x0, [sp, #0xb8]
  ------
0012d90c  ldr        x0, [sp, #0x148]
0012d910  str        x0, [sp, #0xb0]
  ------
0012d914  ldur       x0, [x29, #-0x100]
0012d918  str        x0, [sp, #0xa8]
  ------
0012d91c  ldur       x0, [x29, #-0xf0]
0012d920  str        x0, [sp, #0xa0]
  ------
0012d924  ldur       x0, [x29, #-0xe8]
0012d928  mov        x6, #0xf322
0012d92c  movk       x6, #0x95eb, lsl #16
0012d930  movk       x6, #0x19e4, lsl #32
0012d934  str        x0, [sp, #0x98]
0012d938  movk       x6, #0x193, lsl #48
0012d93c  b          #0x12cc34
  ------
0012d940  ldr        x8, [sp, #0x88]
0012d944  sub        x0, x29, #0x18
0012d948  sub        x2, x29, #0x30
0012d94c  mov        w1, #4
0012d950  ldr        w8, [x8, #0x128]
0012d954  rev        w8, w8
0012d958  stur       w8, [x29, #-0x30]
0012d95c  bl         #0x147d3c
0012d960  ldur       w8, [x29, #-0x18]
0012d964  mov        x9, #0xc65f
0012d968  movk       x9, #0x71bc, lsl #16
0012d96c  str        x0, [sp, #0x128]
0012d970  movk       x9, #0x1c29, lsl #32
0012d974  mov        x27, x20
0012d978  cmp        w8, #0
0012d97c  mov        x8, #0x70c6
0012d980  movk       x8, #0x8723, lsl #16
0012d984  mov        x21, x22
0012d988  movk       x8, #0x9926, lsl #32
0012d98c  mov        x26, x28
0012d990  mov        x28, x19
0012d994  movk       x8, #0x99f3, lsl #48
0012d998  movk       x9, #0xf47c, lsl #48
0012d99c  b          #0x12dbe0
  ------
0012d9a0  mov        w8, #4
0012d9a4  ldur       x4, [x29, #-0x80]
0012d9a8  ldp        x11, x10, [x29, #-0x58]
0012d9ac  stp        xzr, xzr, [sp, #0xf0]
0012d9b0  mov        x27, x20
0012d9b4  str        w8, [sp, #0xe4]
0012d9b8  mov        x21, x22
0012d9bc  ldp        x8, x7, [x29, #-0x78]
0012d9c0  str        xzr, [sp, #0xe8]
0012d9c4  mov        x26, x28
0012d9c8  ldp        x12, x13, [x29, #-0xd0]
0012d9cc  stp        xzr, xzr, [sp, #0xd0]
0012d9d0  mov        x28, x19
0012d9d4  stur       x8, [x29, #-0x48]
0012d9d8  mov        x5, x25
0012d9dc  ldp        x9, x8, [x29, #-0x68]
0012d9e0  str        xzr, [sp, #0xc8]
0012d9e4  ldp        x14, x15, [x29, #-0xc0]
0012d9e8  ldp        x16, x17, [x29, #-0xb0]
0012d9ec  ldp        x30, x1, [x29, #-0xa0]
0012d9f0  ldp        x2, x3, [x29, #-0x90]
0012d9f4  b          #0x12d8fc
  ------
0012d9f8  ldp        x8, x7, [x29, #-0x78]
0012d9fc  mov        w0, #4
0012da00  stp        xzr, xzr, [sp, #0xf0]
0012da04  ldp        x11, x10, [x29, #-0x58]
0012da08  str        xzr, [sp, #0xe8]
0012da0c  mov        x27, x20
0012da10  stur       x8, [x29, #-0x48]
0012da14  ldur       x4, [x29, #-0x80]
0012da18  ldp        x9, x8, [x29, #-0x68]
0012da1c  stp        xzr, xzr, [sp, #0xd0]
0012da20  mov        x21, x22
0012da24  ldp        x12, x13, [x29, #-0xd0]
0012da28  stp        xzr, xzr, [sp, #0xc0]
0012da2c  mov        x26, x28
0012da30  ldp        x14, x15, [x29, #-0xc0]
0012da34  stp        xzr, xzr, [sp, #0xb0]
0012da38  mov        x28, x19
0012da3c  ldp        x16, x17, [x29, #-0xb0]
0012da40  mov        x5, x25
0012da44  str        w0, [sp, #0xe4]
0012da48  ldp        x30, x1, [x29, #-0xa0]
0012da4c  ldp        x2, x3, [x29, #-0x90]
0012da50  b          #0x12d914
  ------
0012da54  sub        x0, x29, #0x18
0012da58  bl         #0x147f8c
0012da5c  ldur       w8, [x29, #-0x18]
0012da60  mov        x9, #0x634e
0012da64  movk       x9, #0xe191, lsl #16
0012da68  mov        x27, x20
0012da6c  movk       x9, #0x1a1d, lsl #32
0012da70  mov        x21, x22
0012da74  cmp        w8, #0
0012da78  mov        x8, #0x33c
0012da7c  movk       x8, #0x58ee, lsl #16
0012da80  mov        x26, x28
0012da84  movk       x8, #0x22f3, lsl #32
0012da88  mov        x28, x19
0012da8c  movk       x8, #0xa520, lsl #48
0012da90  movk       x9, #0xf89c, lsl #48
0012da94  str        x0, [sp, #0x118]
0012da98  b          #0x12dbe0
  ------
0012da9c  sub        x0, x29, #0x18
0012daa0  mov        w1, #0x10
0012daa4  ldr        x2, [sp, #0x48]
0012daa8  bl         #0x147d3c
0012daac  ldur       w8, [x29, #-0x18]
0012dab0  mov        x9, #0xe526
0012dab4  movk       x9, #0xc774, lsl #16
0012dab8  stur       x0, [x29, #-0xf0]
0012dabc  movk       x9, #0xaacf, lsl #32
0012dac0  mov        x27, x20
0012dac4  cmp        w8, #0
0012dac8  mov        x8, #0x5e5d
0012dacc  movk       x8, #0xe6ee, lsl #16
0012dad0  mov        x21, x22
0012dad4  movk       x8, #0xcd9a, lsl #32
0012dad8  mov        x26, x28
0012dadc  mov        x28, x19
0012dae0  movk       x8, #0x450f, lsl #48
0012dae4  movk       x9, #0x7d8f, lsl #48
0012dae8  b          #0x12dbe0
  ------
0012daec  mov        w8, #4
0012daf0  ldur       x4, [x29, #-0x80]
0012daf4  ldp        x11, x10, [x29, #-0x58]
0012daf8  stp        xzr, xzr, [sp, #0xf0]
0012dafc  mov        x27, x20
0012db00  str        w8, [sp, #0xe4]
0012db04  mov        x21, x22
0012db08  ldp        x8, x7, [x29, #-0x78]
0012db0c  str        xzr, [sp, #0xe8]
0012db10  mov        x26, x28
0012db14  ldp        x12, x13, [x29, #-0xd0]
0012db18  stp        xzr, xzr, [sp, #0xd0]
0012db1c  mov        x28, x19
0012db20  stur       x8, [x29, #-0x48]
0012db24  mov        x5, x25
0012db28  ldp        x9, x8, [x29, #-0x68]
0012db2c  ldp        x14, x15, [x29, #-0xc0]
0012db30  ldp        x16, x17, [x29, #-0xb0]
0012db34  ldp        x30, x1, [x29, #-0xa0]
0012db38  ldp        x2, x3, [x29, #-0x90]
0012db3c  b          #0x12d8f4
  ------
0012db40  sub        x0, x29, #0x18
0012db44  mov        w1, #0x14
0012db48  ldr        x2, [sp, #0x40]
0012db4c  bl         #0x147d3c
0012db50  ldur       w8, [x29, #-0x18]
0012db54  mov        x9, #0x6c7b
0012db58  movk       x9, #0xdbb6, lsl #16
0012db5c  stur       x0, [x29, #-0xe8]
0012db60  movk       x9, #0x615, lsl #32
0012db64  mov        x27, x20
0012db68  cmp        w8, #0
0012db6c  mov        x8, #0xdfb
0012db70  movk       x8, #0x2958, lsl #16
0012db74  mov        x21, x22
0012db78  movk       x8, #0x9f87, lsl #32
0012db7c  mov        x26, x28
0012db80  mov        x28, x19
0012db84  movk       x8, #0xd5b5, lsl #48
0012db88  movk       x9, #0x1904, lsl #48
0012db8c  b          #0x12dbe0
  ------
0012db90  ldr        x8, [sp, #0x88]
0012db94  sub        x0, x29, #0x18
0012db98  ldr        w1, [x8, #0x128]
0012db9c  ldr        x2, [x8, #0x130]
0012dba0  bl         #0x147d3c
0012dba4  ldur       w8, [x29, #-0x18]
0012dba8  mov        x9, #0x178
0012dbac  movk       x9, #0x6e1b, lsl #16
0012dbb0  str        x0, [sp, #0x120]
0012dbb4  movk       x9, #0xa1, lsl #32
0012dbb8  mov        x27, x20
0012dbbc  cmp        w8, #0
0012dbc0  mov        x8, #0xe1c0
0012dbc4  movk       x8, #0x4541, lsl #16
0012dbc8  mov        x21, x22
0012dbcc  movk       x8, #0xd3cd, lsl #32
0012dbd0  mov        x26, x28
0012dbd4  mov        x28, x19
0012dbd8  movk       x8, #0xd8f0, lsl #48
0012dbdc  movk       x9, #0x709d, lsl #48
  ------
0012dbe0  csel       x6, x9, x8, eq
  ------
0012dbe4  ldur       x8, [x29, #-0x78]
0012dbe8  stur       x8, [x29, #-0x48]
  ------
0012dbec  ldp        x7, x9, [x29, #-0x70]
0012dbf0  mov        x5, x25
0012dbf4  ldp        x8, x11, [x29, #-0x60]
0012dbf8  ldp        x12, x13, [x29, #-0xd0]
0012dbfc  ldp        x14, x15, [x29, #-0xc0]
0012dc00  ldp        x16, x17, [x29, #-0xb0]
0012dc04  ldp        x30, x1, [x29, #-0xa0]
0012dc08  ldp        x2, x3, [x29, #-0x90]
0012dc0c  ldur       x10, [x29, #-0x50]
0012dc10  ldur       x4, [x29, #-0x80]
0012dc14  b          #0x12cc34
  ------
0012dc18  ldp        x8, x7, [x29, #-0x78]
0012dc1c  mov        x6, #0xa19b
0012dc20  mov        x12, xzr
0012dc24  ldp        x11, x10, [x29, #-0x58]
0012dc28  movk       x6, #0xe897, lsl #16
0012dc2c  mov        x13, xzr
0012dc30  stur       x8, [x29, #-0x48]
0012dc34  ldur       x5, [x29, #-0xe8]
0012dc38  ldp        x9, x8, [x29, #-0x68]
0012dc3c  movk       x6, #0x49dc, lsl #32
0012dc40  mov        x14, xzr
0012dc44  mov        x15, xzr
0012dc48  mov        x16, xzr
0012dc4c  mov        x17, xzr
0012dc50  mov        x30, xzr
0012dc54  mov        x1, xzr
0012dc58  mov        x2, xzr
0012dc5c  mov        x3, xzr
0012dc60  mov        x4, xzr
0012dc64  mov        x27, x20
0012dc68  mov        x21, x22
0012dc6c  mov        x26, x28
0012dc70  mov        x28, x19
0012dc74  movk       x6, #0xf78d, lsl #48
0012dc78  b          #0x12cc34
  ------
0012dc7c  ldr        x0, [sp, #0x118]
0012dc80  bl         #0x147e30
0012dc84  mov        w0, w0
0012dc88  mov        w1, #1
0012dc8c  str        x0, [sp, #0x68]
0012dc90  bl         #0x148b90   ; calloc@plt
0012dc94  mov        x8, #0x830b
0012dc98  mov        x9, #0x47de
0012dc9c  movk       x8, #0xa8ee, lsl #16
0012dca0  movk       x9, #0xf36d, lsl #16
0012dca4  movk       x8, #0x9027, lsl #32
0012dca8  movk       x9, #0xe159, lsl #32
0012dcac  cmp        x0, #0
0012dcb0  movk       x8, #0x7b7e, lsl #48
0012dcb4  movk       x9, #0x8b44, lsl #48
0012dcb8  mov        x27, x20
0012dcbc  mov        x21, x22
0012dcc0  str        x0, [sp, #0x100]
0012dcc4  mov        x26, x28
0012dcc8  csel       x6, x8, x9, eq
0012dccc  mov        x28, x19
0012dcd0  b          #0x12dbe4
  ------
0012dcd4  ldp        x8, x7, [x29, #-0x78]
0012dcd8  mov        w0, #4
0012dcdc  stp        xzr, xzr, [sp, #0xf0]
0012dce0  ldp        x11, x10, [x29, #-0x58]
0012dce4  str        xzr, [sp, #0xe8]
0012dce8  mov        x27, x20
0012dcec  stur       x8, [x29, #-0x48]
0012dcf0  ldur       x4, [x29, #-0x80]
0012dcf4  ldp        x9, x8, [x29, #-0x68]
0012dcf8  stp        xzr, xzr, [sp, #0xd0]
0012dcfc  mov        x21, x22
0012dd00  ldp        x12, x13, [x29, #-0xd0]
0012dd04  stp        xzr, xzr, [sp, #0xc0]
0012dd08  mov        x26, x28
0012dd0c  ldp        x14, x15, [x29, #-0xc0]
0012dd10  stp        xzr, xzr, [sp, #0xb0]
0012dd14  mov        x28, x19
0012dd18  ldp        x16, x17, [x29, #-0xb0]
0012dd1c  stp        xzr, xzr, [sp, #0xa0]
0012dd20  mov        x5, x25
0012dd24  ldp        x30, x1, [x29, #-0xa0]
0012dd28  str        w0, [sp, #0xe4]
0012dd2c  ldp        x2, x3, [x29, #-0x90]
0012dd30  b          #0x12d924
  ------
0012dd34  ldp        x8, x7, [x29, #-0x78]
0012dd38  mov        w0, #4
0012dd3c  mov        x6, #0xf322
0012dd40  ldp        x11, x10, [x29, #-0x58]
0012dd44  movk       x6, #0x95eb, lsl #16
0012dd48  stp        xzr, xzr, [sp, #0xf0]
0012dd4c  stur       x8, [x29, #-0x48]
0012dd50  ldur       x4, [x29, #-0x80]
0012dd54  ldp        x9, x8, [x29, #-0x68]
0012dd58  movk       x6, #0x19e4, lsl #32
0012dd5c  str        xzr, [sp, #0xe8]
0012dd60  ldp        x12, x13, [x29, #-0xd0]
0012dd64  stp        xzr, xzr, [sp, #0xd0]
0012dd68  mov        x27, x20
0012dd6c  ldp        x14, x15, [x29, #-0xc0]
0012dd70  stp        xzr, xzr, [sp, #0xc0]
0012dd74  mov        x21, x22
0012dd78  ldp        x16, x17, [x29, #-0xb0]
0012dd7c  stp        xzr, xzr, [sp, #0xb0]
0012dd80  mov        x26, x28
0012dd84  ldp        x30, x1, [x29, #-0xa0]
0012dd88  stp        xzr, xzr, [sp, #0xa0]
0012dd8c  mov        x28, x19
0012dd90  ldp        x2, x3, [x29, #-0x90]
0012dd94  str        xzr, [sp, #0x98]
0012dd98  mov        x5, x25
0012dd9c  str        w0, [sp, #0xe4]
0012dda0  movk       x6, #0x193, lsl #48
0012dda4  b          #0x12cc34
  ------
0012dda8  ldur       x0, [x29, #-0x68]
0012ddac  bl         #0x147e84
0012ddb0  mov        x0, x20
0012ddb4  bl         #0x147e2c
0012ddb8  ldur       x0, [x29, #-0x58]
0012ddbc  bl         #0x147e2c
0012ddc0  mov        x0, x19
0012ddc4  bl         #0x147e2c
0012ddc8  ldur       x0, [x29, #-0xf8]
0012ddcc  bl         #0x147e2c
0012ddd0  ldr        x0, [sp, #0x60]
0012ddd4  bl         #0x147e2c
0012ddd8  mov        x0, x22
0012dddc  bl         #0x147e2c
0012dde0  ldur       x0, [x29, #-0xe0]
0012dde4  bl         #0x147e2c
0012dde8  ldur       x0, [x29, #-0x78]
0012ddec  bl         #0x147e2c
0012ddf0  ldur       x0, [x29, #-0xd8]
0012ddf4  bl         #0x147e2c
0012ddf8  ldur       x0, [x29, #-0x60]
0012ddfc  bl         #0x147e2c
0012de00  ldur       x0, [x29, #-0x70]
0012de04  bl         #0x147e2c
0012de08  ldur       x0, [x29, #-0x50]
0012de0c  bl         #0x148a00   ; free@plt
0012de10  ldur       x0, [x29, #-0x20]
0012de14  bl         #0x148a00   ; free@plt
0012de18  ldr        x8, [sp, #0x80]
0012de1c  ldr        x9, [sp, #0x38]
0012de20  ldr        w8, [x8]
0012de24  ldr        x9, [x9, #0x28]
0012de28  ldur       x10, [x29, #-0x10]
0012de2c  cmp        w8, #0
0012de30  cset       w0, eq
0012de34  cmp        x9, x10
0012de38  b.ne       #0x12de5c
0012de3c  add        sp, sp, #0x250
0012de40  ldp        x20, x19, [sp, #0x50]
0012de44  ldp        x22, x21, [sp, #0x40]
0012de48  ldp        x24, x23, [sp, #0x30]
0012de4c  ldp        x26, x25, [sp, #0x20]
0012de50  ldp        x28, x27, [sp, #0x10]
0012de54  ldp        x29, x30, [sp], #0x60
0012de58  ret        
  ------
0012de5c  bl         #0x148a10   ; __stack_chk_fail@plt
