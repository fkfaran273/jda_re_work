00100000  b        #0x100040
00100004  mov      x11, #0xd282
00100008  ldr      x10, [sp, #0x10]
0010000c  mov      w12, #0xa
00100010  movk     x11, #0x957d, lsl #16
00100014  movk     x11, #0xadd, lsl #32
00100018  mov      w8, #1
0010001c  mov      w9, w27
00100020  movk     x11, #0x549f, lsl #48
00100024  str      w12, [x10]
00100028  b        #0xffc74
0010002c  cmp      w6, #0xd
00100030  csel     x11, x0, x22, eq
00100034  b        #0x100040
00100038  cmp      w6, #0x14
0010003c  csel     x11, x17, x16, eq
00100040  mov      w8, w26
00100044  mov      w9, w27
00100048  b        #0xffc74
0010004c  ldr      x8, [sp, #8]
00100050  ldr      x8, [x8, #0x28]
00100054  ldur     x9, [x29, #-0x10]
00100058  cmp      x8, x9
0010005c  b.ne     #0x100088
00100060  eor      w8, w27, #1
00100064  ldp      x20, x19, [sp, #0x120]
00100068  and      w0, w8, #1
0010006c  ldp      x22, x21, [sp, #0x110]
00100070  ldp      x24, x23, [sp, #0x100]
00100074  ldp      x26, x25, [sp, #0xf0]
00100078  ldp      x28, x27, [sp, #0xe0]
0010007c  ldp      x29, x30, [sp, #0xd0]
00100080  add      sp, sp, #0x130
00100084  ret      
00100088  bl       #0x148a10
0010008c  mov      w0, wzr
00100090  ret      
00100094  sub      sp, sp, #0x160
00100098  stp      x29, x30, [sp, #0x100]
0010009c  stp      x28, x27, [sp, #0x110]
001000a0  stp      x26, x25, [sp, #0x120]
001000a4  stp      x24, x23, [sp, #0x130]
001000a8  stp      x22, x21, [sp, #0x140]
001000ac  stp      x20, x19, [sp, #0x150]
001000b0  add      x29, sp, #0x100
001000b4  stp      x3, x4, [x29, #-0x58]
001000b8  mov      x9, #-0x28
001000bc  stp      x5, x6, [x29, #-0x48]
001000c0  add      x10, sp, #0x20
001000c4  stur     x7, [x29, #-0x38]
001000c8  sub      x11, x29, #0x58
001000cc  stp      q0, q1, [sp, #0x20]
001000d0  mov      x20, x1
001000d4  stp      q2, q3, [sp, #0x40]
001000d8  mov      x19, x0
001000dc  stp      q4, q5, [sp, #0x60]
001000e0  mov      x24, sp
001000e4  stp      q6, q7, [sp, #0x80]
001000e8  mrs      x25, tpidr_el0
001000ec  ldr      x8, [x25, #0x28]
001000f0  mov      x23, xzr
001000f4  movk     x9, #0xff80, lsl #32
001000f8  add      x10, x10, #0x80
001000fc  mov      w26, w2
00100100  stur     x8, [x29, #-0x10]
00100104  add      x8, x11, #0x28
00100108  add      x11, x29, #0x60
0010010c  stp      x10, x9, [x29, #-0x20]
00100110  stp      x11, x8, [x29, #-0x30]
00100114  cmp      x23, x26
00100118  b.eq     #0x100228
0010011c  ldursw   x8, [x29, #-0x18]
00100120  tbz      w8, #0x1f, #0x100140
00100124  add      w9, w8, #8
00100128  cmn      w8, #8
0010012c  stur     w9, [x29, #-0x18]
00100130  b.hi     #0x100140
00100134  ldur     x9, [x29, #-0x28]
00100138  add      x8, x9, x8
0010013c  b        #0x10014c
00100140  ldur     x8, [x29, #-0x30]
00100144  add      x9, x8, #8
00100148  stur     x9, [x29, #-0x30]
0010014c  ldr      x27, [x8]
00100150  add      x9, x20, x23, lsl #3
00100154  mov      x22, xzr
00100158  add      x28, x9, #0x20
0010015c  ldr      w8, [x27]
00100160  lsr      x21, x8, #2
00100164  cmp      x21, x22
00100168  b.eq     #0x100198
0010016c  ldr      x8, [x27, #8]
00100170  mov      x0, x19
00100174  ldr      x1, [x28]
00100178  mov      w2, w22
0010017c  ldr      w8, [x8, x22, lsl #2]
00100180  rev      w3, w8
00100184  bl       #0x146ed8
00100188  ldr      w8, [x19]
0010018c  add      x22, x22, #1
00100190  cbz      w8, #0x100164
00100194  b        #0x100318
00100198  ldr      w8, [x27]
0010019c  and      w10, w8, #3
001001a0  cmp      w10, #2
001001a4  b.hs     #0x1001c8
001001a8  cmp      w10, #1
001001ac  b.ne     #0x100218
001001b0  sub      w8, w8, #1
001001b4  ldr      x9, [x27, #8]
001001b8  ldr      x1, [x28]
001001bc  ldrb     w8, [x9, w8, uxtw]
001001c0  lsl      w3, w8, #0x18
001001c4  b        #0x10020c
001001c8  ldr      x1, [x28]
001001cc  cmp      w10, #3
001001d0  ldr      x9, [x27, #8]
001001d4  b.ne     #0x1001fc
001001d8  sub      w8, w8, #3
001001dc  add      x8, x9, x8
001001e0  ldrb     w9, [x8]
001001e4  ldrb     w10, [x8, #1]
001001e8  ldrb     w8, [x8, #2]
001001ec  lsl      w9, w9, #0x18
001001f0  orr      w9, w9, w10, lsl #16
001001f4  orr      w3, w9, w8, lsl #8
001001f8  b        #0x10020c
001001fc  sub      w8, w8, #2
00100200  ldrh     w8, [x9, w8, uxtw]
00100204  rev      w8, w8
00100208  and      w3, w8, #0xffff0000
0010020c  mov      x0, x19
00100210  mov      w2, w21
00100214  bl       #0x146ed8
00100218  ldr      w8, [x19]
0010021c  add      x23, x23, #1
00100220  cbz      w8, #0x100114
00100224  b        #0x100318
00100228  ldr      x1, [x20]
0010022c  mov      x0, x19
00100230  mov      w2, #0x19
00100234  bl       #0x147630
00100238  ldr      w8, [x19]
0010023c  cbnz     w8, #0x100318
00100240  ldr      x1, [x20]
00100244  mov      x0, x19
00100248  mov      w2, wzr
0010024c  bl       #0x147630
00100250  ldr      w8, [x19]
00100254  cbnz     w8, #0x100318
00100258  ldr      x1, [x20]
0010025c  mov      x0, x19
00100260  bl       #0x147734
00100264  ldr      w8, [x19]
00100268  cbnz     w8, #0x100318
0010026c  mov      w21, w0
00100270  ldr      x1, [x20]
00100274  mov      x0, x19
00100278  bl       #0x147734
0010027c  ldr      w8, [x19]
00100280  cbnz     w8, #0x100318
00100284  mov      x26, x20
00100288  mov      w3, w0
0010028c  mov      x0, x19
00100290  mov      w2, w21
00100294  ldr      x1, [x26, #8]!
00100298  bl       #0x146ed8
0010029c  ldr      w8, [x19]
001002a0  cbnz     w8, #0x100318
001002a4  ldr      x1, [x20]
001002a8  mov      x0, x19
001002ac  mov      w2, wzr
001002b0  bl       #0x147630
001002b4  ldr      w8, [x19]
001002b8  cbnz     w8, #0x100318
001002bc  ldr      x1, [x20]
001002c0  mov      x0, x19
001002c4  bl       #0x147734
001002c8  ldr      w8, [x19]
001002cc  cbnz     w8, #0x100318
001002d0  add      x8, x20, w0, uxtw #3
001002d4  ldr      x21, [x20]
001002d8  ldr      x0, [x8, #0x20]
001002dc  bl       #0x1472e8
001002e0  mov      w2, w0
001002e4  mov      x0, x19
001002e8  mov      x1, x21
001002ec  bl       #0x147630
001002f0  ldr      w8, [x19]
001002f4  cbnz     w8, #0x100318
001002f8  mov      x8, x20
001002fc  mov      x0, x19
00100300  mov      w2, #0x11
00100304  ldr      x1, [x8, #0x18]!
00100308  str      x8, [sp, #0x18]
0010030c  bl       #0x146470
00100310  ldr      w8, [x19]
00100314  cbz      w8, #0x10034c
00100318  mov      sp, x24
0010031c  ldr      x8, [x25, #0x28]
00100320  ldur     x9, [x29, #-0x10]
00100324  cmp      x8, x9
00100328  b.ne     #0x12aa44
0010032c  ldp      x20, x19, [sp, #0x150]
00100330  ldp      x22, x21, [sp, #0x140]
00100334  ldp      x24, x23, [sp, #0x130]
00100338  ldp      x26, x25, [sp, #0x120]
0010033c  ldp      x28, x27, [sp, #0x110]
00100340  ldp      x29, x30, [sp, #0x100]
00100344  add      sp, sp, #0x160
00100348  ret      
0010034c  add      x8, x20, #0x10
00100350  str      x8, [sp]
00100354  ldr      x1, [x20]
00100358  mov      x0, x19
0010035c  mov      w2, wzr
00100360  bl       #0x147630
00100364  ldr      w8, [x19]
00100368  cbnz     w8, #0x100318
0010036c  ldr      x1, [x20]
00100370  mov      x0, x19
00100374  bl       #0x147734
00100378  ldr      w8, [x19]
0010037c  cbnz     w8, #0x100318
00100380  mov      w1, w0
00100384  ldp      x21, x0, [x20]
00100388  bl       #0x147304
0010038c  mov      w2, w0
00100390  mov      x0, x19
00100394  mov      x1, x21
00100398  bl       #0x147630
0010039c  ldr      w8, [x19]
001003a0  cbnz     w8, #0x100318
001003a4  ldr      x1, [x20]
001003a8  mov      x0, x19
001003ac  mov      w2, #1
001003b0  bl       #0x147a20
001003b4  ldr      w8, [x19]
001003b8  cbnz     w8, #0x100318
001003bc  ldr      x1, [x20]
001003c0  mov      x0, x19
001003c4  mov      w2, #1
001003c8  bl       #0x14784c
001003cc  ldr      w8, [x19]
001003d0  cbnz     w8, #0x100318
001003d4  ldr      x1, [x20]
001003d8  mov      x0, x19
001003dc  bl       #0x147734
001003e0  ldr      w8, [x19]
001003e4  cbnz     w8, #0x100318
001003e8  mov      w21, w0
001003ec  ldr      x1, [x20]
001003f0  mov      x0, x19
001003f4  bl       #0x147734
001003f8  ldr      w8, [x19]
001003fc  cbnz     w8, #0x100318
00100400  ldr      x1, [x20]
00100404  add      w2, w0, w21
00100408  mov      x0, x19
0010040c  bl       #0x147630
00100410  ldr      w8, [x19]
00100414  cbnz     w8, #0x100318
00100418  ldr      x1, [x20]
0010041c  mov      x0, x19
00100420  mov      w2, wzr
00100424  bl       #0x147630
00100428  ldr      w8, [x19]
0010042c  cbnz     w8, #0x100318
00100430  ldr      x1, [x20]
00100434  mov      x0, x19
00100438  bl       #0x147734
0010043c  ldr      w8, [x19]
00100440  cbnz     w8, #0x100318
00100444  mov      w21, w0
00100448  ldr      x1, [x20]
0010044c  mov      x0, x19
00100450  bl       #0x147734
00100454  ldr      w8, [x19]
00100458  cbnz     w8, #0x100318
0010045c  mov      w3, w0
00100460  ldr      x1, [x26]
00100464  mov      x0, x19
00100468  mov      w2, w21
0010046c  bl       #0x146ed8
00100470  ldr      w8, [x19]
00100474  cbnz     w8, #0x100318
00100478  ldr      x1, [x20]
0010047c  mov      x0, x19
00100480  mov      w2, wzr
00100484  bl       #0x147630
00100488  ldr      w8, [x19]
0010048c  cbnz     w8, #0x100318
00100490  ldr      x1, [x20]
00100494  mov      x0, x19
00100498  mov      w2, wzr
0010049c  bl       #0x147630
001004a0  ldr      w8, [x19]
001004a4  cbnz     w8, #0x100318
001004a8  ldr      x1, [x20]
001004ac  mov      x0, x19
001004b0  bl       #0x147734
001004b4  ldr      w8, [x19]
001004b8  cbnz     w8, #0x100318
001004bc  mov      w1, w0
001004c0  ldp      x21, x0, [x20]
001004c4  bl       #0x147304
001004c8  mov      w2, w0
001004cc  mov      x0, x19
001004d0  mov      x1, x21
001004d4  bl       #0x147630
001004d8  ldr      w8, [x19]
001004dc  cbnz     w8, #0x100318
001004e0  ldr      x1, [x20]
001004e4  mov      x0, x19
001004e8  bl       #0x147734
001004ec  ldr      w8, [x19]
001004f0  cbnz     w8, #0x100318
001004f4  ldr      x1, [x20]
001004f8  sub      w2, w0, #1
001004fc  mov      x0, x19
00100500  bl       #0x147630
00100504  ldr      w8, [x19]
00100508  cbnz     w8, #0x100318
0010050c  ldr      x1, [x20]
00100510  mov      x0, x19
00100514  bl       #0x147734
00100518  ldr      w8, [x19]
0010051c  cbnz     w8, #0x100318
00100520  mov      w21, w0
00100524  ldr      x1, [x20]
00100528  mov      x0, x19
0010052c  bl       #0x147734
00100530  ldr      w8, [x19]
00100534  cbnz     w8, #0x100318
00100538  mov      w3, w0
0010053c  ldr      x1, [x26]
00100540  mov      x0, x19
00100544  mov      w2, w21
00100548  bl       #0x146ed8
0010054c  ldr      w8, [x19]
00100550  cbnz     w8, #0x100318
00100554  ldr      x8, [sp, #0x18]
00100558  ldr      x0, [x8]
0010055c  bl       #0x146474
00100560  tbnz     w0, #0, #0x100318
00100564  ldr      x8, [sp, #0x18]
00100568  mov      x0, x19
0010056c  ldr      x1, [x8]
00100570  bl       #0x146478
00100574  ldr      w8, [x19]
00100578  cbnz     w8, #0x100318
0010057c  stp      x24, x25, [sp, #8]
00100580  cmp      w0, #0x2d
00100584  b.lt     #0x128838
00100588  b.eq     #0x128990
0010058c  cmp      w0, #0x37e
00100590  b.hs     #0x100710
00100594  cmp      w0, #0x19f
00100598  b.hs     #0x100830
0010059c  cmp      w0, #0xeb
001005a0  b.hs     #0x100a2c
001005a4  cmp      w0, #0xbb
001005a8  b.hs     #0x100db0
001005ac  cmp      w0, #0x7d
001005b0  b.lo     #0x128fc0
001005b4  cmp      w0, #0x99
001005b8  b.lo     #0x1293c8
001005bc  ldp      x24, x25, [sp, #8]
001005c0  b.ne     #0x12a8b4
001005c4  ldr      x1, [x20]
001005c8  mov      x0, x19
001005cc  mov      w2, #6
001005d0  bl       #0x147630
001005d4  ldr      w8, [x19]
001005d8  cbnz     w8, #0x100318
001005dc  ldr      x1, [x20]
001005e0  mov      x0, x19
001005e4  bl       #0x147734
001005e8  ldr      w8, [x19]
001005ec  cbnz     w8, #0x100318
001005f0  mov      w21, w0
001005f4  ldr      x1, [x20]
001005f8  mov      x0, x19
001005fc  bl       #0x147734
00100600  ldr      w8, [x19]
00100604  cbnz     w8, #0x100318
00100608  mov      w3, w0
0010060c  ldr      x1, [x26]
00100610  mov      x0, x19
00100614  mov      w2, w21
00100618  bl       #0x146ed8
0010061c  ldr      w8, [x19]
00100620  cbnz     w8, #0x100318
00100624  ldr      x1, [x20]
00100628  mov      x0, x19
0010062c  mov      w2, #2
00100630  bl       #0x147630
00100634  ldr      w8, [x19]
00100638  cbnz     w8, #0x100318
0010063c  ldr      x1, [x20]
00100640  mov      x0, x19
00100644  mov      w2, #6
00100648  bl       #0x147630
0010064c  ldr      w8, [x19]
00100650  cbnz     w8, #0x100318
00100654  ldr      x1, [x20]
00100658  mov      x0, x19
0010065c  bl       #0x147734
00100660  ldr      w8, [x19]
00100664  cbnz     w8, #0x100318
00100668  mov      w1, w0
0010066c  ldp      x21, x0, [x20]
00100670  bl       #0x147304
00100674  mov      w2, w0
00100678  mov      x0, x19
0010067c  mov      x1, x21
00100680  bl       #0x147630
00100684  ldr      w8, [x19]
00100688  cbnz     w8, #0x100318
0010068c  ldr      x1, [x20]
00100690  mov      x0, x19
00100694  bl       #0x147734
00100698  ldr      w8, [x19]
0010069c  cbnz     w8, #0x100318
001006a0  mov      w21, w0
001006a4  ldr      x1, [x20]
001006a8  mov      x0, x19
001006ac  bl       #0x147734
001006b0  ldr      w8, [x19]
001006b4  cbnz     w8, #0x100318
001006b8  add      x28, x20, w0, uxtw #3
001006bc  ldr      x0, [x28, #0x20]!
001006c0  bl       #0x1472e8
001006c4  mov      w22, w0
001006c8  mov      w23, wzr
001006cc  cmp      w22, w23
001006d0  b.eq     #0x101ef8
001006d4  ldr      x0, [x28]
001006d8  mov      w1, w23
001006dc  ldr      x24, [x26]
001006e0  add      w25, w21, w23
001006e4  bl       #0x147304
001006e8  mov      w3, w0
001006ec  mov      x0, x19
001006f0  mov      x1, x24
001006f4  mov      w2, w25
001006f8  bl       #0x146ed8
001006fc  ldp      x24, x25, [sp, #8]
00100700  add      w23, w23, #1
00100704  ldr      w8, [x19]
00100708  cbz      w8, #0x1006cc
0010070c  b        #0x100318
00100710  cmp      w0, #0x651
00100714  b.hs     #0x10095c
00100718  cmp      w0, #0x534
0010071c  b.hs     #0x100b24
00100720  cmp      w0, #0x4de
00100724  b.hs     #0x100de8
00100728  cmp      w0, #0x3e5
0010072c  b.hs     #0x10168c
00100730  cmp      w0, #0x3d9
00100734  b.hs     #0x102108
00100738  ldp      x24, x25, [sp, #8]
0010073c  cmp      w0, #0x37e
00100740  b.ne     #0x12a8b4
00100744  ldr      x1, [x20]
00100748  mov      x0, x19
0010074c  mov      w2, wzr
00100750  bl       #0x147630
00100754  ldr      w8, [x19]
00100758  cbnz     w8, #0x100318
0010075c  ldr      x1, [x20]
00100760  mov      x0, x19
00100764  mov      w2, #1
00100768  bl       #0x147630
0010076c  ldr      w8, [x19]
00100770  cbnz     w8, #0x100318
00100774  ldr      x1, [x20]
00100778  mov      x0, x19
0010077c  bl       #0x147734
00100780  ldr      w8, [x19]
00100784  cbnz     w8, #0x100318
00100788  mov      w1, w0
0010078c  ldp      x21, x0, [x20]
00100790  bl       #0x147304
00100794  mov      w2, w0
00100798  mov      x0, x19
0010079c  mov      x1, x21
001007a0  bl       #0x147630
001007a4  ldr      w8, [x19]
001007a8  cbnz     w8, #0x100318
001007ac  ldr      x1, [x20]
001007b0  mov      x0, x19
001007b4  bl       #0x147734
001007b8  ldr      w8, [x19]
001007bc  cbnz     w8, #0x100318
001007c0  mov      w21, w0
001007c4  ldr      x1, [x20]
001007c8  mov      x0, x19
001007cc  bl       #0x147734
001007d0  ldr      w8, [x19]
001007d4  cbnz     w8, #0x100318
001007d8  add      x28, x20, w0, uxtw #3
001007dc  ldr      x0, [x28, #0x20]!
001007e0  bl       #0x1472e8
001007e4  mov      w22, w0
001007e8  mov      w23, wzr
001007ec  cmp      w22, w23
001007f0  b.eq     #0x103db0
001007f4  ldr      x0, [x28]
001007f8  mov      w1, w23
001007fc  ldr      x24, [x26]
00100800  add      w25, w21, w23
00100804  bl       #0x147304
00100808  mov      w3, w0
0010080c  mov      x0, x19
00100810  mov      x1, x24
00100814  mov      w2, w25
00100818  bl       #0x146ed8
0010081c  ldp      x24, x25, [sp, #8]
00100820  add      w23, w23, #1
00100824  ldr      w8, [x19]
00100828  cbz      w8, #0x1007ec
0010082c  b        #0x100318
00100830  cmp      w0, #0x27f
00100834  b.hs     #0x100bd8
00100838  cmp      w0, #0x1fb
0010083c  b.hs     #0x100e94
00100840  cmp      w0, #0x1cd
00100844  b.hs     #0x12913c
00100848  cmp      w0, #0x1bb
0010084c  b.lo     #0x12991c
00100850  ldp      x24, x25, [sp, #8]
00100854  b.ne     #0x12a8b4
00100858  ldr      x1, [x20]
0010085c  mov      x0, x19
00100860  mov      w2, #0xd
00100864  bl       #0x147630
00100868  ldr      w8, [x19]
0010086c  cbnz     w8, #0x100318
00100870  ldr      x1, [x20]
00100874  mov      x0, x19
00100878  bl       #0x147734
0010087c  ldr      w8, [x19]
00100880  cbnz     w8, #0x100318
00100884  mov      w21, w0
00100888  ldr      x1, [x20]
0010088c  mov      x0, x19
00100890  bl       #0x147734
00100894  ldr      w8, [x19]
00100898  cbnz     w8, #0x100318
0010089c  mov      w3, w0
001008a0  ldr      x1, [x26]
001008a4  mov      x0, x19
001008a8  mov      w2, w21
001008ac  bl       #0x146ed8
001008b0  ldr      w8, [x19]
001008b4  cbnz     w8, #0x100318
001008b8  ldr      x1, [x20]
001008bc  mov      x0, x19
001008c0  mov      w2, #0xc
001008c4  bl       #0x147630
001008c8  ldr      w8, [x19]
001008cc  cbnz     w8, #0x100318
001008d0  ldr      x1, [x20]
001008d4  mov      x0, x19
001008d8  bl       #0x147734
001008dc  ldr      w8, [x19]
001008e0  cbnz     w8, #0x100318
001008e4  mov      w1, w0
001008e8  ldp      x21, x0, [x20]
001008ec  bl       #0x147304
001008f0  mov      w2, w0
001008f4  mov      x0, x19
001008f8  mov      x1, x21
001008fc  bl       #0x147630
00100900  ldr      w8, [x19]
00100904  cbnz     w8, #0x100318
00100908  ldr      x1, [x20]
0010090c  mov      x0, x19
00100910  bl       #0x147734
00100914  ldr      w8, [x19]
00100918  cbnz     w8, #0x100318
0010091c  mov      w1, w0
00100920  ldp      x21, x0, [x20]
00100924  bl       #0x147304
00100928  mov      w2, w0
0010092c  mov      x0, x19
00100930  mov      x1, x21
00100934  bl       #0x147630
00100938  ldr      w8, [x19]
0010093c  cbnz     w8, #0x100318
00100940  ldr      x1, [x26]
00100944  mov      x0, x19
00100948  bl       #0x147120
0010094c  ldr      x8, [sp, #0x18]
00100950  mov      x0, x19
00100954  mov      w2, #0x1cd
00100958  b        #0x1030b4
0010095c  cmp      w0, #0x727
00100960  b.hs     #0x100cfc
00100964  cmp      w0, #0x6bb
00100968  b.hs     #0x100fec
0010096c  cmp      w0, #0x685
00100970  b.hs     #0x101858
00100974  cmp      w0, #0x65d
00100978  b.hs     #0x102334
0010097c  ldp      x24, x25, [sp, #8]
00100980  cmp      w0, #0x651
00100984  b.ne     #0x12a8b4
00100988  ldr      x1, [x20]
0010098c  mov      x0, x19
00100990  mov      w2, #8
00100994  bl       #0x147630
00100998  ldr      w8, [x19]
0010099c  cbnz     w8, #0x100318
001009a0  ldr      x1, [x20]
001009a4  mov      x0, x19
001009a8  bl       #0x147734
001009ac  ldr      w8, [x19]
001009b0  cbnz     w8, #0x100318
001009b4  mov      w1, w0
001009b8  ldp      x21, x0, [x20]
001009bc  bl       #0x147304
001009c0  mov      w2, w0
001009c4  mov      x0, x19
001009c8  mov      x1, x21
001009cc  bl       #0x147630
001009d0  ldr      w8, [x19]
001009d4  cbnz     w8, #0x100318
001009d8  ldr      x1, [x20]
001009dc  mov      x0, x19
001009e0  bl       #0x147734
001009e4  ldr      w8, [x19]
001009e8  cbnz     w8, #0x100318
001009ec  mov      w1, w0
001009f0  ldp      x21, x0, [x20]
001009f4  bl       #0x147304
001009f8  mov      w2, w0
001009fc  mov      x0, x19
00100a00  mov      x1, x21
00100a04  bl       #0x147630
00100a08  ldr      w8, [x19]
00100a0c  cbnz     w8, #0x100318
00100a10  ldr      x1, [x26]
00100a14  mov      x0, x19
00100a18  bl       #0x147120
00100a1c  ldr      x8, [sp, #0x18]
00100a20  mov      x0, x19
00100a24  mov      w2, #0x65d
00100a28  b        #0x103420
00100a2c  cmp      w0, #0x143
00100a30  b.hs     #0x101098
00100a34  cmp      w0, #0x10b
00100a38  b.hs     #0x128b90
00100a3c  cmp      w0, #0x101
00100a40  b.hs     #0x129a74
00100a44  ldp      x24, x25, [sp, #8]
00100a48  cmp      w0, #0xeb
00100a4c  b.ne     #0x12a8b4
00100a50  ldr      x1, [x20]
00100a54  mov      x0, x19
00100a58  mov      w2, #6
00100a5c  bl       #0x147630
00100a60  ldr      w8, [x19]
00100a64  cbnz     w8, #0x100318
00100a68  ldr      x1, [x20]
00100a6c  mov      x0, x19
00100a70  bl       #0x147734
00100a74  ldr      w8, [x19]
00100a78  cbnz     w8, #0x100318
00100a7c  mov      w1, w0
00100a80  ldp      x21, x0, [x20]
00100a84  bl       #0x147304
00100a88  mov      w2, w0
00100a8c  mov      x0, x19
00100a90  mov      x1, x21
00100a94  bl       #0x147630
00100a98  ldr      w8, [x19]
00100a9c  cbnz     w8, #0x100318
00100aa0  ldr      x1, [x20]
00100aa4  mov      x0, x19
00100aa8  mov      w2, #2
00100aac  bl       #0x147630
00100ab0  ldr      w8, [x19]
00100ab4  cbnz     w8, #0x100318
00100ab8  ldr      x1, [x20]
00100abc  mov      x0, x19
00100ac0  bl       #0x147734
00100ac4  ldr      w8, [x19]
00100ac8  cbnz     w8, #0x100318
00100acc  mov      w21, w0
00100ad0  ldr      x1, [x20]
00100ad4  mov      x0, x19
00100ad8  bl       #0x147734
00100adc  ldr      w8, [x19]
00100ae0  cbnz     w8, #0x100318
00100ae4  ldr      x1, [x20]
00100ae8  add      w2, w0, w21
00100aec  mov      x0, x19
00100af0  bl       #0x147630
00100af4  ldr      w8, [x19]
00100af8  cbnz     w8, #0x100318
00100afc  ldr      x1, [x20]
00100b00  mov      x0, x19
00100b04  mov      w2, #2
00100b08  bl       #0x147630
00100b0c  ldr      w8, [x19]
00100b10  cbnz     w8, #0x100318
00100b14  ldr      x8, [sp, #0x18]
00100b18  mov      x0, x19
00100b1c  mov      w2, #0x101
00100b20  b        #0x102770
00100b24  cmp      w0, #0x583
00100b28  b.hs     #0x1011b4
00100b2c  cmp      w0, #0x55e
00100b30  b.hs     #0x1018fc
00100b34  cmp      w0, #0x549
00100b38  b.hs     #0x102514
00100b3c  ldp      x24, x25, [sp, #8]
00100b40  cmp      w0, #0x534
00100b44  b.ne     #0x12a8b4
00100b48  ldr      x1, [x20]
00100b4c  mov      x0, x19
00100b50  mov      w2, #0x17
00100b54  bl       #0x147630
00100b58  ldr      w8, [x19]
00100b5c  cbnz     w8, #0x100318
00100b60  ldr      x1, [x20]
00100b64  mov      x0, x19
00100b68  bl       #0x147734
00100b6c  ldr      w8, [x19]
00100b70  cbnz     w8, #0x100318
00100b74  mov      w1, w0
00100b78  ldp      x21, x0, [x20]
00100b7c  bl       #0x147304
00100b80  mov      w2, w0
00100b84  mov      x0, x19
00100b88  mov      x1, x21
00100b8c  bl       #0x147630
00100b90  ldr      w8, [x19]
00100b94  cbnz     w8, #0x100318
00100b98  ldr      x1, [x20]
00100b9c  mov      x0, x19
00100ba0  mov      w2, #3
00100ba4  bl       #0x147630
00100ba8  ldr      w8, [x19]
00100bac  cbnz     w8, #0x100318
00100bb0  ldr      x1, [x20]
00100bb4  mov      x0, x19
00100bb8  mov      w2, #1
00100bbc  bl       #0x147630
00100bc0  ldr      w8, [x19]
00100bc4  cbnz     w8, #0x100318
00100bc8  ldr      x8, [sp, #0x18]
00100bcc  mov      x0, x19
00100bd0  mov      w2, #0x549
00100bd4  b        #0x104938
00100bd8  cmp      w0, #0x2d5
00100bdc  b.hs     #0x101300
00100be0  cmp      w0, #0x29f
00100be4  b.lo     #0x128cf0
00100be8  cmp      w0, #0x2c3
00100bec  b.lo     #0x129678
00100bf0  ldp      x24, x25, [sp, #8]
00100bf4  b.ne     #0x12a8b4
00100bf8  ldr      x1, [x20]
00100bfc  mov      x0, x19
00100c00  mov      w2, #0x15
00100c04  bl       #0x147630
00100c08  ldr      w8, [x19]
00100c0c  cbnz     w8, #0x100318
00100c10  ldr      x1, [x20]
00100c14  mov      x0, x19
00100c18  bl       #0x147734
00100c1c  ldr      w8, [x19]
00100c20  cbnz     w8, #0x100318
00100c24  mov      w21, w0
00100c28  ldr      x1, [x20]
00100c2c  mov      x0, x19
00100c30  bl       #0x147734
00100c34  ldr      w8, [x19]
00100c38  cbnz     w8, #0x100318
00100c3c  mov      w3, w0
00100c40  ldr      x1, [x26]
00100c44  mov      x0, x19
00100c48  mov      w2, w21
00100c4c  bl       #0x146ed8
00100c50  ldr      w8, [x19]
00100c54  cbnz     w8, #0x100318
00100c58  ldr      x1, [x20]
00100c5c  mov      x0, x19
00100c60  mov      w2, #0x14
00100c64  bl       #0x147630
00100c68  ldr      w8, [x19]
00100c6c  cbnz     w8, #0x100318
00100c70  ldr      x1, [x20]
00100c74  mov      x0, x19
00100c78  bl       #0x147734
00100c7c  ldr      w8, [x19]
00100c80  cbnz     w8, #0x100318
00100c84  mov      w1, w0
00100c88  ldp      x21, x0, [x20]
00100c8c  bl       #0x147304
00100c90  mov      w2, w0
00100c94  mov      x0, x19
00100c98  mov      x1, x21
00100c9c  bl       #0x147630
00100ca0  ldr      w8, [x19]
00100ca4  cbnz     w8, #0x100318
00100ca8  ldr      x1, [x20]
00100cac  mov      x0, x19
00100cb0  bl       #0x147734
00100cb4  ldr      w8, [x19]
00100cb8  cbnz     w8, #0x100318
00100cbc  mov      w1, w0
00100cc0  ldp      x21, x0, [x20]
00100cc4  bl       #0x147304
00100cc8  mov      w2, w0
00100ccc  mov      x0, x19
00100cd0  mov      x1, x21
00100cd4  bl       #0x147630
00100cd8  ldr      w8, [x19]
00100cdc  cbnz     w8, #0x100318
00100ce0  ldr      x1, [x26]
00100ce4  mov      x0, x19
00100ce8  bl       #0x147120
00100cec  ldr      x8, [sp, #0x18]
00100cf0  mov      x0, x19
00100cf4  mov      w2, #0x2d5
00100cf8  b        #0x1030b4
00100cfc  cmp      w0, #0x793
00100d00  b.hs     #0x1015e0
00100d04  cmp      w0, #0x75d
00100d08  b.hs     #0x101a10
00100d0c  cmp      w0, #0x73c
00100d10  b.hs     #0x1025ac
00100d14  ldp      x24, x25, [sp, #8]
00100d18  cmp      w0, #0x727
00100d1c  b.ne     #0x12a8b4
00100d20  ldr      x1, [x20]
00100d24  mov      x0, x19
00100d28  mov      w2, #0xf
00100d2c  bl       #0x147630
00100d30  ldr      w8, [x19]
00100d34  cbnz     w8, #0x100318
00100d38  ldr      x1, [x20]
00100d3c  mov      x0, x19
00100d40  bl       #0x147734
00100d44  ldr      w8, [x19]
00100d48  cbnz     w8, #0x100318
00100d4c  mov      w1, w0
00100d50  ldp      x21, x0, [x20]
00100d54  bl       #0x147304
00100d58  mov      w2, w0
00100d5c  mov      x0, x19
00100d60  mov      x1, x21
00100d64  bl       #0x147630
00100d68  ldr      w8, [x19]
00100d6c  cbnz     w8, #0x100318
00100d70  ldr      x1, [x20]
00100d74  mov      x0, x19
00100d78  mov      w2, wzr
00100d7c  bl       #0x147630
00100d80  ldr      w8, [x19]
00100d84  cbnz     w8, #0x100318
00100d88  ldr      x1, [x20]
00100d8c  mov      x0, x19
00100d90  mov      w2, #0x20
00100d94  bl       #0x147630
00100d98  ldr      w8, [x19]
00100d9c  cbnz     w8, #0x100318
00100da0  ldr      x8, [sp, #0x18]
00100da4  mov      x0, x19
00100da8  mov      w2, #0x73c
00100dac  b        #0x104938
00100db0  cmp      w0, #0xd0
00100db4  b.hs     #0x101ab4
00100db8  cmp      w0, #0xc0
00100dbc  b.hs     #0x1026f4
00100dc0  ldp      x24, x25, [sp, #8]
00100dc4  cmp      w0, #0xbb
00100dc8  b.ne     #0x12a8b4
00100dcc  ldr      x1, [x26]
00100dd0  mov      x0, x19
00100dd4  bl       #0x147120
00100dd8  ldr      x8, [sp, #0x18]
00100ddc  mov      x0, x19
00100de0  mov      w2, #0xc0
00100de4  b        #0x1033f8
00100de8  cmp      w0, #0x50a
00100dec  b.hs     #0x101b9c
00100df0  cmp      w0, #0x4f3
00100df4  b.hs     #0x10287c
00100df8  ldp      x24, x25, [sp, #8]
00100dfc  cmp      w0, #0x4de
00100e00  b.ne     #0x12a8b4
00100e04  ldr      x1, [x20]
00100e08  mov      x0, x19
00100e0c  mov      w2, #4
00100e10  bl       #0x147630
00100e14  ldr      w8, [x19]
00100e18  cbnz     w8, #0x100318
00100e1c  ldr      x1, [x20]
00100e20  mov      x0, x19
00100e24  bl       #0x147734
00100e28  ldr      w8, [x19]
00100e2c  cbnz     w8, #0x100318
00100e30  mov      w1, w0
00100e34  ldp      x21, x0, [x20]
00100e38  bl       #0x147304
00100e3c  mov      w2, w0
00100e40  mov      x0, x19
00100e44  mov      x1, x21
00100e48  bl       #0x147630
00100e4c  ldr      w8, [x19]
00100e50  cbnz     w8, #0x100318
00100e54  ldr      x1, [x20]
00100e58  mov      x0, x19
00100e5c  mov      w2, #2
00100e60  bl       #0x147630
00100e64  ldr      w8, [x19]
00100e68  cbnz     w8, #0x100318
00100e6c  ldr      x1, [x20]
00100e70  mov      x0, x19
00100e74  mov      w2, #2
00100e78  bl       #0x147630
00100e7c  ldr      w8, [x19]
00100e80  cbnz     w8, #0x100318
00100e84  ldr      x8, [sp, #0x18]
00100e88  mov      x0, x19
00100e8c  mov      w2, #0x4f3
00100e90  b        #0x104938
00100e94  cmp      w0, #0x211
00100e98  b.hs     #0x128d8c
00100e9c  cmp      w0, #0x206
00100ea0  b.hs     #0x12935c
00100ea4  ldp      x24, x25, [sp, #8]
00100ea8  cmp      w0, #0x1fb
00100eac  b.ne     #0x12a8b4
00100eb0  ldr      x1, [x20]
00100eb4  mov      x0, x19
00100eb8  mov      w2, #0xf
00100ebc  bl       #0x147630
00100ec0  ldr      w8, [x19]
00100ec4  cbnz     w8, #0x100318
00100ec8  ldr      x1, [x20]
00100ecc  mov      x0, x19
00100ed0  bl       #0x147734
00100ed4  ldr      w8, [x19]
00100ed8  cbnz     w8, #0x100318
00100edc  mov      w21, w0
00100ee0  ldr      x1, [x20]
00100ee4  mov      x0, x19
00100ee8  bl       #0x147734
00100eec  ldr      w8, [x19]
00100ef0  cbnz     w8, #0x100318
00100ef4  mov      w3, w0
00100ef8  ldr      x1, [x26]
00100efc  mov      x0, x19
00100f00  mov      w2, w21
00100f04  bl       #0x146ed8
00100f08  ldr      w8, [x19]
00100f0c  cbnz     w8, #0x100318
00100f10  ldr      x1, [x26]
00100f14  mov      x0, x19
00100f18  bl       #0x147120
00100f1c  ldr      x8, [sp, #0x18]
00100f20  mov      x0, x19
00100f24  mov      w2, #0x206
00100f28  ldr      x1, [x8]
00100f2c  bl       #0x146470
00100f30  ldr      w8, [x19]
00100f34  cbnz     w8, #0x100318
00100f38  ldr      x1, [x20]
00100f3c  mov      x0, x19
00100f40  mov      w2, #9
00100f44  bl       #0x147630
00100f48  ldr      w8, [x19]
00100f4c  cbnz     w8, #0x100318
00100f50  ldr      x1, [x20]
00100f54  mov      x0, x19
00100f58  mov      w2, wzr
00100f5c  bl       #0x147630
00100f60  ldr      w8, [x19]
00100f64  cbnz     w8, #0x100318
00100f68  ldr      x1, [x20]
00100f6c  mov      x0, x19
00100f70  bl       #0x147734
00100f74  ldr      w8, [x19]
00100f78  cbnz     w8, #0x100318
00100f7c  mov      w21, w0
00100f80  ldr      x1, [x20]
00100f84  mov      x0, x19
00100f88  bl       #0x147734
00100f8c  ldr      w8, [x19]
00100f90  cbnz     w8, #0x100318
00100f94  add      x28, x20, w0, uxtw #3
00100f98  ldr      x0, [x28, #0x20]!
00100f9c  bl       #0x1472e8
00100fa0  mov      w22, w0
00100fa4  mov      w23, wzr
00100fa8  cmp      w22, w23
00100fac  b.eq     #0x101e88
00100fb0  ldr      x0, [x28]
00100fb4  mov      w1, w23
00100fb8  ldr      x24, [x26]
00100fbc  add      w25, w21, w23
00100fc0  bl       #0x147304
00100fc4  mov      w3, w0
00100fc8  mov      x0, x19
00100fcc  mov      x1, x24
00100fd0  mov      w2, w25
00100fd4  bl       #0x146ed8
00100fd8  ldp      x24, x25, [sp, #8]
00100fdc  add      w23, w23, #1
00100fe0  ldr      w8, [x19]
00100fe4  cbz      w8, #0x100fa8
00100fe8  b        #0x100318
00100fec  cmp      w0, #0x6f1
00100ff0  b.hs     #0x101c40
00100ff4  cmp      w0, #0x6d0
00100ff8  b.hs     #0x102984
00100ffc  ldp      x24, x25, [sp, #8]
00101000  cmp      w0, #0x6bb
00101004  b.ne     #0x12a8b4
00101008  ldr      x1, [x20]
0010100c  mov      x0, x19
00101010  mov      w2, #5
00101014  bl       #0x147630
00101018  ldr      w8, [x19]
0010101c  cbnz     w8, #0x100318
00101020  ldr      x1, [x20]
00101024  mov      x0, x19
00101028  bl       #0x147734
0010102c  ldr      w8, [x19]
00101030  cbnz     w8, #0x100318
00101034  mov      w1, w0
00101038  ldp      x21, x0, [x20]
0010103c  bl       #0x147304
00101040  mov      w2, w0
00101044  mov      x0, x19
00101048  mov      x1, x21
0010104c  bl       #0x147630
00101050  ldr      w8, [x19]
00101054  cbnz     w8, #0x100318
00101058  ldr      x1, [x20]
0010105c  mov      x0, x19
00101060  mov      w2, wzr
00101064  bl       #0x147630
00101068  ldr      w8, [x19]
0010106c  cbnz     w8, #0x100318
00101070  ldr      x1, [x20]
00101074  mov      x0, x19
00101078  mov      w2, #0x14
0010107c  bl       #0x147630
00101080  ldr      w8, [x19]
00101084  cbnz     w8, #0x100318
00101088  ldr      x8, [sp, #0x18]
0010108c  mov      x0, x19
00101090  mov      w2, #0x6d0
00101094  b        #0x104938
00101098  cmp      w0, #0x171
0010109c  b.hs     #0x12924c
001010a0  cmp      w0, #0x15f
001010a4  b.lo     #0x129520
001010a8  ldp      x24, x25, [sp, #8]
001010ac  b.ne     #0x12a8b4
001010b0  ldr      x1, [x20]
001010b4  mov      x0, x19
001010b8  mov      w2, #0xa
001010bc  bl       #0x147630
001010c0  ldr      w8, [x19]
001010c4  cbnz     w8, #0x100318
001010c8  ldr      x1, [x20]
001010cc  mov      x0, x19
001010d0  bl       #0x147734
001010d4  ldr      w8, [x19]
001010d8  cbnz     w8, #0x100318
001010dc  mov      w21, w0
001010e0  ldr      x1, [x20]
001010e4  mov      x0, x19
001010e8  bl       #0x147734
001010ec  ldr      w8, [x19]
001010f0  cbnz     w8, #0x100318
001010f4  mov      w3, w0
001010f8  ldr      x1, [x26]
001010fc  mov      x0, x19
00101100  mov      w2, w21
00101104  bl       #0x146ed8
00101108  ldr      w8, [x19]
0010110c  cbnz     w8, #0x100318
00101110  ldr      x1, [x20]
00101114  mov      x0, x19
00101118  mov      w2, #9
0010111c  bl       #0x147630
00101120  ldr      w8, [x19]
00101124  cbnz     w8, #0x100318
00101128  ldr      x1, [x20]
0010112c  mov      x0, x19
00101130  bl       #0x147734
00101134  ldr      w8, [x19]
00101138  cbnz     w8, #0x100318
0010113c  mov      w1, w0
00101140  ldp      x21, x0, [x20]
00101144  bl       #0x147304
00101148  mov      w2, w0
0010114c  mov      x0, x19
00101150  mov      x1, x21
00101154  bl       #0x147630
00101158  ldr      w8, [x19]
0010115c  cbnz     w8, #0x100318
00101160  ldr      x1, [x20]
00101164  mov      x0, x19
00101168  bl       #0x147734
0010116c  ldr      w8, [x19]
00101170  cbnz     w8, #0x100318
00101174  mov      w1, w0
00101178  ldp      x21, x0, [x20]
0010117c  bl       #0x147304
00101180  mov      w2, w0
00101184  mov      x0, x19
00101188  mov      x1, x21
0010118c  bl       #0x147630
00101190  ldr      w8, [x19]
00101194  cbnz     w8, #0x100318
00101198  ldr      x1, [x26]
0010119c  mov      x0, x19
001011a0  bl       #0x147120
001011a4  ldr      x8, [sp, #0x18]
001011a8  mov      x0, x19
001011ac  mov      w2, #0x171
001011b0  b        #0x1030b4
001011b4  cmp      w0, #0x625
001011b8  b.hs     #0x101ce4
001011bc  cmp      w0, #0x5ed
001011c0  b.hs     #0x102acc
001011c4  ldp      x24, x25, [sp, #8]
001011c8  cmp      w0, #0x583
001011cc  b.ne     #0x12a8b4
001011d0  ldr      x1, [x20]
001011d4  mov      x0, x19
001011d8  mov      w2, #0x12
001011dc  bl       #0x147630
001011e0  ldr      w8, [x19]
001011e4  cbnz     w8, #0x100318
001011e8  ldr      x1, [x20]
001011ec  mov      x0, x19
001011f0  bl       #0x147734
001011f4  ldr      w8, [x19]
001011f8  cbnz     w8, #0x100318
001011fc  mov      w1, w0
00101200  ldp      x21, x0, [x20]
00101204  bl       #0x147304
00101208  mov      w2, w0
0010120c  mov      x0, x19
00101210  mov      x1, x21
00101214  bl       #0x147630
00101218  ldr      w8, [x19]
0010121c  cbnz     w8, #0x100318
00101220  ldr      x1, [x20]
00101224  mov      x0, x19
00101228  mov      w2, wzr
0010122c  bl       #0x147630
00101230  ldr      w8, [x19]
00101234  cbnz     w8, #0x100318
00101238  ldr      x1, [x20]
0010123c  mov      x0, x19
00101240  bl       #0x147734
00101244  ldr      w8, [x19]
00101248  cbnz     w8, #0x100318
0010124c  mov      w22, w0
00101250  cmp      w0, #0xf
00101254  b.hi     #0x12aa34
00101258  ldr      x1, [x20]
0010125c  mov      x0, x19
00101260  bl       #0x147734
00101264  ldp      x24, x25, [sp, #8]
00101268  ldr      w8, [x19]
0010126c  cbnz     w8, #0x100318
00101270  mov      w21, w0
00101274  ldr      x1, [x20]
00101278  mov      x0, x19
0010127c  bl       #0x147734
00101280  ldr      w8, [x19]
00101284  cbnz     w8, #0x100318
00101288  add      x28, x20, w22, uxtw #3
0010128c  mov      w23, w0
00101290  mov      x0, x19
00101294  ldr      x1, [x28, #0x20]!
00101298  bl       #0x147220
0010129c  ldr      w8, [x19]
001012a0  cbnz     w8, #0x100318
001012a4  ldr      x1, [x28]
001012a8  mov      x0, x19
001012ac  bl       #0x147120
001012b0  ldr      w8, [x19]
001012b4  cbnz     w8, #0x100318
001012b8  mov      w22, wzr
001012bc  add      w27, w23, w21
001012c0  add      w1, w21, w22
001012c4  cmp      w1, w27
001012c8  b.hs     #0x105814
001012cc  ldr      x0, [x26]
001012d0  ldr      x23, [x28]
001012d4  bl       #0x147304
001012d8  mov      w3, w0
001012dc  mov      x0, x19
001012e0  mov      x1, x23
001012e4  mov      w2, w22
001012e8  bl       #0x146ed8
001012ec  ldp      x24, x25, [sp, #8]
001012f0  add      w22, w22, #1
001012f4  ldr      w8, [x19]
001012f8  cbz      w8, #0x1012c0
001012fc  b        #0x100318
00101300  cmp      w0, #0x319
00101304  b.lo     #0x128eec
00101308  cmp      w0, #0x329
0010130c  b.lo     #0x129888
00101310  ldp      x24, x25, [sp, #8]
00101314  b.ne     #0x12a8b4
00101318  ldr      x1, [x20]
0010131c  mov      x0, x19
00101320  mov      w2, #0x17
00101324  bl       #0x147630
00101328  ldr      w8, [x19]
0010132c  cbnz     w8, #0x100318
00101330  ldr      x1, [x20]
00101334  mov      x0, x19
00101338  bl       #0x147734
0010133c  ldr      w8, [x19]
00101340  cbnz     w8, #0x100318
00101344  mov      w21, w0
00101348  ldr      x1, [x20]
0010134c  mov      x0, x19
00101350  bl       #0x147734
00101354  ldr      w8, [x19]
00101358  cbnz     w8, #0x100318
0010135c  mov      w3, w0
00101360  ldr      x1, [x26]
00101364  mov      x0, x19
00101368  mov      w2, w21
0010136c  bl       #0x146ed8
00101370  ldr      w8, [x19]
00101374  cbnz     w8, #0x100318
00101378  ldr      x1, [x20]
0010137c  mov      x0, x19
00101380  mov      w2, #0x17
00101384  bl       #0x147630
00101388  ldr      w8, [x19]
0010138c  cbnz     w8, #0x100318
00101390  ldr      x1, [x20]
00101394  mov      x0, x19
00101398  bl       #0x147734
0010139c  ldr      w8, [x19]
001013a0  cbnz     w8, #0x100318
001013a4  mov      w1, w0
001013a8  ldp      x21, x0, [x20]
001013ac  bl       #0x147304
001013b0  mov      w2, w0
001013b4  mov      x0, x19
001013b8  mov      x1, x21
001013bc  bl       #0x147630
001013c0  ldr      w8, [x19]
001013c4  cbnz     w8, #0x100318
001013c8  ldr      x1, [x20]
001013cc  mov      x0, x19
001013d0  mov      w2, #1
001013d4  bl       #0x147630
001013d8  ldr      w8, [x19]
001013dc  cbnz     w8, #0x100318
001013e0  ldr      x1, [x20]
001013e4  mov      x0, x19
001013e8  mov      w2, #1
001013ec  bl       #0x147a20
001013f0  ldr      w8, [x19]
001013f4  cbnz     w8, #0x100318
001013f8  ldr      x1, [x20]
001013fc  mov      x0, x19
00101400  mov      w2, #1
00101404  bl       #0x147630
00101408  ldr      w8, [x19]
0010140c  cbnz     w8, #0x100318
00101410  ldr      x1, [x20]
00101414  mov      x0, x19
00101418  bl       #0x147734
0010141c  ldr      w8, [x19]
00101420  cbnz     w8, #0x100318
00101424  ldr      x8, [sp]
00101428  mov      w2, w0
0010142c  mov      x0, x19
00101430  ldr      x1, [x8]
00101434  bl       #0x146558
00101438  ldr      w8, [x19]
0010143c  cbnz     w8, #0x100318
00101440  ldr      x1, [x20]
00101444  mov      x0, x19
00101448  bl       #0x147734
0010144c  ldr      w8, [x19]
00101450  cbnz     w8, #0x100318
00101454  mov      w21, w0
00101458  ldr      x1, [x20]
0010145c  mov      x0, x19
00101460  bl       #0x147734
00101464  ldr      w8, [x19]
00101468  cbnz     w8, #0x100318
0010146c  mov      w3, w0
00101470  ldr      x1, [x26]
00101474  mov      x0, x19
00101478  mov      w2, w21
0010147c  bl       #0x146ed8
00101480  ldr      w8, [x19]
00101484  cbnz     w8, #0x100318
00101488  ldr      x8, [sp]
0010148c  ldr      x0, [x8]
00101490  bl       #0x146650
00101494  cbnz     w0, #0x101440
00101498  ldr      x1, [x20]
0010149c  mov      x0, x19
001014a0  mov      w2, #4
001014a4  bl       #0x147630
001014a8  ldr      w8, [x19]
001014ac  cbnz     w8, #0x100318
001014b0  ldr      x1, [x20]
001014b4  mov      x0, x19
001014b8  mov      w2, #6
001014bc  bl       #0x147630
001014c0  ldr      w8, [x19]
001014c4  cbnz     w8, #0x100318
001014c8  ldr      x1, [x20]
001014cc  mov      x0, x19
001014d0  bl       #0x147734
001014d4  ldr      w8, [x19]
001014d8  cbnz     w8, #0x100318
001014dc  mov      w1, w0
001014e0  ldp      x21, x0, [x20]
001014e4  bl       #0x147304
001014e8  mov      w2, w0
001014ec  mov      x0, x19
001014f0  mov      x1, x21
001014f4  bl       #0x147630
001014f8  ldr      w8, [x19]
001014fc  cbnz     w8, #0x100318
00101500  ldr      x1, [x20]
00101504  mov      x0, x19
00101508  mov      w2, wzr
0010150c  bl       #0x147630
00101510  ldr      w8, [x19]
00101514  cbnz     w8, #0x100318
00101518  ldr      x1, [x20]
0010151c  mov      x0, x19
00101520  bl       #0x147734
00101524  ldr      w8, [x19]
00101528  cbnz     w8, #0x100318
0010152c  mov      w22, w0
00101530  cmp      w0, #0xf
00101534  b.hi     #0x12aa34
00101538  ldr      x1, [x20]
0010153c  mov      x0, x19
00101540  bl       #0x147734
00101544  ldp      x24, x25, [sp, #8]
00101548  ldr      w8, [x19]
0010154c  cbnz     w8, #0x100318
00101550  mov      w21, w0
00101554  ldr      x1, [x20]
00101558  mov      x0, x19
0010155c  bl       #0x147734
00101560  ldr      w8, [x19]
00101564  cbnz     w8, #0x100318
00101568  add      x28, x20, w22, uxtw #3
0010156c  mov      w23, w0
00101570  mov      x0, x19
00101574  ldr      x1, [x28, #0x20]!
00101578  bl       #0x147220
0010157c  ldr      w8, [x19]
00101580  cbnz     w8, #0x100318
00101584  ldr      x1, [x28]
00101588  mov      x0, x19
0010158c  bl       #0x147120
00101590  ldr      w8, [x19]
00101594  cbnz     w8, #0x100318
00101598  mov      w22, wzr
0010159c  add      w27, w23, w21
001015a0  add      w1, w21, w22
001015a4  cmp      w1, w27
001015a8  b.hs     #0x106018
001015ac  ldr      x0, [x26]
001015b0  ldr      x23, [x28]
001015b4  bl       #0x147304
001015b8  mov      w3, w0
001015bc  mov      x0, x19
001015c0  mov      x1, x23
001015c4  mov      w2, w22
001015c8  bl       #0x146ed8
001015cc  ldp      x24, x25, [sp, #8]
001015d0  add      w22, w22, #1
001015d4  ldr      w8, [x19]
001015d8  cbz      w8, #0x1015a0
001015dc  b        #0x100318
001015e0  cmp      w0, #0x7d3
001015e4  b.hs     #0x101d88
001015e8  cmp      w0, #0x7a8
001015ec  b.hs     #0x102bc0
001015f0  ldp      x24, x25, [sp, #8]
001015f4  cmp      w0, #0x793
001015f8  b.ne     #0x12a8b4
001015fc  ldr      x1, [x20]
00101600  mov      x0, x19
00101604  mov      w2, #0x18
00101608  bl       #0x147630
0010160c  ldr      w8, [x19]
00101610  cbnz     w8, #0x100318
00101614  ldr      x1, [x20]
00101618  mov      x0, x19
0010161c  bl       #0x147734
00101620  ldr      w8, [x19]
00101624  cbnz     w8, #0x100318
00101628  mov      w1, w0
0010162c  ldp      x21, x0, [x20]
00101630  bl       #0x147304
00101634  mov      w2, w0
00101638  mov      x0, x19
0010163c  mov      x1, x21
00101640  bl       #0x147630
00101644  ldr      w8, [x19]
00101648  cbnz     w8, #0x100318
0010164c  ldr      x1, [x20]
00101650  mov      x0, x19
00101654  mov      w2, wzr
00101658  bl       #0x147630
0010165c  ldr      w8, [x19]
00101660  cbnz     w8, #0x100318
00101664  ldr      x1, [x20]
00101668  mov      x0, x19
0010166c  mov      w2, #0x10
00101670  bl       #0x147630
00101674  ldr      w8, [x19]
00101678  cbnz     w8, #0x100318
0010167c  ldr      x8, [sp, #0x18]
00101680  mov      x0, x19
00101684  mov      w2, #0x7a8
00101688  b        #0x104938
0010168c  cmp      w0, #0x467
00101690  b.hs     #0x102da8
00101694  ldp      x24, x25, [sp, #8]
00101698  cmp      w0, #0x3e5
0010169c  b.ne     #0x12a8b4
001016a0  ldr      x1, [x20]
001016a4  mov      x0, x19
001016a8  mov      w2, #0xd
001016ac  bl       #0x147630
001016b0  ldr      w8, [x19]
001016b4  cbnz     w8, #0x100318
001016b8  ldr      x1, [x20]
001016bc  mov      x0, x19
001016c0  bl       #0x147734
001016c4  ldr      w8, [x19]
001016c8  cbnz     w8, #0x100318
001016cc  mov      w1, w0
001016d0  ldp      x21, x0, [x20]
001016d4  bl       #0x147304
001016d8  mov      w2, w0
001016dc  mov      x0, x19
001016e0  mov      x1, x21
001016e4  bl       #0x147630
001016e8  ldr      w8, [x19]
001016ec  cbnz     w8, #0x100318
001016f0  ldr      x1, [x20]
001016f4  mov      x0, x19
001016f8  bl       #0x147734
001016fc  ldr      w8, [x19]
00101700  cbnz     w8, #0x100318
00101704  mov      w1, w0
00101708  ldp      x21, x0, [x20]
0010170c  bl       #0x147304
00101710  mov      w2, w0
00101714  mov      x0, x19
00101718  mov      x1, x21
0010171c  bl       #0x147630
00101720  ldr      w8, [x19]
00101724  cbnz     w8, #0x100318
00101728  ldr      x1, [x20]
0010172c  mov      x0, x19
00101730  mov      w2, #0xe
00101734  bl       #0x147630
00101738  ldr      w8, [x19]
0010173c  cbnz     w8, #0x100318
00101740  ldr      x1, [x20]
00101744  mov      x0, x19
00101748  bl       #0x147734
0010174c  ldr      w8, [x19]
00101750  cbnz     w8, #0x100318
00101754  mov      w1, w0
00101758  ldp      x21, x0, [x20]
0010175c  bl       #0x147304
00101760  mov      w2, w0
00101764  mov      x0, x19
00101768  mov      x1, x21
0010176c  bl       #0x147630
00101770  ldr      w8, [x19]
00101774  cbnz     w8, #0x100318
00101778  ldr      x1, [x20]
0010177c  mov      x0, x19
00101780  mov      w2, wzr
00101784  bl       #0x147630
00101788  ldr      w8, [x19]
0010178c  cbnz     w8, #0x100318
00101790  ldr      x1, [x20]
00101794  mov      x0, x19
00101798  bl       #0x147734
0010179c  ldr      w8, [x19]
001017a0  cbnz     w8, #0x100318
001017a4  mov      w22, w0
001017a8  cmp      w0, #0xf
001017ac  b.hi     #0x12aa34
001017b0  ldr      x1, [x20]
001017b4  mov      x0, x19
001017b8  bl       #0x147734
001017bc  ldp      x24, x25, [sp, #8]
001017c0  ldr      w8, [x19]
001017c4  cbnz     w8, #0x100318
001017c8  mov      w21, w0
001017cc  ldr      x1, [x20]
001017d0  mov      x0, x19
001017d4  bl       #0x147734
001017d8  ldr      w8, [x19]
001017dc  cbnz     w8, #0x100318
001017e0  add      x28, x20, w22, uxtw #3
001017e4  mov      w23, w0
001017e8  mov      x0, x19
001017ec  ldr      x1, [x28, #0x20]!
001017f0  bl       #0x147220
001017f4  ldr      w8, [x19]
001017f8  cbnz     w8, #0x100318
001017fc  ldr      x1, [x28]
00101800  mov      x0, x19
00101804  bl       #0x147120
00101808  ldr      w8, [x19]
0010180c  cbnz     w8, #0x100318
00101810  mov      w22, wzr
00101814  add      w27, w23, w21
00101818  add      w1, w21, w22
0010181c  cmp      w1, w27
00101820  b.hs     #0x105ce8
00101824  ldr      x0, [x26]
00101828  ldr      x23, [x28]
0010182c  bl       #0x147304
00101830  mov      w3, w0
00101834  mov      x0, x19
00101838  mov      x1, x23
0010183c  mov      w2, w22
00101840  bl       #0x146ed8
00101844  ldp      x24, x25, [sp, #8]
00101848  add      w22, w22, #1
0010184c  ldr      w8, [x19]
00101850  cbz      w8, #0x101818
00101854  b        #0x100318
00101858  cmp      w0, #0x69a
0010185c  b.hs     #0x102e9c
00101860  ldp      x24, x25, [sp, #8]
00101864  cmp      w0, #0x685
00101868  b.ne     #0x12a8b4
0010186c  ldr      x1, [x20]
00101870  mov      x0, x19
00101874  mov      w2, #8
00101878  bl       #0x147630
0010187c  ldr      w8, [x19]
00101880  cbnz     w8, #0x100318
00101884  ldr      x1, [x20]
00101888  mov      x0, x19
0010188c  bl       #0x147734
00101890  ldr      w8, [x19]
00101894  cbnz     w8, #0x100318
00101898  mov      w1, w0
0010189c  ldp      x21, x0, [x20]
001018a0  bl       #0x147304
001018a4  mov      w2, w0
001018a8  mov      x0, x19
001018ac  mov      x1, x21
001018b0  bl       #0x147630
001018b4  ldr      w8, [x19]
001018b8  cbnz     w8, #0x100318
001018bc  ldr      x1, [x20]
001018c0  mov      x0, x19
001018c4  mov      w2, wzr
001018c8  bl       #0x147630
001018cc  ldr      w8, [x19]
001018d0  cbnz     w8, #0x100318
001018d4  ldr      x1, [x20]
001018d8  mov      x0, x19
001018dc  mov      w2, #4
001018e0  bl       #0x147630
001018e4  ldr      w8, [x19]
001018e8  cbnz     w8, #0x100318
001018ec  ldr      x8, [sp, #0x18]
001018f0  mov      x0, x19
001018f4  mov      w2, #0x69a
001018f8  b        #0x104938
001018fc  cmp      w0, #0x575
00101900  b.hs     #0x102fe4
00101904  ldp      x24, x25, [sp, #8]
00101908  cmp      w0, #0x55e
0010190c  b.ne     #0x12a8b4
00101910  ldr      x1, [x20]
00101914  mov      x0, x19
00101918  mov      w2, #0xb
0010191c  bl       #0x147630
00101920  ldr      w8, [x19]
00101924  cbnz     w8, #0x100318
00101928  ldr      x1, [x20]
0010192c  mov      x0, x19
00101930  bl       #0x147734
00101934  ldr      w8, [x19]
00101938  cbnz     w8, #0x100318
0010193c  mov      w1, w0
00101940  ldp      x21, x0, [x20]
00101944  bl       #0x147304
00101948  mov      w2, w0
0010194c  mov      x0, x19
00101950  mov      x1, x21
00101954  bl       #0x147630
00101958  ldr      w8, [x19]
0010195c  cbnz     w8, #0x100318
00101960  ldr      x1, [x20]
00101964  mov      x0, x19
00101968  mov      w2, wzr
0010196c  bl       #0x147630
00101970  ldr      w8, [x19]
00101974  cbnz     w8, #0x100318
00101978  ldr      x1, [x20]
0010197c  mov      x0, x19
00101980  mov      w2, #9
00101984  bl       #0x147630
00101988  ldr      w8, [x19]
0010198c  cbnz     w8, #0x100318
00101990  ldr      x1, [x20]
00101994  mov      x0, x19
00101998  bl       #0x147734
0010199c  ldr      w8, [x19]
001019a0  cbnz     w8, #0x100318
001019a4  mov      w1, w0
001019a8  ldp      x21, x0, [x20]
001019ac  bl       #0x147304
001019b0  mov      w2, w0
001019b4  mov      x0, x19
001019b8  mov      x1, x21
001019bc  bl       #0x147630
001019c0  ldr      w8, [x19]
001019c4  cbnz     w8, #0x100318
001019c8  ldr      x1, [x20]
001019cc  mov      x0, x19
001019d0  bl       #0x147734
001019d4  ldr      w8, [x19]
001019d8  cbnz     w8, #0x100318
001019dc  mov      w1, w0
001019e0  ldp      x21, x0, [x20]
001019e4  bl       #0x147304
001019e8  mov      w2, w0
001019ec  mov      x0, x19
001019f0  mov      x1, x21
001019f4  bl       #0x147630
001019f8  ldr      w8, [x19]
001019fc  cbnz     w8, #0x100318
00101a00  ldr      x8, [sp, #0x18]
00101a04  mov      x0, x19
00101a08  mov      w2, #0x575
00101a0c  b        #0x104938
00101a10  cmp      w0, #0x772
00101a14  b.hs     #0x103290
00101a18  ldp      x24, x25, [sp, #8]
00101a1c  cmp      w0, #0x75d
00101a20  b.ne     #0x12a8b4
00101a24  ldr      x1, [x20]
00101a28  mov      x0, x19
00101a2c  mov      w2, #0x17
00101a30  bl       #0x147630
00101a34  ldr      w8, [x19]
00101a38  cbnz     w8, #0x100318
00101a3c  ldr      x1, [x20]
00101a40  mov      x0, x19
00101a44  bl       #0x147734
00101a48  ldr      w8, [x19]
00101a4c  cbnz     w8, #0x100318
00101a50  mov      w1, w0
00101a54  ldp      x21, x0, [x20]
00101a58  bl       #0x147304
00101a5c  mov      w2, w0
00101a60  mov      x0, x19
00101a64  mov      x1, x21
00101a68  bl       #0x147630
00101a6c  ldr      w8, [x19]
00101a70  cbnz     w8, #0x100318
00101a74  ldr      x1, [x20]
00101a78  mov      x0, x19
00101a7c  mov      w2, #3
00101a80  bl       #0x147630
00101a84  ldr      w8, [x19]
00101a88  cbnz     w8, #0x100318
00101a8c  ldr      x1, [x20]
00101a90  mov      x0, x19
00101a94  mov      w2, #1
00101a98  bl       #0x147630
00101a9c  ldr      w8, [x19]
00101aa0  cbnz     w8, #0x100318
00101aa4  ldr      x8, [sp, #0x18]
00101aa8  mov      x0, x19
00101aac  mov      w2, #0x772
00101ab0  b        #0x104938
00101ab4  cmp      w0, #0xe6
00101ab8  b.hs     #0x1033d8
00101abc  ldp      x24, x25, [sp, #8]
00101ac0  cmp      w0, #0xd0
00101ac4  b.ne     #0x12a8b4
00101ac8  ldr      x1, [x20]
00101acc  mov      x0, x19
00101ad0  mov      w2, #6
00101ad4  bl       #0x147630
00101ad8  ldr      w8, [x19]
00101adc  cbnz     w8, #0x100318
00101ae0  ldr      x1, [x20]
00101ae4  mov      x0, x19
00101ae8  bl       #0x147734
00101aec  ldr      w8, [x19]
00101af0  cbnz     w8, #0x100318
00101af4  mov      w1, w0
00101af8  ldp      x21, x0, [x20]
00101afc  bl       #0x147304
00101b00  mov      w2, w0
00101b04  mov      x0, x19
00101b08  mov      x1, x21
00101b0c  bl       #0x147630
00101b10  ldr      w8, [x19]
00101b14  cbnz     w8, #0x100318
00101b18  ldr      x1, [x20]
00101b1c  mov      x0, x19
00101b20  mov      w2, #2
00101b24  bl       #0x147630
00101b28  ldr      w8, [x19]
00101b2c  cbnz     w8, #0x100318
00101b30  ldr      x1, [x20]
00101b34  mov      x0, x19
00101b38  bl       #0x147734
00101b3c  ldr      w8, [x19]
00101b40  cbnz     w8, #0x100318
00101b44  mov      w21, w0
00101b48  ldr      x1, [x20]
00101b4c  mov      x0, x19
00101b50  bl       #0x147734
00101b54  ldr      w8, [x19]
00101b58  cbnz     w8, #0x100318
00101b5c  ldr      x1, [x20]
00101b60  add      w2, w0, w21
00101b64  mov      x0, x19
00101b68  bl       #0x147630
00101b6c  ldr      w8, [x19]
00101b70  cbnz     w8, #0x100318
00101b74  ldr      x1, [x20]
00101b78  mov      x0, x19
00101b7c  mov      w2, #2
00101b80  bl       #0x147630
00101b84  ldr      w8, [x19]
00101b88  cbnz     w8, #0x100318
00101b8c  ldr      x8, [sp, #0x18]
00101b90  mov      x0, x19
00101b94  mov      w2, #0xe6
00101b98  b        #0x101f70
00101b9c  cmp      w0, #0x51f
00101ba0  b.hs     #0x1037d4
00101ba4  ldp      x24, x25, [sp, #8]
00101ba8  cmp      w0, #0x50a
00101bac  b.ne     #0x12a8b4
00101bb0  ldr      x1, [x20]
00101bb4  mov      x0, x19
00101bb8  mov      w2, #8
00101bbc  bl       #0x147630
00101bc0  ldr      w8, [x19]
00101bc4  cbnz     w8, #0x100318
00101bc8  ldr      x1, [x20]
00101bcc  mov      x0, x19
00101bd0  bl       #0x147734
00101bd4  ldr      w8, [x19]
00101bd8  cbnz     w8, #0x100318
00101bdc  mov      w1, w0
00101be0  ldp      x21, x0, [x20]
00101be4  bl       #0x147304
00101be8  mov      w2, w0
00101bec  mov      x0, x19
00101bf0  mov      x1, x21
00101bf4  bl       #0x147630
00101bf8  ldr      w8, [x19]
00101bfc  cbnz     w8, #0x100318
00101c00  ldr      x1, [x20]
00101c04  mov      x0, x19
00101c08  mov      w2, wzr
00101c0c  bl       #0x147630
00101c10  ldr      w8, [x19]
00101c14  cbnz     w8, #0x100318
00101c18  ldr      x1, [x20]
00101c1c  mov      x0, x19
00101c20  mov      w2, #4
00101c24  bl       #0x147630
00101c28  ldr      w8, [x19]
00101c2c  cbnz     w8, #0x100318
00101c30  ldr      x8, [sp, #0x18]
00101c34  mov      x0, x19
00101c38  mov      w2, #0x51f
00101c3c  b        #0x104938
00101c40  cmp      w0, #0x706
00101c44  b.hs     #0x10386c
00101c48  ldp      x24, x25, [sp, #8]
00101c4c  cmp      w0, #0x6f1
00101c50  b.ne     #0x12a8b4
00101c54  ldr      x1, [x20]
00101c58  mov      x0, x19
00101c5c  mov      w2, #0x10
00101c60  bl       #0x147630
00101c64  ldr      w8, [x19]
00101c68  cbnz     w8, #0x100318
00101c6c  ldr      x1, [x20]
00101c70  mov      x0, x19
00101c74  bl       #0x147734
00101c78  ldr      w8, [x19]
00101c7c  cbnz     w8, #0x100318
00101c80  mov      w1, w0
00101c84  ldp      x21, x0, [x20]
00101c88  bl       #0x147304
00101c8c  mov      w2, w0
00101c90  mov      x0, x19
00101c94  mov      x1, x21
00101c98  bl       #0x147630
00101c9c  ldr      w8, [x19]
00101ca0  cbnz     w8, #0x100318
00101ca4  ldr      x1, [x20]
00101ca8  mov      x0, x19
00101cac  mov      w2, wzr
00101cb0  bl       #0x147630
00101cb4  ldr      w8, [x19]
00101cb8  cbnz     w8, #0x100318
00101cbc  ldr      x1, [x20]
00101cc0  mov      x0, x19
00101cc4  mov      w2, #0x20
00101cc8  bl       #0x147630
00101ccc  ldr      w8, [x19]
00101cd0  cbnz     w8, #0x100318
00101cd4  ldr      x8, [sp, #0x18]
00101cd8  mov      x0, x19
00101cdc  mov      w2, #0x706
00101ce0  b        #0x104938
00101ce4  cmp      w0, #0x63a
00101ce8  b.hs     #0x1039b4
00101cec  ldp      x24, x25, [sp, #8]
00101cf0  cmp      w0, #0x625
00101cf4  b.ne     #0x12a8b4
00101cf8  ldr      x1, [x20]
00101cfc  mov      x0, x19
00101d00  mov      w2, #4
00101d04  bl       #0x147630
00101d08  ldr      w8, [x19]
00101d0c  cbnz     w8, #0x100318
00101d10  ldr      x1, [x20]
00101d14  mov      x0, x19
00101d18  bl       #0x147734
00101d1c  ldr      w8, [x19]
00101d20  cbnz     w8, #0x100318
00101d24  mov      w1, w0
00101d28  ldp      x21, x0, [x20]
00101d2c  bl       #0x147304
00101d30  mov      w2, w0
00101d34  mov      x0, x19
00101d38  mov      x1, x21
00101d3c  bl       #0x147630
00101d40  ldr      w8, [x19]
00101d44  cbnz     w8, #0x100318
00101d48  ldr      x1, [x20]
00101d4c  mov      x0, x19
00101d50  mov      w2, #2
00101d54  bl       #0x147630
00101d58  ldr      w8, [x19]
00101d5c  cbnz     w8, #0x100318
00101d60  ldr      x1, [x20]
00101d64  mov      x0, x19
00101d68  mov      w2, #2
00101d6c  bl       #0x147630
00101d70  ldr      w8, [x19]
00101d74  cbnz     w8, #0x100318
00101d78  ldr      x8, [sp, #0x18]
00101d7c  mov      x0, x19
00101d80  mov      w2, #0x63a
00101d84  b        #0x104938
00101d88  cmp      w0, #0x83f
00101d8c  b.hs     #0x103abc
00101d90  ldp      x24, x25, [sp, #8]
00101d94  cmp      w0, #0x7d3
00101d98  b.ne     #0x12a8b4
00101d9c  ldr      x1, [x20]
00101da0  mov      x0, x19
00101da4  mov      w2, wzr
00101da8  bl       #0x147630
00101dac  ldr      w8, [x19]
00101db0  cbnz     w8, #0x100318
00101db4  ldr      x1, [x20]
00101db8  mov      x0, x19
00101dbc  mov      w2, #0x16
00101dc0  bl       #0x147630
00101dc4  ldr      w8, [x19]
00101dc8  cbnz     w8, #0x100318
00101dcc  ldr      x1, [x20]
00101dd0  mov      x0, x19
00101dd4  bl       #0x147734
00101dd8  ldr      w8, [x19]
00101ddc  cbnz     w8, #0x100318
00101de0  mov      w1, w0
00101de4  ldp      x21, x0, [x20]
00101de8  bl       #0x147304
00101dec  mov      w2, w0
00101df0  mov      x0, x19
00101df4  mov      x1, x21
00101df8  bl       #0x147630
00101dfc  ldr      w8, [x19]
00101e00  cbnz     w8, #0x100318
00101e04  ldr      x1, [x20]
00101e08  mov      x0, x19
00101e0c  bl       #0x147734
00101e10  ldr      w8, [x19]
00101e14  cbnz     w8, #0x100318
00101e18  mov      w21, w0
00101e1c  ldr      x1, [x20]
00101e20  mov      x0, x19
00101e24  bl       #0x147734
00101e28  ldr      w8, [x19]
00101e2c  cbnz     w8, #0x100318
00101e30  add      x28, x20, w0, uxtw #3
00101e34  ldr      x0, [x28, #0x20]!
00101e38  bl       #0x1472e8
00101e3c  mov      w22, w0
00101e40  mov      w23, wzr
00101e44  cmp      w22, w23
00101e48  b.eq     #0x104344
00101e4c  ldr      x0, [x28]
00101e50  mov      w1, w23
00101e54  ldr      x24, [x26]
00101e58  add      w25, w21, w23
00101e5c  bl       #0x147304
00101e60  mov      w3, w0
00101e64  mov      x0, x19
00101e68  mov      x1, x24
00101e6c  mov      w2, w25
00101e70  bl       #0x146ed8
00101e74  ldp      x24, x25, [sp, #8]
00101e78  add      w23, w23, #1
00101e7c  ldr      w8, [x19]
00101e80  cbz      w8, #0x101e44
00101e84  b        #0x100318
00101e88  ldr      x1, [x20]
00101e8c  mov      x0, x19
00101e90  mov      w2, wzr
00101e94  bl       #0x147630
00101e98  ldp      x24, x25, [sp, #8]
00101e9c  ldr      w8, [x19]
00101ea0  cbnz     w8, #0x100318
00101ea4  ldr      x1, [x20]
00101ea8  mov      x0, x19
00101eac  bl       #0x147734
00101eb0  ldr      w8, [x19]
00101eb4  cbnz     w8, #0x100318
00101eb8  mov      w1, w0
00101ebc  ldp      x21, x0, [x20]
00101ec0  bl       #0x147304
00101ec4  mov      w2, w0
00101ec8  mov      x0, x19
00101ecc  mov      x1, x21
00101ed0  bl       #0x147630
00101ed4  ldr      w8, [x19]
00101ed8  cbnz     w8, #0x100318
00101edc  ldr      x1, [x26]
00101ee0  mov      x0, x19
00101ee4  bl       #0x147120
00101ee8  ldr      x8, [sp, #0x18]
00101eec  mov      x0, x19
00101ef0  mov      w2, #0xcdb
00101ef4  b        #0x1030b4
00101ef8  ldr      x1, [x20]
00101efc  mov      x0, x19
00101f00  mov      w2, #6
00101f04  bl       #0x147630
00101f08  ldp      x24, x25, [sp, #8]
00101f0c  ldr      w8, [x19]
00101f10  cbnz     w8, #0x100318
00101f14  ldr      x1, [x20]
00101f18  mov      x0, x19
00101f1c  bl       #0x147734
00101f20  ldr      w8, [x19]
00101f24  cbnz     w8, #0x100318
00101f28  mov      w1, w0
00101f2c  ldp      x21, x0, [x20]
00101f30  bl       #0x147304
00101f34  mov      w2, w0
00101f38  mov      x0, x19
00101f3c  mov      x1, x21
00101f40  bl       #0x147630
00101f44  ldr      w8, [x19]
00101f48  cbnz     w8, #0x100318
00101f4c  ldr      x1, [x20]
00101f50  mov      x0, x19
00101f54  mov      w2, #2
00101f58  bl       #0x147630
00101f5c  ldr      w8, [x19]
00101f60  cbnz     w8, #0x100318
00101f64  ldr      x8, [sp, #0x18]
00101f68  mov      x0, x19
00101f6c  mov      w2, #0xbb
00101f70  ldr      x1, [x8]
00101f74  bl       #0x146470
00101f78  ldr      w8, [x19]
00101f7c  cbnz     w8, #0x100318
00101f80  ldr      x1, [x20]
00101f84  mov      x0, x19
00101f88  bl       #0x147a18
00101f8c  ldr      w8, [x19]
00101f90  cbnz     w8, #0x100318
00101f94  ldr      x1, [x20]
00101f98  mov      x0, x19
00101f9c  mov      w2, #2
00101fa0  bl       #0x147a20
00101fa4  ldr      w8, [x19]
00101fa8  cbnz     w8, #0x100318
00101fac  ldr      x1, [x20]
00101fb0  mov      x0, x19
00101fb4  bl       #0x147734
00101fb8  ldr      w8, [x19]
00101fbc  cbnz     w8, #0x100318
00101fc0  mov      w21, w0
00101fc4  ldr      x1, [x20]
00101fc8  mov      x0, x19
00101fcc  bl       #0x147734
00101fd0  ldr      w8, [x19]
00101fd4  cbnz     w8, #0x100318
00101fd8  ldr      x1, [x20]
00101fdc  add      w2, w0, w21
00101fe0  mov      x0, x19
00101fe4  bl       #0x147630
00101fe8  ldr      w8, [x19]
00101fec  cbnz     w8, #0x100318
00101ff0  ldr      x1, [x20]
00101ff4  mov      x0, x19
00101ff8  bl       #0x147734
00101ffc  ldr      w8, [x19]
00102000  cbnz     w8, #0x100318
00102004  ldr      x1, [x20]
00102008  sub      w2, w0, #1
0010200c  mov      x0, x19
00102010  bl       #0x147630
00102014  ldr      w8, [x19]
00102018  cbnz     w8, #0x100318
0010201c  ldr      x1, [x20]
00102020  mov      x0, x19
00102024  mov      w2, #1
00102028  bl       #0x147a20
0010202c  ldr      w8, [x19]
00102030  cbnz     w8, #0x100318
00102034  ldr      x1, [x20]
00102038  mov      x0, x19
0010203c  bl       #0x147734
00102040  ldr      w8, [x19]
00102044  cbnz     w8, #0x100318
00102048  ldr      x8, [sp]
0010204c  mov      w2, w0
00102050  mov      x0, x19
00102054  ldr      x1, [x8]
00102058  bl       #0x146558
0010205c  ldr      w8, [x19]
00102060  cbnz     w8, #0x100318
00102064  ldr      x1, [x20]
00102068  mov      x0, x19
0010206c  bl       #0x147a18
00102070  ldr      w8, [x19]
00102074  cbnz     w8, #0x100318
00102078  ldr      x1, [x20]
0010207c  mov      x0, x19
00102080  bl       #0x147734
00102084  ldr      w8, [x19]
00102088  cbnz     w8, #0x100318
0010208c  mov      w1, w0
00102090  ldp      x21, x0, [x20]
00102094  bl       #0x147304
00102098  mov      w2, w0
0010209c  mov      x0, x19
001020a0  mov      x1, x21
001020a4  bl       #0x147630
001020a8  ldr      w8, [x19]
001020ac  cbnz     w8, #0x100318
001020b0  ldr      x1, [x20]
001020b4  mov      x0, x19
001020b8  mov      w2, #1
001020bc  bl       #0x147a20
001020c0  ldr      w8, [x19]
001020c4  cbnz     w8, #0x100318
001020c8  ldr      x1, [x20]
001020cc  mov      x0, x19
001020d0  bl       #0x147734
001020d4  ldr      w8, [x19]
001020d8  cbnz     w8, #0x100318
001020dc  ldr      x1, [x20]
001020e0  sub      w2, w0, #1
001020e4  mov      x0, x19
001020e8  bl       #0x147630
001020ec  ldr      w8, [x19]
001020f0  cbnz     w8, #0x100318
001020f4  ldr      x8, [sp]
001020f8  ldr      x0, [x8]
001020fc  bl       #0x146650
00102100  cbnz     w0, #0x102064
00102104  b        #0x104a04
00102108  ldp      x24, x25, [sp, #8]
0010210c  b.ne     #0x12a8b4
00102110  ldr      x1, [x20]
00102114  mov      x0, x19
00102118  mov      w2, #0x15
0010211c  bl       #0x147630
00102120  ldr      w8, [x19]
00102124  cbnz     w8, #0x100318
00102128  ldr      x1, [x20]
0010212c  mov      x0, x19
00102130  bl       #0x147734
00102134  ldr      w8, [x19]
00102138  cbnz     w8, #0x100318
0010213c  mov      w1, w0
00102140  ldp      x21, x0, [x20]
00102144  bl       #0x147304
00102148  mov      w2, w0
0010214c  mov      x0, x19
00102150  mov      x1, x21
00102154  bl       #0x147630
00102158  ldr      w8, [x19]
0010215c  cbnz     w8, #0x100318
00102160  ldr      x1, [x20]
00102164  mov      x0, x19
00102168  bl       #0x147734
0010216c  ldr      w8, [x19]
00102170  cbnz     w8, #0x100318
00102174  mov      w21, w0
00102178  ldr      x1, [x20]
0010217c  mov      x0, x19
00102180  bl       #0x147734
00102184  ldr      w8, [x19]
00102188  cbnz     w8, #0x100318
0010218c  mov      w3, w0
00102190  ldr      x1, [x26]
00102194  mov      x0, x19
00102198  mov      w2, w21
0010219c  bl       #0x146ed8
001021a0  ldr      w8, [x19]
001021a4  cbnz     w8, #0x100318
001021a8  ldr      x8, [sp, #0x18]
001021ac  mov      x0, x19
001021b0  mov      w2, #0x3e5
001021b4  ldr      x1, [x8]
001021b8  bl       #0x146470
001021bc  ldr      w8, [x19]
001021c0  cbnz     w8, #0x100318
001021c4  ldr      x1, [x20]
001021c8  mov      x0, x19
001021cc  mov      w2, #1
001021d0  bl       #0x147630
001021d4  ldr      w8, [x19]
001021d8  cbnz     w8, #0x100318
001021dc  ldr      x1, [x20]
001021e0  mov      x0, x19
001021e4  bl       #0x147734
001021e8  ldr      w8, [x19]
001021ec  cbnz     w8, #0x100318
001021f0  mov      w1, w0
001021f4  ldp      x21, x0, [x20]
001021f8  bl       #0x147304
001021fc  mov      w2, w0
00102200  mov      x0, x19
00102204  mov      x1, x21
00102208  bl       #0x147630
0010220c  ldr      w8, [x19]
00102210  cbnz     w8, #0x100318
00102214  ldr      x1, [x20]
00102218  mov      x0, x19
0010221c  mov      w2, #3
00102220  bl       #0x147630
00102224  ldr      w8, [x19]
00102228  cbnz     w8, #0x100318
0010222c  ldr      x1, [x20]
00102230  mov      x0, x19
00102234  bl       #0x147734
00102238  ldr      w8, [x19]
0010223c  cbnz     w8, #0x100318
00102240  mov      w1, w0
00102244  ldp      x21, x0, [x20]
00102248  bl       #0x147304
0010224c  mov      w2, w0
00102250  mov      x0, x19
00102254  mov      x1, x21
00102258  bl       #0x147630
0010225c  ldr      w8, [x19]
00102260  cbnz     w8, #0x100318
00102264  ldr      x1, [x20]
00102268  mov      x0, x19
0010226c  bl       #0x147734
00102270  ldr      w8, [x19]
00102274  cbnz     w8, #0x100318
00102278  mov      w1, w0
0010227c  ldp      x21, x0, [x20]
00102280  bl       #0x147304
00102284  mov      w2, w0
00102288  mov      x0, x19
0010228c  mov      x1, x21
00102290  bl       #0x147630
00102294  ldr      w8, [x19]
00102298  cbnz     w8, #0x100318
0010229c  ldr      x1, [x20]
001022a0  mov      x0, x19
001022a4  bl       #0x147734
001022a8  ldr      w8, [x19]
001022ac  cbnz     w8, #0x100318
001022b0  ldr      x8, [sp]
001022b4  mov      w2, w0
001022b8  mov      x0, x19
001022bc  ldr      x1, [x8]
001022c0  bl       #0x146558
001022c4  ldr      w8, [x19]
001022c8  cbnz     w8, #0x100318
001022cc  ldr      x1, [x20]
001022d0  mov      x0, x19
001022d4  bl       #0x147a18
001022d8  ldr      w8, [x19]
001022dc  cbnz     w8, #0x100318
001022e0  ldr      x1, [x20]
001022e4  mov      x0, x19
001022e8  bl       #0x147734
001022ec  ldr      w8, [x19]
001022f0  cbnz     w8, #0x100318
001022f4  mov      w1, w0
001022f8  ldp      x21, x0, [x20]
001022fc  bl       #0x147304
00102300  mov      w2, w0
00102304  mov      x0, x19
00102308  mov      x1, x21
0010230c  bl       #0x147630
00102310  ldr      w8, [x19]
00102314  cbnz     w8, #0x100318
00102318  ldr      x1, [x26]
0010231c  mov      x0, x19
00102320  bl       #0x147120
00102324  ldr      x8, [sp, #0x18]
00102328  mov      x0, x19
0010232c  mov      w2, #0xbea
00102330  b        #0x103420
00102334  ldp      x24, x25, [sp, #8]
00102338  b.ne     #0x12a8b4
0010233c  ldr      x1, [x20]
00102340  mov      x0, x19
00102344  mov      w2, #8
00102348  bl       #0x147630
0010234c  ldr      w8, [x19]
00102350  cbnz     w8, #0x100318
00102354  ldr      x1, [x20]
00102358  mov      x0, x19
0010235c  bl       #0x147734
00102360  ldr      w8, [x19]
00102364  cbnz     w8, #0x100318
00102368  mov      w1, w0
0010236c  ldp      x21, x0, [x20]
00102370  bl       #0x147304
00102374  mov      w2, w0
00102378  mov      x0, x19
0010237c  mov      x1, x21
00102380  bl       #0x147630
00102384  ldr      w8, [x19]
00102388  cbnz     w8, #0x100318
0010238c  ldr      x1, [x20]
00102390  mov      x0, x19
00102394  bl       #0x147734
00102398  ldr      w8, [x19]
0010239c  cbnz     w8, #0x100318
001023a0  mov      w21, w0
001023a4  ldr      x1, [x20]
001023a8  mov      x0, x19
001023ac  bl       #0x147734
001023b0  ldr      w8, [x19]
001023b4  cbnz     w8, #0x100318
001023b8  mov      w3, w0
001023bc  ldr      x1, [x26]
001023c0  mov      x0, x19
001023c4  mov      w2, w21
001023c8  bl       #0x146ed8
001023cc  ldr      w8, [x19]
001023d0  cbnz     w8, #0x100318
001023d4  ldr      x1, [x20]
001023d8  mov      x0, x19
001023dc  mov      w2, #2
001023e0  bl       #0x147630
001023e4  ldr      w8, [x19]
001023e8  cbnz     w8, #0x100318
001023ec  ldr      x1, [x20]
001023f0  mov      x0, x19
001023f4  mov      w2, wzr
001023f8  bl       #0x147630
001023fc  ldr      w8, [x19]
00102400  cbnz     w8, #0x100318
00102404  ldr      x1, [x20]
00102408  mov      x0, x19
0010240c  bl       #0x147734
00102410  ldr      w8, [x19]
00102414  cbnz     w8, #0x100318
00102418  mov      w1, w0
0010241c  ldp      x21, x0, [x20]
00102420  bl       #0x147304
00102424  mov      w2, w0
00102428  mov      x0, x19
0010242c  mov      x1, x21
00102430  bl       #0x147630
00102434  ldr      w8, [x19]
00102438  cbnz     w8, #0x100318
0010243c  ldr      x1, [x20]
00102440  mov      x0, x19
00102444  bl       #0x147734
00102448  ldr      w8, [x19]
0010244c  cbnz     w8, #0x100318
00102450  mov      w21, w0
00102454  ldr      x1, [x20]
00102458  mov      x0, x19
0010245c  bl       #0x147734
00102460  ldr      w8, [x19]
00102464  cbnz     w8, #0x100318
00102468  mov      w3, w0
0010246c  ldr      x1, [x26]
00102470  mov      x0, x19
00102474  mov      w2, w21
00102478  bl       #0x146ed8
0010247c  ldr      w8, [x19]
00102480  cbnz     w8, #0x100318
00102484  ldr      x1, [x20]
00102488  mov      x0, x19
0010248c  mov      w2, wzr
00102490  bl       #0x147630
00102494  ldr      w8, [x19]
00102498  cbnz     w8, #0x100318
0010249c  ldr      x1, [x20]
001024a0  mov      x0, x19
001024a4  bl       #0x147734
001024a8  ldr      w8, [x19]
001024ac  cbnz     w8, #0x100318
001024b0  mov      w1, w0
001024b4  ldp      x21, x0, [x20]
001024b8  bl       #0x147304
001024bc  mov      w2, w0
001024c0  mov      x0, x19
001024c4  mov      x1, x21
001024c8  bl       #0x147630
001024cc  ldr      w8, [x19]
001024d0  cbnz     w8, #0x100318
001024d4  ldr      x1, [x20]
001024d8  mov      x0, x19
001024dc  mov      w2, #3
001024e0  bl       #0x147630
001024e4  ldr      w8, [x19]
001024e8  cbnz     w8, #0x100318
001024ec  ldr      x1, [x20]
001024f0  mov      x0, x19
001024f4  mov      w2, #1
001024f8  bl       #0x147630
001024fc  ldr      w8, [x19]
00102500  cbnz     w8, #0x100318
00102504  ldr      x8, [sp, #0x18]
00102508  mov      x0, x19
0010250c  mov      w2, #0x685
00102510  b        #0x104938
00102514  ldp      x24, x25, [sp, #8]
00102518  b.ne     #0x12a8b4
0010251c  ldr      x1, [x20]
00102520  mov      x0, x19
00102524  mov      w2, #0x18
00102528  bl       #0x147630
0010252c  ldr      w8, [x19]
00102530  cbnz     w8, #0x100318
00102534  ldr      x1, [x20]
00102538  mov      x0, x19
0010253c  bl       #0x147734
00102540  ldr      w8, [x19]
00102544  cbnz     w8, #0x100318
00102548  mov      w1, w0
0010254c  ldp      x21, x0, [x20]
00102550  bl       #0x147304
00102554  mov      w2, w0
00102558  mov      x0, x19
0010255c  mov      x1, x21
00102560  bl       #0x147630
00102564  ldr      w8, [x19]
00102568  cbnz     w8, #0x100318
0010256c  ldr      x1, [x20]
00102570  mov      x0, x19
00102574  mov      w2, wzr
00102578  bl       #0x147630
0010257c  ldr      w8, [x19]
00102580  cbnz     w8, #0x100318
00102584  ldr      x1, [x20]
00102588  mov      x0, x19
0010258c  mov      w2, #0x10
00102590  bl       #0x147630
00102594  ldr      w8, [x19]
00102598  cbnz     w8, #0x100318
0010259c  ldr      x8, [sp, #0x18]
001025a0  mov      x0, x19
001025a4  mov      w2, #0x55e
001025a8  b        #0x104938
001025ac  ldp      x24, x25, [sp, #8]
001025b0  b.ne     #0x12a8b4
001025b4  ldr      x1, [x20]
001025b8  mov      x0, x19
001025bc  mov      w2, #6
001025c0  bl       #0x147630
001025c4  ldr      w8, [x19]
001025c8  cbnz     w8, #0x100318
001025cc  ldr      x1, [x20]
001025d0  mov      x0, x19
001025d4  mov      w2, wzr
001025d8  bl       #0x147630
001025dc  ldr      w8, [x19]
001025e0  cbnz     w8, #0x100318
001025e4  ldr      x1, [x20]
001025e8  mov      x0, x19
001025ec  bl       #0x147734
001025f0  ldr      w8, [x19]
001025f4  cbnz     w8, #0x100318
001025f8  mov      w1, w0
001025fc  ldp      x21, x0, [x20]
00102600  bl       #0x147304
00102604  mov      w2, w0
00102608  mov      x0, x19
0010260c  mov      x1, x21
00102610  bl       #0x147630
00102614  ldr      w8, [x19]
00102618  cbnz     w8, #0x100318
0010261c  ldr      x1, [x20]
00102620  mov      x0, x19
00102624  bl       #0x147734
00102628  ldr      w8, [x19]
0010262c  cbnz     w8, #0x100318
00102630  mov      w21, w0
00102634  ldr      x1, [x20]
00102638  mov      x0, x19
0010263c  bl       #0x147734
00102640  ldr      w8, [x19]
00102644  cbnz     w8, #0x100318
00102648  mov      w3, w0
0010264c  ldr      x1, [x26]
00102650  mov      x0, x19
00102654  mov      w2, w21
00102658  bl       #0x146ed8
0010265c  ldr      w8, [x19]
00102660  cbnz     w8, #0x100318
00102664  ldr      x1, [x20]
00102668  mov      x0, x19
0010266c  mov      w2, wzr
00102670  bl       #0x147630
00102674  ldr      w8, [x19]
00102678  cbnz     w8, #0x100318
0010267c  ldr      x1, [x20]
00102680  mov      x0, x19
00102684  bl       #0x147734
00102688  ldr      w8, [x19]
0010268c  cbnz     w8, #0x100318
00102690  mov      w1, w0
00102694  ldp      x21, x0, [x20]
00102698  bl       #0x147304
0010269c  mov      w2, w0
001026a0  mov      x0, x19
001026a4  mov      x1, x21
001026a8  bl       #0x147630
001026ac  ldr      w8, [x19]
001026b0  cbnz     w8, #0x100318
001026b4  ldr      x1, [x20]
001026b8  mov      x0, x19
001026bc  mov      w2, #3
001026c0  bl       #0x147630
001026c4  ldr      w8, [x19]
001026c8  cbnz     w8, #0x100318
001026cc  ldr      x1, [x20]
001026d0  mov      x0, x19
001026d4  mov      w2, #1
001026d8  bl       #0x147630
001026dc  ldr      w8, [x19]
001026e0  cbnz     w8, #0x100318
001026e4  ldr      x8, [sp, #0x18]
001026e8  mov      x0, x19
001026ec  mov      w2, #0x75d
001026f0  b        #0x104938
001026f4  ldp      x24, x25, [sp, #8]
001026f8  b.ne     #0x12a8b4
001026fc  ldr      x1, [x20]
00102700  mov      x0, x19
00102704  mov      w2, #6
00102708  bl       #0x147630
0010270c  ldr      w8, [x19]
00102710  cbnz     w8, #0x100318
00102714  ldr      x1, [x20]
00102718  mov      x0, x19
0010271c  bl       #0x147734
00102720  ldr      w8, [x19]
00102724  cbnz     w8, #0x100318
00102728  mov      w1, w0
0010272c  ldp      x21, x0, [x20]
00102730  bl       #0x147304
00102734  mov      w2, w0
00102738  mov      x0, x19
0010273c  mov      x1, x21
00102740  bl       #0x147630
00102744  ldr      w8, [x19]
00102748  cbnz     w8, #0x100318
0010274c  ldr      x1, [x20]
00102750  mov      x0, x19
00102754  mov      w2, #2
00102758  bl       #0x147630
0010275c  ldr      w8, [x19]
00102760  cbnz     w8, #0x100318
00102764  ldr      x8, [sp, #0x18]
00102768  mov      x0, x19
0010276c  mov      w2, #0xd0
00102770  ldr      x1, [x8]
00102774  bl       #0x146470
00102778  ldr      w8, [x19]
0010277c  cbnz     w8, #0x100318
00102780  ldr      x1, [x20]
00102784  mov      x0, x19
00102788  bl       #0x147734
0010278c  ldr      w8, [x19]
00102790  cbnz     w8, #0x100318
00102794  ldr      x8, [sp]
00102798  mov      w2, w0
0010279c  mov      x0, x19
001027a0  ldr      x1, [x8]
001027a4  bl       #0x146558
001027a8  ldr      w8, [x19]
001027ac  cbnz     w8, #0x100318
001027b0  ldr      x1, [x20]
001027b4  mov      x0, x19
001027b8  bl       #0x147a18
001027bc  ldr      w8, [x19]
001027c0  cbnz     w8, #0x100318
001027c4  ldr      x1, [x20]
001027c8  mov      x0, x19
001027cc  bl       #0x147734
001027d0  ldr      w8, [x19]
001027d4  cbnz     w8, #0x100318
001027d8  ldr      x1, [x20]
001027dc  add      w2, w0, #1
001027e0  mov      x0, x19
001027e4  bl       #0x147630
001027e8  ldr      w8, [x19]
001027ec  cbnz     w8, #0x100318
001027f0  ldr      x1, [x20]
001027f4  mov      x0, x19
001027f8  mov      w2, #2
001027fc  bl       #0x147a20
00102800  ldr      w8, [x19]
00102804  cbnz     w8, #0x100318
00102808  ldr      x1, [x20]
0010280c  mov      x0, x19
00102810  mov      w2, #1
00102814  bl       #0x147a20
00102818  ldr      w8, [x19]
0010281c  cbnz     w8, #0x100318
00102820  ldr      x1, [x20]
00102824  mov      x0, x19
00102828  bl       #0x147734
0010282c  ldr      w8, [x19]
00102830  cbnz     w8, #0x100318
00102834  mov      w21, w0
00102838  ldr      x1, [x20]
0010283c  mov      x0, x19
00102840  bl       #0x147734
00102844  ldr      w8, [x19]
00102848  cbnz     w8, #0x100318
0010284c  mov      w3, w0
00102850  ldr      x1, [x26]
00102854  mov      x0, x19
00102858  mov      w2, w21
0010285c  bl       #0x146ed8
00102860  ldr      w8, [x19]
00102864  cbnz     w8, #0x100318
00102868  ldr      x8, [sp]
0010286c  ldr      x0, [x8]
00102870  bl       #0x146650
00102874  cbnz     w0, #0x1027b0
00102878  b        #0x104a04
0010287c  ldp      x24, x25, [sp, #8]
00102880  b.ne     #0x12a8b4
00102884  ldr      x1, [x20]
00102888  mov      x0, x19
0010288c  mov      w2, #1
00102890  bl       #0x147630
00102894  ldr      w8, [x19]
00102898  cbnz     w8, #0x100318
0010289c  ldr      x1, [x20]
001028a0  mov      x0, x19
001028a4  bl       #0x147734
001028a8  ldr      w8, [x19]
001028ac  cbnz     w8, #0x100318
001028b0  mov      w1, w0
001028b4  ldp      x21, x0, [x20]
001028b8  bl       #0x147304
001028bc  mov      w2, w0
001028c0  mov      x0, x19
001028c4  mov      x1, x21
001028c8  bl       #0x147630
001028cc  ldr      w8, [x19]
001028d0  cbnz     w8, #0x100318
001028d4  ldr      x1, [x20]
001028d8  mov      x0, x19
001028dc  mov      w2, wzr
001028e0  bl       #0x147630
001028e4  ldr      w8, [x19]
001028e8  cbnz     w8, #0x100318
001028ec  ldr      x1, [x20]
001028f0  mov      x0, x19
001028f4  mov      w2, #2
001028f8  bl       #0x147630
001028fc  ldr      w8, [x19]
00102900  cbnz     w8, #0x100318
00102904  ldr      x1, [x20]
00102908  mov      x0, x19
0010290c  bl       #0x147734
00102910  ldr      w8, [x19]
00102914  cbnz     w8, #0x100318
00102918  mov      w1, w0
0010291c  ldp      x21, x0, [x20]
00102920  bl       #0x147304
00102924  mov      w2, w0
00102928  mov      x0, x19
0010292c  mov      x1, x21
00102930  bl       #0x147630
00102934  ldr      w8, [x19]
00102938  cbnz     w8, #0x100318
0010293c  ldr      x1, [x20]
00102940  mov      x0, x19
00102944  bl       #0x147734
00102948  ldr      w8, [x19]
0010294c  cbnz     w8, #0x100318
00102950  mov      w1, w0
00102954  ldp      x21, x0, [x20]
00102958  bl       #0x147304
0010295c  mov      w2, w0
00102960  mov      x0, x19
00102964  mov      x1, x21
00102968  bl       #0x147630
0010296c  ldr      w8, [x19]
00102970  cbnz     w8, #0x100318
00102974  ldr      x8, [sp, #0x18]
00102978  mov      x0, x19
0010297c  mov      w2, #0x50a
00102980  b        #0x104938
00102984  ldp      x24, x25, [sp, #8]
00102988  b.ne     #0x12a8b4
0010298c  ldr      x1, [x20]
00102990  mov      x0, x19
00102994  mov      w2, #4
00102998  bl       #0x147630
0010299c  ldr      w8, [x19]
001029a0  cbnz     w8, #0x100318
001029a4  ldr      x1, [x20]
001029a8  mov      x0, x19
001029ac  mov      w2, wzr
001029b0  bl       #0x147630
001029b4  ldr      w8, [x19]
001029b8  cbnz     w8, #0x100318
001029bc  ldr      x1, [x20]
001029c0  mov      x0, x19
001029c4  bl       #0x147734
001029c8  ldr      w8, [x19]
001029cc  cbnz     w8, #0x100318
001029d0  mov      w1, w0
001029d4  ldp      x21, x0, [x20]
001029d8  bl       #0x147304
001029dc  mov      w2, w0
001029e0  mov      x0, x19
001029e4  mov      x1, x21
001029e8  bl       #0x147630
001029ec  ldr      w8, [x19]
001029f0  cbnz     w8, #0x100318
001029f4  ldr      x1, [x20]
001029f8  mov      x0, x19
001029fc  bl       #0x147734
00102a00  ldr      w8, [x19]
00102a04  cbnz     w8, #0x100318
00102a08  mov      w21, w0
00102a0c  ldr      x1, [x20]
00102a10  mov      x0, x19
00102a14  bl       #0x147734
00102a18  ldr      w8, [x19]
00102a1c  cbnz     w8, #0x100318
00102a20  mov      w3, w0
00102a24  ldr      x1, [x26]
00102a28  mov      x0, x19
00102a2c  mov      w2, w21
00102a30  bl       #0x146ed8
00102a34  ldr      w8, [x19]
00102a38  cbnz     w8, #0x100318
00102a3c  ldr      x1, [x20]
00102a40  mov      x0, x19
00102a44  mov      w2, wzr
00102a48  bl       #0x147630
00102a4c  ldr      w8, [x19]
00102a50  cbnz     w8, #0x100318
00102a54  ldr      x1, [x20]
00102a58  mov      x0, x19
00102a5c  bl       #0x147734
00102a60  ldr      w8, [x19]
00102a64  cbnz     w8, #0x100318
00102a68  mov      w1, w0
00102a6c  ldp      x21, x0, [x20]
00102a70  bl       #0x147304
00102a74  mov      w2, w0
00102a78  mov      x0, x19
00102a7c  mov      x1, x21
00102a80  bl       #0x147630
00102a84  ldr      w8, [x19]
00102a88  cbnz     w8, #0x100318
00102a8c  ldr      x1, [x20]
00102a90  mov      x0, x19
00102a94  mov      w2, #3
00102a98  bl       #0x147630
00102a9c  ldr      w8, [x19]
00102aa0  cbnz     w8, #0x100318
00102aa4  ldr      x1, [x20]
00102aa8  mov      x0, x19
00102aac  mov      w2, #1
00102ab0  bl       #0x147630
00102ab4  ldr      w8, [x19]
00102ab8  cbnz     w8, #0x100318
00102abc  ldr      x8, [sp, #0x18]
00102ac0  mov      x0, x19
00102ac4  mov      w2, #0x6f1
00102ac8  b        #0x104938
00102acc  ldp      x24, x25, [sp, #8]
00102ad0  b.ne     #0x12a8b4
00102ad4  ldr      x1, [x20]
00102ad8  mov      x0, x19
00102adc  mov      w2, wzr
00102ae0  bl       #0x147630
00102ae4  ldr      w8, [x19]
00102ae8  cbnz     w8, #0x100318
00102aec  ldr      x1, [x20]
00102af0  mov      x0, x19
00102af4  mov      w2, #0x10
00102af8  bl       #0x147630
00102afc  ldr      w8, [x19]
00102b00  cbnz     w8, #0x100318
00102b04  ldr      x1, [x20]
00102b08  mov      x0, x19
00102b0c  bl       #0x147734
00102b10  ldr      w8, [x19]
00102b14  cbnz     w8, #0x100318
00102b18  mov      w1, w0
00102b1c  ldp      x21, x0, [x20]
00102b20  bl       #0x147304
00102b24  mov      w2, w0
00102b28  mov      x0, x19
00102b2c  mov      x1, x21
00102b30  bl       #0x147630
00102b34  ldr      w8, [x19]
00102b38  cbnz     w8, #0x100318
00102b3c  ldr      x1, [x20]
00102b40  mov      x0, x19
00102b44  bl       #0x147734
00102b48  ldr      w8, [x19]
00102b4c  cbnz     w8, #0x100318
00102b50  mov      w21, w0
00102b54  ldr      x1, [x20]
00102b58  mov      x0, x19
00102b5c  bl       #0x147734
00102b60  ldr      w8, [x19]
00102b64  cbnz     w8, #0x100318
00102b68  add      x28, x20, w0, uxtw #3
00102b6c  ldr      x0, [x28, #0x20]!
00102b70  bl       #0x1472e8
00102b74  mov      w22, w0
00102b78  mov      w23, wzr
00102b7c  cmp      w22, w23
00102b80  b.eq     #0x104790
00102b84  ldr      x0, [x28]
00102b88  mov      w1, w23
00102b8c  ldr      x24, [x26]
00102b90  add      w25, w21, w23
00102b94  bl       #0x147304
00102b98  mov      w3, w0
00102b9c  mov      x0, x19
00102ba0  mov      x1, x24
00102ba4  mov      w2, w25
00102ba8  bl       #0x146ed8
00102bac  ldp      x24, x25, [sp, #8]
00102bb0  add      w23, w23, #1
00102bb4  ldr      w8, [x19]
00102bb8  cbz      w8, #0x102b7c
00102bbc  b        #0x100318
00102bc0  ldp      x24, x25, [sp, #8]
00102bc4  b.ne     #0x12a8b4
00102bc8  ldr      x1, [x20]
00102bcc  mov      x0, x19
00102bd0  bl       #0x147734
00102bd4  ldr      w8, [x19]
00102bd8  cbnz     w8, #0x100318
00102bdc  ldr      x1, [x20]
00102be0  mov      x0, x19
00102be4  bl       #0x147734
00102be8  ldr      w8, [x19]
00102bec  cbnz     w8, #0x100318
00102bf0  ldr      x1, [x20]
00102bf4  mov      x0, x19
00102bf8  mov      w2, #0x15
00102bfc  bl       #0x147630
00102c00  ldr      w8, [x19]
00102c04  cbnz     w8, #0x100318
00102c08  ldr      x1, [x20]
00102c0c  mov      x0, x19
00102c10  bl       #0x147734
00102c14  ldr      w8, [x19]
00102c18  cbnz     w8, #0x100318
00102c1c  mov      w1, w0
00102c20  ldp      x21, x0, [x20]
00102c24  bl       #0x147304
00102c28  mov      w2, w0
00102c2c  mov      x0, x19
00102c30  mov      x1, x21
00102c34  bl       #0x147630
00102c38  ldr      w8, [x19]
00102c3c  cbnz     w8, #0x100318
00102c40  ldr      x1, [x20]
00102c44  mov      x0, x19
00102c48  bl       #0x147734
00102c4c  ldr      w8, [x19]
00102c50  cbnz     w8, #0x100318
00102c54  mov      w1, w0
00102c58  ldp      x21, x0, [x20]
00102c5c  bl       #0x147304
00102c60  mov      w2, w0
00102c64  mov      x0, x19
00102c68  mov      x1, x21
00102c6c  bl       #0x147630
00102c70  ldr      w8, [x19]
00102c74  cbnz     w8, #0x100318
00102c78  ldr      x1, [x20]
00102c7c  mov      x0, x19
00102c80  mov      w2, #0x16
00102c84  bl       #0x147630
00102c88  ldr      w8, [x19]
00102c8c  cbnz     w8, #0x100318
00102c90  ldr      x1, [x20]
00102c94  mov      x0, x19
00102c98  bl       #0x147734
00102c9c  ldr      w8, [x19]
00102ca0  cbnz     w8, #0x100318
00102ca4  mov      w1, w0
00102ca8  ldp      x21, x0, [x20]
00102cac  bl       #0x147304
00102cb0  mov      w2, w0
00102cb4  mov      x0, x19
00102cb8  mov      x1, x21
00102cbc  bl       #0x147630
00102cc0  ldr      w8, [x19]
00102cc4  cbnz     w8, #0x100318
00102cc8  ldr      x1, [x20]
00102ccc  mov      x0, x19
00102cd0  mov      w2, wzr
00102cd4  bl       #0x147630
00102cd8  ldr      w8, [x19]
00102cdc  cbnz     w8, #0x100318
00102ce0  ldr      x1, [x20]
00102ce4  mov      x0, x19
00102ce8  bl       #0x147734
00102cec  ldr      w8, [x19]
00102cf0  cbnz     w8, #0x100318
00102cf4  mov      w22, w0
00102cf8  cmp      w0, #0xf
00102cfc  b.hi     #0x12aa34
00102d00  ldr      x1, [x20]
00102d04  mov      x0, x19
00102d08  bl       #0x147734
00102d0c  ldp      x24, x25, [sp, #8]
00102d10  ldr      w8, [x19]
00102d14  cbnz     w8, #0x100318
00102d18  mov      w21, w0
00102d1c  ldr      x1, [x20]
00102d20  mov      x0, x19
00102d24  bl       #0x147734
00102d28  ldr      w8, [x19]
00102d2c  cbnz     w8, #0x100318
00102d30  add      x28, x20, w22, uxtw #3
00102d34  mov      w23, w0
00102d38  mov      x0, x19
00102d3c  ldr      x1, [x28, #0x20]!
00102d40  bl       #0x147220
00102d44  ldr      w8, [x19]
00102d48  cbnz     w8, #0x100318
00102d4c  ldr      x1, [x28]
00102d50  mov      x0, x19
00102d54  bl       #0x147120
00102d58  ldr      w8, [x19]
00102d5c  cbnz     w8, #0x100318
00102d60  mov      w22, wzr
00102d64  add      w27, w23, w21
00102d68  add      w1, w21, w22
00102d6c  cmp      w1, w27
00102d70  b.hs     #0x105e34
00102d74  ldr      x0, [x26]
00102d78  ldr      x23, [x28]
00102d7c  bl       #0x147304
00102d80  mov      w3, w0
00102d84  mov      x0, x19
00102d88  mov      x1, x23
00102d8c  mov      w2, w22
00102d90  bl       #0x146ed8
00102d94  ldp      x24, x25, [sp, #8]
00102d98  add      w22, w22, #1
00102d9c  ldr      w8, [x19]
00102da0  cbz      w8, #0x102d68
00102da4  b        #0x100318
00102da8  ldp      x24, x25, [sp, #8]
00102dac  b.ne     #0x12a8b4
00102db0  ldr      x1, [x20]
00102db4  mov      x0, x19
00102db8  mov      w2, wzr
00102dbc  bl       #0x147630
00102dc0  ldr      w8, [x19]
00102dc4  cbnz     w8, #0x100318
00102dc8  ldr      x1, [x20]
00102dcc  mov      x0, x19
00102dd0  mov      w2, #0xf
00102dd4  bl       #0x147630
00102dd8  ldr      w8, [x19]
00102ddc  cbnz     w8, #0x100318
00102de0  ldr      x1, [x20]
00102de4  mov      x0, x19
00102de8  bl       #0x147734
00102dec  ldr      w8, [x19]
00102df0  cbnz     w8, #0x100318
00102df4  mov      w1, w0
00102df8  ldp      x21, x0, [x20]
00102dfc  bl       #0x147304
00102e00  mov      w2, w0
00102e04  mov      x0, x19
00102e08  mov      x1, x21
00102e0c  bl       #0x147630
00102e10  ldr      w8, [x19]
00102e14  cbnz     w8, #0x100318
00102e18  ldr      x1, [x20]
00102e1c  mov      x0, x19
00102e20  bl       #0x147734
00102e24  ldr      w8, [x19]
00102e28  cbnz     w8, #0x100318
00102e2c  mov      w21, w0
00102e30  ldr      x1, [x20]
00102e34  mov      x0, x19
00102e38  bl       #0x147734
00102e3c  ldr      w8, [x19]
00102e40  cbnz     w8, #0x100318
00102e44  add      x28, x20, w0, uxtw #3
00102e48  ldr      x0, [x28, #0x20]!
00102e4c  bl       #0x1472e8
00102e50  mov      w22, w0
00102e54  mov      w23, wzr
00102e58  cmp      w22, w23
00102e5c  b.eq     #0x1052b4
00102e60  ldr      x0, [x28]
00102e64  mov      w1, w23
00102e68  ldr      x24, [x26]
00102e6c  add      w25, w21, w23
00102e70  bl       #0x147304
00102e74  mov      w3, w0
00102e78  mov      x0, x19
00102e7c  mov      x1, x24
00102e80  mov      w2, w25
00102e84  bl       #0x146ed8
00102e88  ldp      x24, x25, [sp, #8]
00102e8c  add      w23, w23, #1
00102e90  ldr      w8, [x19]
00102e94  cbz      w8, #0x102e58
00102e98  b        #0x100318
00102e9c  ldp      x24, x25, [sp, #8]
00102ea0  b.ne     #0x12a8b4
00102ea4  ldr      x1, [x20]
00102ea8  mov      x0, x19
00102eac  mov      w2, #3
00102eb0  bl       #0x147630
00102eb4  ldr      w8, [x19]
00102eb8  cbnz     w8, #0x100318
00102ebc  ldr      x1, [x20]
00102ec0  mov      x0, x19
00102ec4  mov      w2, wzr
00102ec8  bl       #0x147630
00102ecc  ldr      w8, [x19]
00102ed0  cbnz     w8, #0x100318
00102ed4  ldr      x1, [x20]
00102ed8  mov      x0, x19
00102edc  bl       #0x147734
00102ee0  ldr      w8, [x19]
00102ee4  cbnz     w8, #0x100318
00102ee8  mov      w1, w0
00102eec  ldp      x21, x0, [x20]
00102ef0  bl       #0x147304
00102ef4  mov      w2, w0
00102ef8  mov      x0, x19
00102efc  mov      x1, x21
00102f00  bl       #0x147630
00102f04  ldr      w8, [x19]
00102f08  cbnz     w8, #0x100318
00102f0c  ldr      x1, [x20]
00102f10  mov      x0, x19
00102f14  bl       #0x147734
00102f18  ldr      w8, [x19]
00102f1c  cbnz     w8, #0x100318
00102f20  mov      w21, w0
00102f24  ldr      x1, [x20]
00102f28  mov      x0, x19
00102f2c  bl       #0x147734
00102f30  ldr      w8, [x19]
00102f34  cbnz     w8, #0x100318
00102f38  mov      w3, w0
00102f3c  ldr      x1, [x26]
00102f40  mov      x0, x19
00102f44  mov      w2, w21
00102f48  bl       #0x146ed8
00102f4c  ldr      w8, [x19]
00102f50  cbnz     w8, #0x100318
00102f54  ldr      x1, [x20]
00102f58  mov      x0, x19
00102f5c  mov      w2, wzr
00102f60  bl       #0x147630
00102f64  ldr      w8, [x19]
00102f68  cbnz     w8, #0x100318
00102f6c  ldr      x1, [x20]
00102f70  mov      x0, x19
00102f74  bl       #0x147734
00102f78  ldr      w8, [x19]
00102f7c  cbnz     w8, #0x100318
00102f80  mov      w1, w0
00102f84  ldp      x21, x0, [x20]
00102f88  bl       #0x147304
00102f8c  mov      w2, w0
00102f90  mov      x0, x19
00102f94  mov      x1, x21
00102f98  bl       #0x147630
00102f9c  ldr      w8, [x19]
00102fa0  cbnz     w8, #0x100318
00102fa4  ldr      x1, [x20]
00102fa8  mov      x0, x19
00102fac  mov      w2, #3
00102fb0  bl       #0x147630
00102fb4  ldr      w8, [x19]
00102fb8  cbnz     w8, #0x100318
00102fbc  ldr      x1, [x20]
00102fc0  mov      x0, x19
00102fc4  mov      w2, #1
00102fc8  bl       #0x147630
00102fcc  ldr      w8, [x19]
00102fd0  cbnz     w8, #0x100318
00102fd4  ldr      x8, [sp, #0x18]
00102fd8  mov      x0, x19
00102fdc  mov      w2, #0x6bb
00102fe0  b        #0x104938
00102fe4  ldp      x24, x25, [sp, #8]
00102fe8  b.ne     #0x12a8b4
00102fec  ldr      x1, [x20]
00102ff0  mov      x0, x19
00102ff4  bl       #0x147734
00102ff8  ldr      w8, [x19]
00102ffc  cbnz     w8, #0x100318
00103000  ldr      x1, [x20]
00103004  mov      x0, x19
00103008  bl       #0x147734
0010300c  ldr      w8, [x19]
00103010  cbnz     w8, #0x100318
00103014  ldr      x1, [x20]
00103018  mov      x0, x19
0010301c  mov      w2, #0x11
00103020  bl       #0x147630
00103024  ldr      w8, [x19]
00103028  cbnz     w8, #0x100318
0010302c  ldr      x1, [x20]
00103030  mov      x0, x19
00103034  bl       #0x147734
00103038  ldr      w8, [x19]
0010303c  cbnz     w8, #0x100318
00103040  mov      w1, w0
00103044  ldp      x21, x0, [x20]
00103048  bl       #0x147304
0010304c  mov      w2, w0
00103050  mov      x0, x19
00103054  mov      x1, x21
00103058  bl       #0x147630
0010305c  ldr      w8, [x19]
00103060  cbnz     w8, #0x100318
00103064  ldr      x1, [x20]
00103068  mov      x0, x19
0010306c  bl       #0x147734
00103070  ldr      w8, [x19]
00103074  cbnz     w8, #0x100318
00103078  mov      w1, w0
0010307c  ldp      x21, x0, [x20]
00103080  bl       #0x147304
00103084  mov      w2, w0
00103088  mov      x0, x19
0010308c  mov      x1, x21
00103090  bl       #0x147630
00103094  ldr      w8, [x19]
00103098  cbnz     w8, #0x100318
0010309c  ldr      x1, [x26]
001030a0  mov      x0, x19
001030a4  bl       #0x147120
001030a8  ldr      x8, [sp, #0x18]
001030ac  mov      x0, x19
001030b0  mov      w2, #0x583
001030b4  ldr      x1, [x8]
001030b8  bl       #0x146470
001030bc  ldr      w8, [x19]
001030c0  cbnz     w8, #0x100318
001030c4  ldr      x1, [x20]
001030c8  mov      x0, x19
001030cc  mov      w2, #4
001030d0  bl       #0x147630
001030d4  ldr      w8, [x19]
001030d8  cbnz     w8, #0x100318
001030dc  ldr      x1, [x20]
001030e0  mov      x0, x19
001030e4  mov      w2, #1
001030e8  bl       #0x14784c
001030ec  ldr      w8, [x19]
001030f0  cbnz     w8, #0x100318
001030f4  ldr      x1, [x20]
001030f8  mov      x0, x19
001030fc  bl       #0x147734
00103100  ldr      w8, [x19]
00103104  cbnz     w8, #0x100318
00103108  mov      w21, w0
0010310c  ldr      x1, [x20]
00103110  mov      x0, x19
00103114  bl       #0x147734
00103118  ldr      w8, [x19]
0010311c  cbnz     w8, #0x100318
00103120  udiv     w2, w21, w0
00103124  ldr      x1, [x20]
00103128  mov      x0, x19
0010312c  bl       #0x147630
00103130  ldr      w8, [x19]
00103134  cbnz     w8, #0x100318
00103138  ldr      x1, [x20]
0010313c  mov      x0, x19
00103140  mov      w2, #4
00103144  bl       #0x147630
00103148  ldr      w8, [x19]
0010314c  cbnz     w8, #0x100318
00103150  ldr      x1, [x20]
00103154  mov      x0, x19
00103158  mov      w2, #2
0010315c  bl       #0x14784c
00103160  ldr      w8, [x19]
00103164  cbnz     w8, #0x100318
00103168  ldr      x1, [x20]
0010316c  mov      x0, x19
00103170  bl       #0x147734
00103174  ldr      w8, [x19]
00103178  cbnz     w8, #0x100318
0010317c  mov      w21, w0
00103180  ldr      x1, [x20]
00103184  mov      x0, x19
00103188  bl       #0x147734
0010318c  ldr      w8, [x19]
00103190  cbnz     w8, #0x100318
00103194  udiv     w8, w21, w0
00103198  ldr      x1, [x20]
0010319c  msub     w2, w8, w0, w21
001031a0  mov      x0, x19
001031a4  bl       #0x147630
001031a8  ldr      w8, [x19]
001031ac  cbnz     w8, #0x100318
001031b0  ldr      x1, [x20]
001031b4  mov      x0, x19
001031b8  mov      w2, wzr
001031bc  bl       #0x147630
001031c0  ldr      w8, [x19]
001031c4  cbnz     w8, #0x100318
001031c8  ldr      x1, [x20]
001031cc  mov      x0, x19
001031d0  bl       #0x147734
001031d4  ldr      w8, [x19]
001031d8  cbnz     w8, #0x100318
001031dc  mov      w21, w0
001031e0  ldr      x1, [x20]
001031e4  mov      x0, x19
001031e8  bl       #0x147734
001031ec  ldr      w8, [x19]
001031f0  cbnz     w8, #0x100318
001031f4  cmp      w21, w0
001031f8  ldr      x1, [x20]
001031fc  cset     w2, lo
00103200  mov      x0, x19
00103204  bl       #0x147630
00103208  ldr      w8, [x19]
0010320c  cbnz     w8, #0x100318
00103210  ldr      x1, [x20]
00103214  mov      x0, x19
00103218  bl       #0x147734
0010321c  ldr      w8, [x19]
00103220  cbnz     w8, #0x100318
00103224  mov      w21, w0
00103228  ldr      x1, [x20]
0010322c  mov      x0, x19
00103230  bl       #0x147734
00103234  ldr      w8, [x19]
00103238  cbnz     w8, #0x100318
0010323c  ldr      x1, [x20]
00103240  add      w2, w0, w21
00103244  mov      x0, x19
00103248  bl       #0x147630
0010324c  ldr      w8, [x19]
00103250  cbnz     w8, #0x100318
00103254  ldr      x1, [x20]
00103258  mov      x0, x19
0010325c  mov      w2, #1
00103260  bl       #0x147a20
00103264  ldr      w8, [x19]
00103268  cbnz     w8, #0x100318
0010326c  ldr      x1, [x20]
00103270  mov      x0, x19
00103274  bl       #0x147734
00103278  ldr      w8, [x19]
0010327c  cbnz     w8, #0x100318
00103280  ldr      x1, [x26]
00103284  mov      x0, x19
00103288  bl       #0x147220
0010328c  b        #0x104a18
00103290  ldp      x24, x25, [sp, #8]
00103294  b.ne     #0x12a8b4
00103298  ldr      x1, [x20]
0010329c  mov      x0, x19
001032a0  mov      w2, #7
001032a4  bl       #0x147630
001032a8  ldr      w8, [x19]
001032ac  cbnz     w8, #0x100318
001032b0  ldr      x1, [x20]
001032b4  mov      x0, x19
001032b8  mov      w2, wzr
001032bc  bl       #0x147630
001032c0  ldr      w8, [x19]
001032c4  cbnz     w8, #0x100318
001032c8  ldr      x1, [x20]
001032cc  mov      x0, x19
001032d0  bl       #0x147734
001032d4  ldr      w8, [x19]
001032d8  cbnz     w8, #0x100318
001032dc  mov      w1, w0
001032e0  ldp      x21, x0, [x20]
001032e4  bl       #0x147304
001032e8  mov      w2, w0
001032ec  mov      x0, x19
001032f0  mov      x1, x21
001032f4  bl       #0x147630
001032f8  ldr      w8, [x19]
001032fc  cbnz     w8, #0x100318
00103300  ldr      x1, [x20]
00103304  mov      x0, x19
00103308  bl       #0x147734
0010330c  ldr      w8, [x19]
00103310  cbnz     w8, #0x100318
00103314  mov      w21, w0
00103318  ldr      x1, [x20]
0010331c  mov      x0, x19
00103320  bl       #0x147734
00103324  ldr      w8, [x19]
00103328  cbnz     w8, #0x100318
0010332c  mov      w3, w0
00103330  ldr      x1, [x26]
00103334  mov      x0, x19
00103338  mov      w2, w21
0010333c  bl       #0x146ed8
00103340  ldr      w8, [x19]
00103344  cbnz     w8, #0x100318
00103348  ldr      x1, [x20]
0010334c  mov      x0, x19
00103350  mov      w2, wzr
00103354  bl       #0x147630
00103358  ldr      w8, [x19]
0010335c  cbnz     w8, #0x100318
00103360  ldr      x1, [x20]
00103364  mov      x0, x19
00103368  bl       #0x147734
0010336c  ldr      w8, [x19]
00103370  cbnz     w8, #0x100318
00103374  mov      w1, w0
00103378  ldp      x21, x0, [x20]
0010337c  bl       #0x147304
00103380  mov      w2, w0
00103384  mov      x0, x19
00103388  mov      x1, x21
0010338c  bl       #0x147630
00103390  ldr      w8, [x19]
00103394  cbnz     w8, #0x100318
00103398  ldr      x1, [x20]
0010339c  mov      x0, x19
001033a0  mov      w2, #3
001033a4  bl       #0x147630
001033a8  ldr      w8, [x19]
001033ac  cbnz     w8, #0x100318
001033b0  ldr      x1, [x20]
001033b4  mov      x0, x19
001033b8  mov      w2, #1
001033bc  bl       #0x147630
001033c0  ldr      w8, [x19]
001033c4  cbnz     w8, #0x100318
001033c8  ldr      x8, [sp, #0x18]
001033cc  mov      x0, x19
001033d0  mov      w2, #0x793
001033d4  b        #0x104938
001033d8  ldp      x24, x25, [sp, #8]
001033dc  b.ne     #0x12a8b4
001033e0  ldr      x1, [x26]
001033e4  mov      x0, x19
001033e8  bl       #0x147120
001033ec  ldr      x8, [sp, #0x18]
001033f0  mov      x0, x19
001033f4  mov      w2, #0xeb
001033f8  ldr      x1, [x8]
001033fc  bl       #0x146470
00103400  ldr      w8, [x19]
00103404  cbnz     w8, #0x100318
00103408  ldr      x1, [x26]
0010340c  mov      x0, x19
00103410  bl       #0x147120
00103414  ldr      x8, [sp, #0x18]
00103418  mov      x0, x19
0010341c  mov      w2, #0x1bf9
00103420  ldr      x1, [x8]
00103424  bl       #0x146470
00103428  ldr      w8, [x19]
0010342c  cbnz     w8, #0x100318
00103430  ldr      x1, [x20]
00103434  mov      x0, x19
00103438  mov      w2, #0x18
0010343c  bl       #0x147630
00103440  ldr      w8, [x19]
00103444  cbnz     w8, #0x100318
00103448  ldr      x1, [x20]
0010344c  mov      x0, x19
00103450  mov      w2, #1
00103454  bl       #0x14784c
00103458  ldr      w8, [x19]
0010345c  cbnz     w8, #0x100318
00103460  ldr      x1, [x20]
00103464  mov      x0, x19
00103468  bl       #0x147734
0010346c  ldr      w8, [x19]
00103470  cbnz     w8, #0x100318
00103474  mov      w21, w0
00103478  ldr      x1, [x20]
0010347c  mov      x0, x19
00103480  bl       #0x147734
00103484  ldr      w8, [x19]
00103488  cbnz     w8, #0x100318
0010348c  ldr      x1, [x20]
00103490  lsr      w2, w21, w0
00103494  mov      x0, x19
00103498  bl       #0x147630
0010349c  ldr      w8, [x19]
001034a0  cbnz     w8, #0x100318
001034a4  ldr      x1, [x20]
001034a8  mov      x0, x19
001034ac  mov      w2, #8
001034b0  bl       #0x147630
001034b4  ldr      w8, [x19]
001034b8  cbnz     w8, #0x100318
001034bc  ldr      x1, [x20]
001034c0  mov      x0, x19
001034c4  mov      w2, #2
001034c8  bl       #0x14784c
001034cc  ldr      w8, [x19]
001034d0  cbnz     w8, #0x100318
001034d4  ldr      x1, [x20]
001034d8  mov      x0, x19
001034dc  mov      w2, #0xff0000
001034e0  bl       #0x147630
001034e4  ldr      w8, [x19]
001034e8  cbnz     w8, #0x100318
001034ec  ldr      x1, [x20]
001034f0  mov      x0, x19
001034f4  bl       #0x147734
001034f8  ldr      w8, [x19]
001034fc  cbnz     w8, #0x100318
00103500  mov      w21, w0
00103504  ldr      x1, [x20]
00103508  mov      x0, x19
0010350c  bl       #0x147734
00103510  ldr      w8, [x19]
00103514  cbnz     w8, #0x100318
00103518  ldr      x1, [x20]
0010351c  and      w2, w0, w21
00103520  mov      x0, x19
00103524  bl       #0x147630
00103528  ldr      w8, [x19]
0010352c  cbnz     w8, #0x100318
00103530  ldr      x1, [x20]
00103534  mov      x0, x19
00103538  bl       #0x147734
0010353c  ldr      w8, [x19]
00103540  cbnz     w8, #0x100318
00103544  mov      w21, w0
00103548  ldr      x1, [x20]
0010354c  mov      x0, x19
00103550  bl       #0x147734
00103554  ldr      w8, [x19]
00103558  cbnz     w8, #0x100318
0010355c  ldr      x1, [x20]
00103560  lsr      w2, w21, w0
00103564  mov      x0, x19
00103568  bl       #0x147630
0010356c  ldr      w8, [x19]
00103570  cbnz     w8, #0x100318
00103574  ldr      x1, [x20]
00103578  mov      x0, x19
0010357c  bl       #0x147734
00103580  ldr      w8, [x19]
00103584  cbnz     w8, #0x100318
00103588  mov      w21, w0
0010358c  ldr      x1, [x20]
00103590  mov      x0, x19
00103594  bl       #0x147734
00103598  ldr      w8, [x19]
0010359c  cbnz     w8, #0x100318
001035a0  ldr      x1, [x20]
001035a4  orr      w2, w0, w21
001035a8  mov      x0, x19
001035ac  bl       #0x147630
001035b0  ldr      w8, [x19]
001035b4  cbnz     w8, #0x100318
001035b8  ldr      x1, [x20]
001035bc  mov      x0, x19
001035c0  mov      w2, #8
001035c4  bl       #0x147630
001035c8  ldr      w8, [x19]
001035cc  cbnz     w8, #0x100318
001035d0  ldr      x1, [x20]
001035d4  mov      x0, x19
001035d8  mov      w2, #2
001035dc  bl       #0x14784c
001035e0  ldr      w8, [x19]
001035e4  cbnz     w8, #0x100318
001035e8  ldr      x1, [x20]
001035ec  mov      x0, x19
001035f0  mov      w2, #0xff00
001035f4  bl       #0x147630
001035f8  ldr      w8, [x19]
001035fc  cbnz     w8, #0x100318
00103600  ldr      x1, [x20]
00103604  mov      x0, x19
00103608  bl       #0x147734
0010360c  ldr      w8, [x19]
00103610  cbnz     w8, #0x100318
00103614  mov      w21, w0
00103618  ldr      x1, [x20]
0010361c  mov      x0, x19
00103620  bl       #0x147734
00103624  ldr      w8, [x19]
00103628  cbnz     w8, #0x100318
0010362c  ldr      x1, [x20]
00103630  and      w2, w0, w21
00103634  mov      x0, x19
00103638  bl       #0x147630
0010363c  ldr      w8, [x19]
00103640  cbnz     w8, #0x100318
00103644  ldr      x1, [x20]
00103648  mov      x0, x19
0010364c  bl       #0x147734
00103650  ldr      w8, [x19]
00103654  cbnz     w8, #0x100318
00103658  mov      w21, w0
0010365c  ldr      x1, [x20]
00103660  mov      x0, x19
00103664  bl       #0x147734
00103668  ldr      w8, [x19]
0010366c  cbnz     w8, #0x100318
00103670  ldr      x1, [x20]
00103674  lsl      w2, w21, w0
00103678  mov      x0, x19
0010367c  bl       #0x147630
00103680  ldr      w8, [x19]
00103684  cbnz     w8, #0x100318
00103688  ldr      x1, [x20]
0010368c  mov      x0, x19
00103690  bl       #0x147734
00103694  ldr      w8, [x19]
00103698  cbnz     w8, #0x100318
0010369c  mov      w21, w0
001036a0  ldr      x1, [x20]
001036a4  mov      x0, x19
001036a8  bl       #0x147734
001036ac  ldr      w8, [x19]
001036b0  cbnz     w8, #0x100318
001036b4  ldr      x1, [x20]
001036b8  orr      w2, w0, w21
001036bc  mov      x0, x19
001036c0  bl       #0x147630
001036c4  ldr      w8, [x19]
001036c8  cbnz     w8, #0x100318
001036cc  ldr      x1, [x20]
001036d0  mov      x0, x19
001036d4  mov      w2, #0x18
001036d8  bl       #0x147630
001036dc  ldr      w8, [x19]
001036e0  cbnz     w8, #0x100318
001036e4  ldr      x1, [x20]
001036e8  mov      x0, x19
001036ec  mov      w2, #2
001036f0  bl       #0x14784c
001036f4  ldr      w8, [x19]
001036f8  cbnz     w8, #0x100318
001036fc  ldr      x1, [x20]
00103700  mov      x0, x19
00103704  mov      w2, #0xff
00103708  bl       #0x147630
0010370c  ldr      w8, [x19]
00103710  cbnz     w8, #0x100318
00103714  ldr      x1, [x20]
00103718  mov      x0, x19
0010371c  bl       #0x147734
00103720  ldr      w8, [x19]
00103724  cbnz     w8, #0x100318
00103728  mov      w21, w0
0010372c  ldr      x1, [x20]
00103730  mov      x0, x19
00103734  bl       #0x147734
00103738  ldr      w8, [x19]
0010373c  cbnz     w8, #0x100318
00103740  ldr      x1, [x20]
00103744  and      w2, w0, w21
00103748  mov      x0, x19
0010374c  bl       #0x147630
00103750  ldr      w8, [x19]
00103754  cbnz     w8, #0x100318
00103758  ldr      x1, [x20]
0010375c  mov      x0, x19
00103760  bl       #0x147734
00103764  ldr      w8, [x19]
00103768  cbnz     w8, #0x100318
0010376c  mov      w21, w0
00103770  ldr      x1, [x20]
00103774  mov      x0, x19
00103778  bl       #0x147734
0010377c  ldr      w8, [x19]
00103780  cbnz     w8, #0x100318
00103784  ldr      x1, [x20]
00103788  lsl      w2, w21, w0
0010378c  mov      x0, x19
00103790  bl       #0x147630
00103794  ldr      w8, [x19]
00103798  cbnz     w8, #0x100318
0010379c  ldr      x1, [x20]
001037a0  mov      x0, x19
001037a4  bl       #0x147734
001037a8  ldr      w8, [x19]
001037ac  cbnz     w8, #0x100318
001037b0  mov      w21, w0
001037b4  ldr      x1, [x20]
001037b8  mov      x0, x19
001037bc  bl       #0x147734
001037c0  ldr      w8, [x19]
001037c4  cbnz     w8, #0x100318
001037c8  ldr      x1, [x20]
001037cc  orr      w2, w0, w21
001037d0  b        #0x103244
001037d4  ldp      x24, x25, [sp, #8]
001037d8  b.ne     #0x12a8b4
001037dc  ldr      x1, [x20]
001037e0  mov      x0, x19
001037e4  mov      w2, #0xf
001037e8  bl       #0x147630
001037ec  ldr      w8, [x19]
001037f0  cbnz     w8, #0x100318
001037f4  ldr      x1, [x20]
001037f8  mov      x0, x19
001037fc  bl       #0x147734
00103800  ldr      w8, [x19]
00103804  cbnz     w8, #0x100318
00103808  mov      w1, w0
0010380c  ldp      x21, x0, [x20]
00103810  bl       #0x147304
00103814  mov      w2, w0
00103818  mov      x0, x19
0010381c  mov      x1, x21
00103820  bl       #0x147630
00103824  ldr      w8, [x19]
00103828  cbnz     w8, #0x100318
0010382c  ldr      x1, [x20]
00103830  mov      x0, x19
00103834  mov      w2, wzr
00103838  bl       #0x147630
0010383c  ldr      w8, [x19]
00103840  cbnz     w8, #0x100318
00103844  ldr      x1, [x20]
00103848  mov      x0, x19
0010384c  mov      w2, #0x20
00103850  bl       #0x147630
00103854  ldr      w8, [x19]
00103858  cbnz     w8, #0x100318
0010385c  ldr      x8, [sp, #0x18]
00103860  mov      x0, x19
00103864  mov      w2, #0x534
00103868  b        #0x104938
0010386c  ldp      x24, x25, [sp, #8]
00103870  b.ne     #0x12a8b4
00103874  ldr      x1, [x20]
00103878  mov      x0, x19
0010387c  mov      w2, #5
00103880  bl       #0x147630
00103884  ldr      w8, [x19]
00103888  cbnz     w8, #0x100318
0010388c  ldr      x1, [x20]
00103890  mov      x0, x19
00103894  mov      w2, wzr
00103898  bl       #0x147630
0010389c  ldr      w8, [x19]
001038a0  cbnz     w8, #0x100318
001038a4  ldr      x1, [x20]
001038a8  mov      x0, x19
001038ac  bl       #0x147734
001038b0  ldr      w8, [x19]
001038b4  cbnz     w8, #0x100318
001038b8  mov      w1, w0
001038bc  ldp      x21, x0, [x20]
001038c0  bl       #0x147304
001038c4  mov      w2, w0
001038c8  mov      x0, x19
001038cc  mov      x1, x21
001038d0  bl       #0x147630
001038d4  ldr      w8, [x19]
001038d8  cbnz     w8, #0x100318
001038dc  ldr      x1, [x20]
001038e0  mov      x0, x19
001038e4  bl       #0x147734
001038e8  ldr      w8, [x19]
001038ec  cbnz     w8, #0x100318
001038f0  mov      w21, w0
001038f4  ldr      x1, [x20]
001038f8  mov      x0, x19
001038fc  bl       #0x147734
00103900  ldr      w8, [x19]
00103904  cbnz     w8, #0x100318
00103908  mov      w3, w0
0010390c  ldr      x1, [x26]
00103910  mov      x0, x19
00103914  mov      w2, w21
00103918  bl       #0x146ed8
0010391c  ldr      w8, [x19]
00103920  cbnz     w8, #0x100318
00103924  ldr      x1, [x20]
00103928  mov      x0, x19
0010392c  mov      w2, wzr
00103930  bl       #0x147630
00103934  ldr      w8, [x19]
00103938  cbnz     w8, #0x100318
0010393c  ldr      x1, [x20]
00103940  mov      x0, x19
00103944  bl       #0x147734
00103948  ldr      w8, [x19]
0010394c  cbnz     w8, #0x100318
00103950  mov      w1, w0
00103954  ldp      x21, x0, [x20]
00103958  bl       #0x147304
0010395c  mov      w2, w0
00103960  mov      x0, x19
00103964  mov      x1, x21
00103968  bl       #0x147630
0010396c  ldr      w8, [x19]
00103970  cbnz     w8, #0x100318
00103974  ldr      x1, [x20]
00103978  mov      x0, x19
0010397c  mov      w2, #3
00103980  bl       #0x147630
00103984  ldr      w8, [x19]
00103988  cbnz     w8, #0x100318
0010398c  ldr      x1, [x20]
00103990  mov      x0, x19
00103994  mov      w2, #1
00103998  bl       #0x147630
0010399c  ldr      w8, [x19]
001039a0  cbnz     w8, #0x100318
001039a4  ldr      x8, [sp, #0x18]
001039a8  mov      x0, x19
001039ac  mov      w2, #0x727
001039b0  b        #0x104938
001039b4  ldp      x24, x25, [sp, #8]
001039b8  b.ne     #0x12a8b4
001039bc  ldr      x1, [x20]
001039c0  mov      x0, x19
001039c4  mov      w2, #1
001039c8  bl       #0x147630
001039cc  ldr      w8, [x19]
001039d0  cbnz     w8, #0x100318
001039d4  ldr      x1, [x20]
001039d8  mov      x0, x19
001039dc  bl       #0x147734
001039e0  ldr      w8, [x19]
001039e4  cbnz     w8, #0x100318
001039e8  mov      w1, w0
001039ec  ldp      x21, x0, [x20]
001039f0  bl       #0x147304
001039f4  mov      w2, w0
001039f8  mov      x0, x19
001039fc  mov      x1, x21
00103a00  bl       #0x147630
00103a04  ldr      w8, [x19]
00103a08  cbnz     w8, #0x100318
00103a0c  ldr      x1, [x20]
00103a10  mov      x0, x19
00103a14  mov      w2, wzr
00103a18  bl       #0x147630
00103a1c  ldr      w8, [x19]
00103a20  cbnz     w8, #0x100318
00103a24  ldr      x1, [x20]
00103a28  mov      x0, x19
00103a2c  mov      w2, #2
00103a30  bl       #0x147630
00103a34  ldr      w8, [x19]
00103a38  cbnz     w8, #0x100318
00103a3c  ldr      x1, [x20]
00103a40  mov      x0, x19
00103a44  bl       #0x147734
00103a48  ldr      w8, [x19]
00103a4c  cbnz     w8, #0x100318
00103a50  mov      w1, w0
00103a54  ldp      x21, x0, [x20]
00103a58  bl       #0x147304
00103a5c  mov      w2, w0
00103a60  mov      x0, x19
00103a64  mov      x1, x21
00103a68  bl       #0x147630
00103a6c  ldr      w8, [x19]
00103a70  cbnz     w8, #0x100318
00103a74  ldr      x1, [x20]
00103a78  mov      x0, x19
00103a7c  bl       #0x147734
00103a80  ldr      w8, [x19]
00103a84  cbnz     w8, #0x100318
00103a88  mov      w1, w0
00103a8c  ldp      x21, x0, [x20]
00103a90  bl       #0x147304
00103a94  mov      w2, w0
00103a98  mov      x0, x19
00103a9c  mov      x1, x21
00103aa0  bl       #0x147630
00103aa4  ldr      w8, [x19]
00103aa8  cbnz     w8, #0x100318
00103aac  ldr      x8, [sp, #0x18]
00103ab0  mov      x0, x19
00103ab4  mov      w2, #0x651
00103ab8  b        #0x104938
00103abc  b.ne     #0x103bb0
00103ac0  ldr      x1, [x20]
00103ac4  mov      x0, x19
00103ac8  mov      w2, wzr
00103acc  bl       #0x147630
00103ad0  ldp      x24, x25, [sp, #8]
00103ad4  ldr      w8, [x19]
00103ad8  cbnz     w8, #0x100318
00103adc  ldr      x1, [x20]
00103ae0  mov      x0, x19
00103ae4  mov      w2, #0x16
00103ae8  bl       #0x147630
00103aec  ldr      w8, [x19]
00103af0  cbnz     w8, #0x100318
00103af4  ldr      x1, [x20]
00103af8  mov      x0, x19
00103afc  bl       #0x147734
00103b00  ldr      w8, [x19]
00103b04  cbnz     w8, #0x100318
00103b08  mov      w1, w0
00103b0c  ldp      x21, x0, [x20]
00103b10  bl       #0x147304
00103b14  mov      w2, w0
00103b18  mov      x0, x19
00103b1c  mov      x1, x21
00103b20  bl       #0x147630
00103b24  ldr      w8, [x19]
00103b28  cbnz     w8, #0x100318
00103b2c  ldr      x1, [x20]
00103b30  mov      x0, x19
00103b34  bl       #0x147734
00103b38  ldr      w8, [x19]
00103b3c  cbnz     w8, #0x100318
00103b40  mov      w21, w0
00103b44  ldr      x1, [x20]
00103b48  mov      x0, x19
00103b4c  bl       #0x147734
00103b50  ldr      w8, [x19]
00103b54  cbnz     w8, #0x100318
00103b58  add      x28, x20, w0, uxtw #3
00103b5c  ldr      x0, [x28, #0x20]!
00103b60  bl       #0x1472e8
00103b64  mov      w22, w0
00103b68  mov      w23, wzr
00103b6c  cmp      w22, w23
00103b70  b.eq     #0x106164
00103b74  ldr      x0, [x28]
00103b78  mov      w1, w23
00103b7c  ldr      x24, [x26]
00103b80  add      w25, w21, w23
00103b84  bl       #0x147304
00103b88  mov      w3, w0
00103b8c  mov      x0, x19
00103b90  mov      x1, x24
00103b94  mov      w2, w25
00103b98  bl       #0x146ed8
00103b9c  ldp      x24, x25, [sp, #8]
00103ba0  add      w23, w23, #1
00103ba4  ldr      w8, [x19]
00103ba8  cbz      w8, #0x103b6c
00103bac  b        #0x100318
00103bb0  lsr      w9, w0, #1
00103bb4  lsr      w8, w0, #2
00103bb8  lsr      w10, w0, #3
00103bbc  lsr      w11, w0, #5
00103bc0  cmp      w9, #0xdd1
00103bc4  b.hs     #0x105f80
00103bc8  mov      w12, #0x1859
00103bcc  cmp      w0, w12
00103bd0  b.hs     #0x106918
00103bd4  cmp      w0, #0xbea
00103bd8  b.hs     #0x108c24
00103bdc  cmp      w0, #0xa9e
00103be0  b.hs     #0x109a48
00103be4  cmp      w0, #0xa1c
00103be8  b.hs     #0x10bdf4
00103bec  ldp      x24, x25, [sp, #8]
00103bf0  cmp      w0, #0x90d
00103bf4  b.ne     #0x12a8b4
00103bf8  ldr      x1, [x20]
00103bfc  mov      x0, x19
00103c00  mov      w2, wzr
00103c04  bl       #0x147630
00103c08  ldr      w8, [x19]
00103c0c  cbnz     w8, #0x100318
00103c10  ldr      x1, [x20]
00103c14  mov      x0, x19
00103c18  mov      w2, #0x16
00103c1c  bl       #0x147630
00103c20  ldr      w8, [x19]
00103c24  cbnz     w8, #0x100318
00103c28  ldr      x1, [x20]
00103c2c  mov      x0, x19
00103c30  bl       #0x147734
00103c34  ldr      w8, [x19]
00103c38  cbnz     w8, #0x100318
00103c3c  mov      w1, w0
00103c40  ldp      x21, x0, [x20]
00103c44  bl       #0x147304
00103c48  mov      w2, w0
00103c4c  mov      x0, x19
00103c50  mov      x1, x21
00103c54  bl       #0x147630
00103c58  ldr      w8, [x19]
00103c5c  cbnz     w8, #0x100318
00103c60  ldr      x1, [x20]
00103c64  mov      x0, x19
00103c68  mov      w2, #0x15
00103c6c  bl       #0x147630
00103c70  ldr      w8, [x19]
00103c74  cbnz     w8, #0x100318
00103c78  ldr      x1, [x20]
00103c7c  mov      x0, x19
00103c80  bl       #0x147734
00103c84  ldr      w8, [x19]
00103c88  cbnz     w8, #0x100318
00103c8c  mov      w1, w0
00103c90  ldp      x21, x0, [x20]
00103c94  bl       #0x147304
00103c98  mov      w2, w0
00103c9c  mov      x0, x19
00103ca0  mov      x1, x21
00103ca4  bl       #0x147630
00103ca8  ldr      w8, [x19]
00103cac  cbnz     w8, #0x100318
00103cb0  ldr      x1, [x20]
00103cb4  mov      x0, x19
00103cb8  bl       #0x147734
00103cbc  ldr      w8, [x19]
00103cc0  cbnz     w8, #0x100318
00103cc4  mov      w1, w0
00103cc8  ldp      x21, x0, [x20]
00103ccc  bl       #0x147304
00103cd0  mov      w2, w0
00103cd4  mov      x0, x19
00103cd8  mov      x1, x21
00103cdc  bl       #0x147630
00103ce0  ldr      w8, [x19]
00103ce4  cbnz     w8, #0x100318
00103ce8  ldr      x1, [x20]
00103cec  mov      x0, x19
00103cf0  bl       #0x147734
00103cf4  ldr      w8, [x19]
00103cf8  cbnz     w8, #0x100318
00103cfc  mov      w21, w0
00103d00  ldr      x1, [x20]
00103d04  mov      x0, x19
00103d08  bl       #0x147734
00103d0c  ldr      w8, [x19]
00103d10  cbnz     w8, #0x100318
00103d14  ldr      x1, [x20]
00103d18  add      w2, w0, w21
00103d1c  mov      x0, x19
00103d20  bl       #0x147630
00103d24  ldr      w8, [x19]
00103d28  cbnz     w8, #0x100318
00103d2c  ldr      x1, [x20]
00103d30  mov      x0, x19
00103d34  bl       #0x147734
00103d38  ldr      w8, [x19]
00103d3c  cbnz     w8, #0x100318
00103d40  mov      w21, w0
00103d44  ldr      x1, [x20]
00103d48  mov      x0, x19
00103d4c  bl       #0x147734
00103d50  ldr      w8, [x19]
00103d54  cbnz     w8, #0x100318
00103d58  add      x28, x20, w0, uxtw #3
00103d5c  ldr      x0, [x28, #0x20]!
00103d60  bl       #0x1472e8
00103d64  mov      w22, w0
00103d68  mov      w23, wzr
00103d6c  cmp      w22, w23
00103d70  b.eq     #0x1142e8
00103d74  ldr      x0, [x28]
00103d78  mov      w1, w23
00103d7c  ldr      x24, [x26]
00103d80  add      w25, w21, w23
00103d84  bl       #0x147304
00103d88  mov      w3, w0
00103d8c  mov      x0, x19
00103d90  mov      x1, x24
00103d94  mov      w2, w25
00103d98  bl       #0x146ed8
00103d9c  ldp      x24, x25, [sp, #8]
00103da0  add      w23, w23, #1
00103da4  ldr      w8, [x19]
00103da8  cbz      w8, #0x103d6c
00103dac  b        #0x100318
00103db0  ldr      x1, [x20]
00103db4  mov      x0, x19
00103db8  mov      w2, wzr
00103dbc  bl       #0x147630
00103dc0  ldp      x24, x25, [sp, #8]
00103dc4  ldr      w8, [x19]
00103dc8  cbnz     w8, #0x100318
00103dcc  ldr      x1, [x20]
00103dd0  mov      x0, x19
00103dd4  bl       #0x147734
00103dd8  ldr      w8, [x19]
00103ddc  cbnz     w8, #0x100318
00103de0  add      x8, x20, w0, uxtw #3
00103de4  ldr      x21, [x20]
00103de8  ldr      x0, [x8, #0x20]
00103dec  bl       #0x1472e8
00103df0  mov      w2, w0
00103df4  mov      x0, x19
00103df8  mov      x1, x21
00103dfc  bl       #0x147630
00103e00  ldr      w8, [x19]
00103e04  cbnz     w8, #0x100318
00103e08  ldr      x1, [x20]
00103e0c  mov      x0, x19
00103e10  mov      w2, #3
00103e14  bl       #0x147630
00103e18  ldr      w8, [x19]
00103e1c  cbnz     w8, #0x100318
00103e20  ldr      x1, [x20]
00103e24  mov      x0, x19
00103e28  bl       #0x147734
00103e2c  ldr      w8, [x19]
00103e30  cbnz     w8, #0x100318
00103e34  mov      w1, w0
00103e38  ldp      x21, x0, [x20]
00103e3c  bl       #0x147304
00103e40  mov      w2, w0
00103e44  mov      x0, x19
00103e48  mov      x1, x21
00103e4c  bl       #0x147630
00103e50  ldr      w8, [x19]
00103e54  cbnz     w8, #0x100318
00103e58  ldr      x1, [x20]
00103e5c  mov      x0, x19
00103e60  bl       #0x147734
00103e64  ldr      w8, [x19]
00103e68  cbnz     w8, #0x100318
00103e6c  mov      w21, w0
00103e70  ldr      x1, [x20]
00103e74  mov      x0, x19
00103e78  bl       #0x147734
00103e7c  ldr      w8, [x19]
00103e80  cbnz     w8, #0x100318
00103e84  mov      w3, w0
00103e88  ldr      x1, [x26]
00103e8c  mov      x0, x19
00103e90  mov      w2, w21
00103e94  bl       #0x146ed8
00103e98  ldr      w8, [x19]
00103e9c  cbnz     w8, #0x100318
00103ea0  ldr      x1, [x20]
00103ea4  mov      x0, x19
00103ea8  mov      w2, #3
00103eac  bl       #0x147630
00103eb0  ldr      w8, [x19]
00103eb4  cbnz     w8, #0x100318
00103eb8  ldr      x1, [x20]
00103ebc  mov      x0, x19
00103ec0  bl       #0x147734
00103ec4  ldr      w8, [x19]
00103ec8  cbnz     w8, #0x100318
00103ecc  mov      w1, w0
00103ed0  ldp      x21, x0, [x20]
00103ed4  bl       #0x147304
00103ed8  mov      w2, w0
00103edc  mov      x0, x19
00103ee0  mov      x1, x21
00103ee4  bl       #0x147630
00103ee8  ldr      w8, [x19]
00103eec  cbnz     w8, #0x100318
00103ef0  ldr      x1, [x20]
00103ef4  mov      x0, x19
00103ef8  bl       #0x147734
00103efc  ldr      w8, [x19]
00103f00  cbnz     w8, #0x100318
00103f04  mov      w1, w0
00103f08  ldp      x21, x0, [x20]
00103f0c  bl       #0x147304
00103f10  mov      w2, w0
00103f14  mov      x0, x19
00103f18  mov      x1, x21
00103f1c  bl       #0x147630
00103f20  ldr      w8, [x19]
00103f24  cbnz     w8, #0x100318
00103f28  ldr      x1, [x20]
00103f2c  mov      x0, x19
00103f30  mov      w2, #2
00103f34  bl       #0x147630
00103f38  ldr      w8, [x19]
00103f3c  cbnz     w8, #0x100318
00103f40  ldr      x1, [x20]
00103f44  mov      x0, x19
00103f48  bl       #0x147734
00103f4c  ldr      w8, [x19]
00103f50  cbnz     w8, #0x100318
00103f54  mov      w21, w0
00103f58  ldr      x1, [x20]
00103f5c  mov      x0, x19
00103f60  bl       #0x147734
00103f64  ldr      w8, [x19]
00103f68  cbnz     w8, #0x100318
00103f6c  mul      w2, w0, w21
00103f70  ldr      x1, [x20]
00103f74  mov      x0, x19
00103f78  bl       #0x147630
00103f7c  ldr      w8, [x19]
00103f80  cbnz     w8, #0x100318
00103f84  ldr      x1, [x20]
00103f88  mov      x0, x19
00103f8c  bl       #0x147a18
00103f90  ldr      w8, [x19]
00103f94  cbnz     w8, #0x100318
00103f98  ldr      x1, [x20]
00103f9c  mov      x0, x19
00103fa0  mov      w2, #4
00103fa4  bl       #0x147630
00103fa8  ldr      w8, [x19]
00103fac  cbnz     w8, #0x100318
00103fb0  ldr      x1, [x20]
00103fb4  mov      x0, x19
00103fb8  bl       #0x147734
00103fbc  ldr      w8, [x19]
00103fc0  cbnz     w8, #0x100318
00103fc4  mov      w1, w0
00103fc8  ldp      x21, x0, [x20]
00103fcc  bl       #0x147304
00103fd0  mov      w2, w0
00103fd4  mov      x0, x19
00103fd8  mov      x1, x21
00103fdc  bl       #0x147630
00103fe0  ldr      w8, [x19]
00103fe4  cbnz     w8, #0x100318
00103fe8  ldr      x1, [x20]
00103fec  mov      x0, x19
00103ff0  bl       #0x147734
00103ff4  ldr      w8, [x19]
00103ff8  cbnz     w8, #0x100318
00103ffc  mov      w21, w0
00104000  ldr      x1, [x20]
00104004  mov      x0, x19
00104008  bl       #0x147734
0010400c  ldr      w8, [x19]
00104010  cbnz     w8, #0x100318
00104014  mov      w3, w0
00104018  ldr      x1, [x26]
0010401c  mov      x0, x19
00104020  mov      w2, w21
00104024  bl       #0x146ed8
00104028  ldr      w8, [x19]
0010402c  cbnz     w8, #0x100318
00104030  ldr      x1, [x20]
00104034  mov      x0, x19
00104038  mov      w2, #2
0010403c  bl       #0x147630
00104040  ldr      w8, [x19]
00104044  cbnz     w8, #0x100318
00104048  ldr      x1, [x20]
0010404c  mov      x0, x19
00104050  bl       #0x147734
00104054  ldr      w8, [x19]
00104058  cbnz     w8, #0x100318
0010405c  mov      w21, w0
00104060  ldr      x1, [x20]
00104064  mov      x0, x19
00104068  bl       #0x147734
0010406c  ldr      w8, [x19]
00104070  cbnz     w8, #0x100318
00104074  mul      w2, w0, w21
00104078  ldr      x1, [x20]
0010407c  mov      x0, x19
00104080  bl       #0x147630
00104084  ldr      w8, [x19]
00104088  cbnz     w8, #0x100318
0010408c  ldr      x1, [x20]
00104090  mov      x0, x19
00104094  mov      w2, #2
00104098  bl       #0x147630
0010409c  ldr      w8, [x19]
001040a0  cbnz     w8, #0x100318
001040a4  ldr      x1, [x20]
001040a8  mov      x0, x19
001040ac  bl       #0x147734
001040b0  ldr      w8, [x19]
001040b4  cbnz     w8, #0x100318
001040b8  mov      w1, w0
001040bc  ldp      x21, x0, [x20]
001040c0  bl       #0x147304
001040c4  mov      w2, w0
001040c8  mov      x0, x19
001040cc  mov      x1, x21
001040d0  bl       #0x147630
001040d4  ldr      w8, [x19]
001040d8  cbnz     w8, #0x100318
001040dc  ldr      x1, [x20]
001040e0  mov      x0, x19
001040e4  bl       #0x147734
001040e8  ldr      w8, [x19]
001040ec  cbnz     w8, #0x100318
001040f0  mov      w21, w0
001040f4  ldr      x1, [x20]
001040f8  mov      x0, x19
001040fc  bl       #0x147734
00104100  ldr      w8, [x19]
00104104  cbnz     w8, #0x100318
00104108  mov      w3, w0
0010410c  ldr      x1, [x26]
00104110  mov      x0, x19
00104114  mov      w2, w21
00104118  bl       #0x146ed8
0010411c  ldr      w8, [x19]
00104120  cbnz     w8, #0x100318
00104124  ldr      x1, [x20]
00104128  mov      x0, x19
0010412c  mov      w2, #0x72
00104130  bl       #0x147630
00104134  ldr      w8, [x19]
00104138  cbnz     w8, #0x100318
0010413c  ldr      x1, [x20]
00104140  mov      x0, x19
00104144  mov      w2, #2
00104148  bl       #0x147630
0010414c  ldr      w8, [x19]
00104150  cbnz     w8, #0x100318
00104154  ldr      x1, [x20]
00104158  mov      x0, x19
0010415c  bl       #0x147734
00104160  ldr      w8, [x19]
00104164  cbnz     w8, #0x100318
00104168  mov      w1, w0
0010416c  ldp      x21, x0, [x20]
00104170  bl       #0x147304
00104174  mov      w2, w0
00104178  mov      x0, x19
0010417c  mov      x1, x21
00104180  bl       #0x147630
00104184  ldr      w8, [x19]
00104188  cbnz     w8, #0x100318
0010418c  ldr      x1, [x20]
00104190  mov      x0, x19
00104194  bl       #0x147734
00104198  ldr      w8, [x19]
0010419c  cbnz     w8, #0x100318
001041a0  mov      w1, w0
001041a4  ldp      x21, x0, [x20]
001041a8  bl       #0x147304
001041ac  mov      w2, w0
001041b0  mov      x0, x19
001041b4  mov      x1, x21
001041b8  bl       #0x147630
001041bc  ldr      w8, [x19]
001041c0  cbnz     w8, #0x100318
001041c4  ldr      x1, [x20]
001041c8  mov      x0, x19
001041cc  bl       #0x147734
001041d0  ldr      w8, [x19]
001041d4  cbnz     w8, #0x100318
001041d8  mov      w21, w0
001041dc  ldr      x1, [x20]
001041e0  mov      x0, x19
001041e4  bl       #0x147734
001041e8  ldr      w8, [x19]
001041ec  cbnz     w8, #0x100318
001041f0  ldr      x1, [x20]
001041f4  add      w2, w0, w21
001041f8  mov      x0, x19
001041fc  bl       #0x147630
00104200  ldr      w8, [x19]
00104204  cbnz     w8, #0x100318
00104208  ldr      x1, [x20]
0010420c  mov      x0, x19
00104210  mov      w2, #0x14
00104214  bl       #0x147630
00104218  ldr      w8, [x19]
0010421c  cbnz     w8, #0x100318
00104220  ldr      x1, [x20]
00104224  mov      x0, x19
00104228  bl       #0x147734
0010422c  ldr      w8, [x19]
00104230  cbnz     w8, #0x100318
00104234  mov      w1, w0
00104238  ldp      x21, x0, [x20]
0010423c  bl       #0x147304
00104240  mov      w2, w0
00104244  mov      x0, x19
00104248  mov      x1, x21
0010424c  bl       #0x147630
00104250  ldr      w8, [x19]
00104254  cbnz     w8, #0x100318
00104258  ldr      x1, [x20]
0010425c  mov      x0, x19
00104260  bl       #0x147734
00104264  ldr      w8, [x19]
00104268  cbnz     w8, #0x100318
0010426c  mov      w21, w0
00104270  ldr      x1, [x20]
00104274  mov      x0, x19
00104278  bl       #0x147734
0010427c  ldr      w8, [x19]
00104280  cbnz     w8, #0x100318
00104284  mov      w3, w0
00104288  ldr      x1, [x26]
0010428c  mov      x0, x19
00104290  mov      w2, w21
00104294  bl       #0x146ed8
00104298  ldr      w8, [x19]
0010429c  cbnz     w8, #0x100318
001042a0  ldr      x1, [x20]
001042a4  mov      x0, x19
001042a8  mov      w2, #0x14
001042ac  bl       #0x147630
001042b0  ldr      w8, [x19]
001042b4  cbnz     w8, #0x100318
001042b8  ldr      x1, [x20]
001042bc  mov      x0, x19
001042c0  bl       #0x147734
001042c4  ldr      w8, [x19]
001042c8  cbnz     w8, #0x100318
001042cc  mov      w1, w0
001042d0  ldp      x21, x0, [x20]
001042d4  bl       #0x147304
001042d8  mov      w2, w0
001042dc  mov      x0, x19
001042e0  mov      x1, x21
001042e4  bl       #0x147630
001042e8  ldr      w8, [x19]
001042ec  cbnz     w8, #0x100318
001042f0  ldr      x1, [x20]
001042f4  mov      x0, x19
001042f8  bl       #0x147734
001042fc  ldr      w8, [x19]
00104300  cbnz     w8, #0x100318
00104304  mov      w1, w0
00104308  ldp      x21, x0, [x20]
0010430c  bl       #0x147304
00104310  mov      w2, w0
00104314  mov      x0, x19
00104318  mov      x1, x21
0010431c  bl       #0x147630
00104320  ldr      w8, [x19]
00104324  cbnz     w8, #0x100318
00104328  ldr      x1, [x26]
0010432c  mov      x0, x19
00104330  bl       #0x147120
00104334  ldr      x8, [sp, #0x18]
00104338  mov      x0, x19
0010433c  mov      w2, #0x3d9
00104340  b        #0x1030b4
00104344  ldr      x1, [x20]
00104348  mov      x0, x19
0010434c  mov      w2, wzr
00104350  bl       #0x147630
00104354  ldp      x24, x25, [sp, #8]
00104358  ldr      w8, [x19]
0010435c  cbnz     w8, #0x100318
00104360  ldr      x1, [x20]
00104364  mov      x0, x19
00104368  bl       #0x147734
0010436c  ldr      w8, [x19]
00104370  cbnz     w8, #0x100318
00104374  add      x8, x20, w0, uxtw #3
00104378  ldr      x21, [x20]
0010437c  ldr      x0, [x8, #0x20]
00104380  bl       #0x1472e8
00104384  mov      w2, w0
00104388  mov      x0, x19
0010438c  mov      x1, x21
00104390  bl       #0x147630
00104394  ldr      w8, [x19]
00104398  cbnz     w8, #0x100318
0010439c  ldr      x1, [x20]
001043a0  mov      x0, x19
001043a4  mov      w2, #4
001043a8  bl       #0x147630
001043ac  ldr      w8, [x19]
001043b0  cbnz     w8, #0x100318
001043b4  ldr      x1, [x20]
001043b8  mov      x0, x19
001043bc  bl       #0x147734
001043c0  ldr      w8, [x19]
001043c4  cbnz     w8, #0x100318
001043c8  mov      w21, w0
001043cc  ldr      x1, [x20]
001043d0  mov      x0, x19
001043d4  bl       #0x147734
001043d8  ldr      w8, [x19]
001043dc  cbnz     w8, #0x100318
001043e0  mul      w2, w0, w21
001043e4  ldr      x1, [x20]
001043e8  mov      x0, x19
001043ec  bl       #0x147630
001043f0  ldr      w8, [x19]
001043f4  cbnz     w8, #0x100318
001043f8  ldr      x1, [x20]
001043fc  mov      x0, x19
00104400  mov      w2, #0x14
00104404  bl       #0x147630
00104408  ldr      w8, [x19]
0010440c  cbnz     w8, #0x100318
00104410  ldr      x1, [x20]
00104414  mov      x0, x19
00104418  bl       #0x147734
0010441c  ldr      w8, [x19]
00104420  cbnz     w8, #0x100318
00104424  mov      w1, w0
00104428  ldp      x21, x0, [x20]
0010442c  bl       #0x147304
00104430  mov      w2, w0
00104434  mov      x0, x19
00104438  mov      x1, x21
0010443c  bl       #0x147630
00104440  ldr      w8, [x19]
00104444  cbnz     w8, #0x100318
00104448  ldr      x1, [x20]
0010444c  mov      x0, x19
00104450  bl       #0x147734
00104454  ldr      w8, [x19]
00104458  cbnz     w8, #0x100318
0010445c  mov      w21, w0
00104460  ldr      x1, [x20]
00104464  mov      x0, x19
00104468  bl       #0x147734
0010446c  ldr      w8, [x19]
00104470  cbnz     w8, #0x100318
00104474  mov      w3, w0
00104478  ldr      x1, [x26]
0010447c  mov      x0, x19
00104480  mov      w2, w21
00104484  bl       #0x146ed8
00104488  ldr      w8, [x19]
0010448c  cbnz     w8, #0x100318
00104490  ldr      x1, [x20]
00104494  mov      x0, x19
00104498  mov      w2, #4
0010449c  bl       #0x147630
001044a0  ldr      w8, [x19]
001044a4  cbnz     w8, #0x100318
001044a8  ldr      x1, [x20]
001044ac  mov      x0, x19
001044b0  mov      w2, #0x14
001044b4  bl       #0x147630
001044b8  ldr      w8, [x19]
001044bc  cbnz     w8, #0x100318
001044c0  ldr      x1, [x20]
001044c4  mov      x0, x19
001044c8  bl       #0x147734
001044cc  ldr      w8, [x19]
001044d0  cbnz     w8, #0x100318
001044d4  mov      w1, w0
001044d8  ldp      x21, x0, [x20]
001044dc  bl       #0x147304
001044e0  mov      w2, w0
001044e4  mov      x0, x19
001044e8  mov      x1, x21
001044ec  bl       #0x147630
001044f0  ldr      w8, [x19]
001044f4  cbnz     w8, #0x100318
001044f8  ldr      x1, [x20]
001044fc  mov      x0, x19
00104500  bl       #0x147734
00104504  ldr      w8, [x19]
00104508  cbnz     w8, #0x100318
0010450c  mov      w1, w0
00104510  ldp      x21, x0, [x20]
00104514  bl       #0x147304
00104518  mov      w2, w0
0010451c  mov      x0, x19
00104520  mov      x1, x21
00104524  bl       #0x147630
00104528  ldr      w8, [x19]
0010452c  cbnz     w8, #0x100318
00104530  ldr      x1, [x20]
00104534  mov      x0, x19
00104538  bl       #0x147734
0010453c  ldr      w8, [x19]
00104540  cbnz     w8, #0x100318
00104544  mov      w21, w0
00104548  ldr      x1, [x20]
0010454c  mov      x0, x19
00104550  bl       #0x147734
00104554  ldr      w8, [x19]
00104558  cbnz     w8, #0x100318
0010455c  udiv     w2, w21, w0
00104560  ldr      x1, [x20]
00104564  mov      x0, x19
00104568  bl       #0x147630
0010456c  ldr      w8, [x19]
00104570  cbnz     w8, #0x100318
00104574  ldr      x1, [x20]
00104578  mov      x0, x19
0010457c  mov      w2, #0x15
00104580  bl       #0x147630
00104584  ldr      w8, [x19]
00104588  cbnz     w8, #0x100318
0010458c  ldr      x1, [x20]
00104590  mov      x0, x19
00104594  bl       #0x147734
00104598  ldr      w8, [x19]
0010459c  cbnz     w8, #0x100318
001045a0  mov      w1, w0
001045a4  ldp      x21, x0, [x20]
001045a8  bl       #0x147304
001045ac  mov      w2, w0
001045b0  mov      x0, x19
001045b4  mov      x1, x21
001045b8  bl       #0x147630
001045bc  ldr      w8, [x19]
001045c0  cbnz     w8, #0x100318
001045c4  ldr      x1, [x20]
001045c8  mov      x0, x19
001045cc  bl       #0x147734
001045d0  ldr      w8, [x19]
001045d4  cbnz     w8, #0x100318
001045d8  mov      w21, w0
001045dc  ldr      x1, [x20]
001045e0  mov      x0, x19
001045e4  bl       #0x147734
001045e8  ldr      w8, [x19]
001045ec  cbnz     w8, #0x100318
001045f0  mov      w3, w0
001045f4  ldr      x1, [x26]
001045f8  mov      x0, x19
001045fc  mov      w2, w21
00104600  bl       #0x146ed8
00104604  ldr      w8, [x19]
00104608  cbnz     w8, #0x100318
0010460c  ldr      x1, [x20]
00104610  mov      x0, x19
00104614  mov      w2, wzr
00104618  bl       #0x147630
0010461c  ldr      w8, [x19]
00104620  cbnz     w8, #0x100318
00104624  ldr      x1, [x20]
00104628  mov      x0, x19
0010462c  bl       #0x147734
00104630  ldr      w8, [x19]
00104634  cbnz     w8, #0x100318
00104638  add      x8, x20, w0, uxtw #3
0010463c  ldr      x21, [x20]
00104640  ldr      x0, [x8, #0x20]
00104644  bl       #0x1472e8
00104648  mov      w2, w0
0010464c  mov      x0, x19
00104650  mov      x1, x21
00104654  bl       #0x147630
00104658  ldr      w8, [x19]
0010465c  cbnz     w8, #0x100318
00104660  ldr      x1, [x20]
00104664  mov      x0, x19
00104668  mov      w2, #0x16
0010466c  bl       #0x147630
00104670  ldr      w8, [x19]
00104674  cbnz     w8, #0x100318
00104678  ldr      x1, [x20]
0010467c  mov      x0, x19
00104680  bl       #0x147734
00104684  ldr      w8, [x19]
00104688  cbnz     w8, #0x100318
0010468c  mov      w1, w0
00104690  ldp      x21, x0, [x20]
00104694  bl       #0x147304
00104698  mov      w2, w0
0010469c  mov      x0, x19
001046a0  mov      x1, x21
001046a4  bl       #0x147630
001046a8  ldr      w8, [x19]
001046ac  cbnz     w8, #0x100318
001046b0  ldr      x1, [x20]
001046b4  mov      x0, x19
001046b8  mov      w2, wzr
001046bc  bl       #0x147630
001046c0  ldr      w8, [x19]
001046c4  cbnz     w8, #0x100318
001046c8  ldr      x1, [x20]
001046cc  mov      x0, x19
001046d0  bl       #0x147734
001046d4  ldr      w8, [x19]
001046d8  cbnz     w8, #0x100318
001046dc  mov      w22, w0
001046e0  cmp      w0, #0xf
001046e4  b.hi     #0x12aa34
001046e8  ldr      x1, [x20]
001046ec  mov      x0, x19
001046f0  bl       #0x147734
001046f4  ldp      x24, x25, [sp, #8]
001046f8  ldr      w8, [x19]
001046fc  cbnz     w8, #0x100318
00104700  mov      w21, w0
00104704  ldr      x1, [x20]
00104708  mov      x0, x19
0010470c  bl       #0x147734
00104710  ldr      w8, [x19]
00104714  cbnz     w8, #0x100318
00104718  add      x28, x20, w22, uxtw #3
0010471c  mov      w23, w0
00104720  mov      x0, x19
00104724  ldr      x1, [x28, #0x20]!
00104728  bl       #0x147220
0010472c  ldr      w8, [x19]
00104730  cbnz     w8, #0x100318
00104734  ldr      x1, [x28]
00104738  mov      x0, x19
0010473c  bl       #0x147120
00104740  ldr      w8, [x19]
00104744  cbnz     w8, #0x100318
00104748  mov      w22, wzr
0010474c  add      w27, w23, w21
00104750  add      w1, w21, w22
00104754  cmp      w1, w27
00104758  b.hs     #0x109714
0010475c  ldr      x0, [x26]
00104760  ldr      x23, [x28]
00104764  bl       #0x147304
00104768  mov      w3, w0
0010476c  mov      x0, x19
00104770  mov      x1, x23
00104774  mov      w2, w22
00104778  bl       #0x146ed8
0010477c  ldp      x24, x25, [sp, #8]
00104780  add      w22, w22, #1
00104784  ldr      w8, [x19]
00104788  cbz      w8, #0x104750
0010478c  b        #0x100318
00104790  ldr      x1, [x20]
00104794  mov      x0, x19
00104798  mov      w2, #1
0010479c  bl       #0x147630
001047a0  ldp      x24, x25, [sp, #8]
001047a4  ldr      w8, [x19]
001047a8  cbnz     w8, #0x100318
001047ac  ldr      x1, [x20]
001047b0  mov      x0, x19
001047b4  mov      w2, wzr
001047b8  bl       #0x147630
001047bc  ldr      w8, [x19]
001047c0  cbnz     w8, #0x100318
001047c4  ldr      x1, [x20]
001047c8  mov      x0, x19
001047cc  bl       #0x147734
001047d0  ldr      w8, [x19]
001047d4  cbnz     w8, #0x100318
001047d8  mov      w1, w0
001047dc  ldp      x21, x0, [x20]
001047e0  bl       #0x147304
001047e4  mov      w2, w0
001047e8  mov      x0, x19
001047ec  mov      x1, x21
001047f0  bl       #0x147630
001047f4  ldr      w8, [x19]
001047f8  cbnz     w8, #0x100318
001047fc  ldr      x1, [x20]
00104800  mov      x0, x19
00104804  bl       #0x147734
00104808  ldr      w8, [x19]
0010480c  cbnz     w8, #0x100318
00104810  mov      w21, w0
00104814  ldr      x1, [x20]
00104818  mov      x0, x19
0010481c  bl       #0x147734
00104820  ldr      w8, [x19]
00104824  cbnz     w8, #0x100318
00104828  mov      w3, w0
0010482c  ldr      x1, [x26]
00104830  mov      x0, x19
00104834  mov      w2, w21
00104838  bl       #0x146ed8
0010483c  ldr      w8, [x19]
00104840  cbnz     w8, #0x100318
00104844  ldr      x1, [x20]
00104848  mov      x0, x19
0010484c  mov      w2, #0x16
00104850  bl       #0x147630
00104854  ldr      w8, [x19]
00104858  cbnz     w8, #0x100318
0010485c  ldr      x1, [x20]
00104860  mov      x0, x19
00104864  bl       #0x147734
00104868  ldr      w8, [x19]
0010486c  cbnz     w8, #0x100318
00104870  mov      w1, w0
00104874  ldp      x21, x0, [x20]
00104878  bl       #0x147304
0010487c  mov      w2, w0
00104880  mov      x0, x19
00104884  mov      x1, x21
00104888  bl       #0x147630
0010488c  ldr      w8, [x19]
00104890  cbnz     w8, #0x100318
00104894  ldr      x1, [x20]
00104898  mov      x0, x19
0010489c  mov      w2, wzr
001048a0  bl       #0x147630
001048a4  ldr      w8, [x19]
001048a8  cbnz     w8, #0x100318
001048ac  ldr      x1, [x20]
001048b0  mov      x0, x19
001048b4  mov      w2, wzr
001048b8  bl       #0x147630
001048bc  ldr      w8, [x19]
001048c0  cbnz     w8, #0x100318
001048c4  ldr      x1, [x20]
001048c8  mov      x0, x19
001048cc  bl       #0x147734
001048d0  ldr      w8, [x19]
001048d4  cbnz     w8, #0x100318
001048d8  mov      w1, w0
001048dc  ldp      x21, x0, [x20]
001048e0  bl       #0x147304
001048e4  mov      w2, w0
001048e8  mov      x0, x19
001048ec  mov      x1, x21
001048f0  bl       #0x147630
001048f4  ldr      w8, [x19]
001048f8  cbnz     w8, #0x100318
001048fc  ldr      x1, [x20]
00104900  mov      x0, x19
00104904  mov      w2, #3
00104908  bl       #0x147630
0010490c  ldr      w8, [x19]
00104910  cbnz     w8, #0x100318
00104914  ldr      x1, [x20]
00104918  mov      x0, x19
0010491c  mov      w2, #1
00104920  bl       #0x147630
00104924  ldr      w8, [x19]
00104928  cbnz     w8, #0x100318
0010492c  ldr      x8, [sp, #0x18]
00104930  mov      x0, x19
00104934  mov      w2, #0x625
00104938  ldr      x1, [x8]
0010493c  bl       #0x146470
00104940  ldr      w8, [x19]
00104944  cbnz     w8, #0x100318
00104948  ldr      x1, [x20]
0010494c  mov      x0, x19
00104950  bl       #0x147a18
00104954  ldr      w8, [x19]
00104958  cbnz     w8, #0x100318
0010495c  ldr      x1, [x20]
00104960  mov      x0, x19
00104964  mov      w2, wzr
00104968  bl       #0x147630
0010496c  ldr      w8, [x19]
00104970  cbnz     w8, #0x100318
00104974  ldr      x1, [x20]
00104978  mov      x0, x19
0010497c  bl       #0x147734
00104980  ldr      w8, [x19]
00104984  cbnz     w8, #0x100318
00104988  mov      w21, w0
0010498c  ldr      x1, [x20]
00104990  mov      x0, x19
00104994  bl       #0x147734
00104998  ldr      w8, [x19]
0010499c  cbnz     w8, #0x100318
001049a0  cmp      w21, w0
001049a4  ldr      x1, [x20]
001049a8  cset     w2, eq
001049ac  mov      x0, x19
001049b0  bl       #0x147630
001049b4  ldr      w8, [x19]
001049b8  cbnz     w8, #0x100318
001049bc  ldr      x1, [x20]
001049c0  mov      x0, x19
001049c4  bl       #0x147734
001049c8  ldr      w8, [x19]
001049cc  cbnz     w8, #0x100318
001049d0  mov      w21, w0
001049d4  ldr      x1, [x20]
001049d8  mov      x0, x19
001049dc  bl       #0x147734
001049e0  ldr      w8, [x19]
001049e4  cbz      w21, #0x104a44
001049e8  ldp      x24, x25, [sp, #8]
001049ec  cbnz     w8, #0x100318
001049f0  ldr      x1, [x20]
001049f4  mov      x0, x19
001049f8  bl       #0x147734
001049fc  ldr      w8, [x19]
00104a00  cbnz     w8, #0x100318
00104a04  ldr      x1, [x20]
00104a08  mov      x0, x19
00104a0c  bl       #0x147734
00104a10  ldr      w8, [x19]
00104a14  cbnz     w8, #0x100318
00104a18  ldr      x8, [sp, #0x18]
00104a1c  ldr      x0, [x8]
00104a20  bl       #0x146474
00104a24  tbnz     w0, #0, #0x100318
00104a28  ldr      x8, [sp, #0x18]
00104a2c  mov      x0, x19
00104a30  ldr      x1, [x8]
00104a34  bl       #0x146478
00104a38  ldr      w8, [x19]
00104a3c  cbz      w8, #0x100580
00104a40  b        #0x100318
00104a44  ldp      x24, x25, [sp, #8]
00104a48  cbnz     w8, #0x100318
00104a4c  ldr      x8, [sp]
00104a50  mov      w2, w0
00104a54  mov      x0, x19
00104a58  ldr      x1, [x8]
00104a5c  bl       #0x146558
00104a60  ldr      w8, [x19]
00104a64  cbnz     w8, #0x100318
00104a68  ldr      x1, [x20]
00104a6c  mov      x0, x19
00104a70  mov      w2, wzr
00104a74  bl       #0x14784c
00104a78  ldr      w8, [x19]
00104a7c  cbnz     w8, #0x100318
00104a80  ldr      x1, [x20]
00104a84  mov      x0, x19
00104a88  mov      w2, #3
00104a8c  bl       #0x147630
00104a90  ldr      w8, [x19]
00104a94  cbnz     w8, #0x100318
00104a98  ldr      x1, [x20]
00104a9c  mov      x0, x19
00104aa0  bl       #0x147734
00104aa4  ldr      w8, [x19]
00104aa8  cbnz     w8, #0x100318
00104aac  mov      w21, w0
00104ab0  ldr      x1, [x20]
00104ab4  mov      x0, x19
00104ab8  bl       #0x147734
00104abc  ldr      w8, [x19]
00104ac0  cbnz     w8, #0x100318
00104ac4  ldr      x1, [x20]
00104ac8  sub      w2, w21, w0
00104acc  mov      x0, x19
00104ad0  bl       #0x147630
00104ad4  ldr      w8, [x19]
00104ad8  cbnz     w8, #0x100318
00104adc  ldr      x1, [x20]
00104ae0  mov      x0, x19
00104ae4  mov      w2, #8
00104ae8  bl       #0x147630
00104aec  ldr      w8, [x19]
00104af0  cbnz     w8, #0x100318
00104af4  ldr      x1, [x20]
00104af8  mov      x0, x19
00104afc  bl       #0x147734
00104b00  ldr      w8, [x19]
00104b04  cbnz     w8, #0x100318
00104b08  mov      w21, w0
00104b0c  ldr      x1, [x20]
00104b10  mov      x0, x19
00104b14  bl       #0x147734
00104b18  ldr      w8, [x19]
00104b1c  cbnz     w8, #0x100318
00104b20  mul      w2, w0, w21
00104b24  ldr      x1, [x20]
00104b28  mov      x0, x19
00104b2c  bl       #0x147630
00104b30  ldr      w8, [x19]
00104b34  cbnz     w8, #0x100318
00104b38  ldr      x1, [x20]
00104b3c  mov      x0, x19
00104b40  bl       #0x147a18
00104b44  ldr      w8, [x19]
00104b48  cbnz     w8, #0x100318
00104b4c  ldr      x1, [x20]
00104b50  mov      x0, x19
00104b54  mov      w2, #0xff
00104b58  bl       #0x147630
00104b5c  ldr      w8, [x19]
00104b60  cbnz     w8, #0x100318
00104b64  ldr      x1, [x20]
00104b68  mov      x0, x19
00104b6c  bl       #0x147734
00104b70  ldr      w8, [x19]
00104b74  cbnz     w8, #0x100318
00104b78  mov      w21, w0
00104b7c  ldr      x1, [x20]
00104b80  mov      x0, x19
00104b84  bl       #0x147734
00104b88  ldr      w8, [x19]
00104b8c  cbnz     w8, #0x100318
00104b90  ldr      x1, [x20]
00104b94  lsl      w2, w21, w0
00104b98  mov      x0, x19
00104b9c  bl       #0x147630
00104ba0  ldr      w8, [x19]
00104ba4  cbnz     w8, #0x100318
00104ba8  ldr      x1, [x20]
00104bac  mov      x0, x19
00104bb0  mov      w2, #3
00104bb4  bl       #0x14784c
00104bb8  ldr      w8, [x19]
00104bbc  cbnz     w8, #0x100318
00104bc0  ldr      x1, [x20]
00104bc4  mov      x0, x19
00104bc8  bl       #0x147734
00104bcc  ldr      w8, [x19]
00104bd0  cbnz     w8, #0x100318
00104bd4  mov      w1, w0
00104bd8  ldp      x21, x0, [x20]
00104bdc  bl       #0x147304
00104be0  mov      w2, w0
00104be4  mov      x0, x19
00104be8  mov      x1, x21
00104bec  bl       #0x147630
00104bf0  ldr      w8, [x19]
00104bf4  cbnz     w8, #0x100318
00104bf8  ldr      x1, [x20]
00104bfc  mov      x0, x19
00104c00  bl       #0x147734
00104c04  ldr      w8, [x19]
00104c08  cbnz     w8, #0x100318
00104c0c  mov      w21, w0
00104c10  ldr      x1, [x20]
00104c14  mov      x0, x19
00104c18  bl       #0x147734
00104c1c  ldr      w8, [x19]
00104c20  cbnz     w8, #0x100318
00104c24  ldr      x1, [x20]
00104c28  and      w2, w0, w21
00104c2c  mov      x0, x19
00104c30  bl       #0x147630
00104c34  ldr      w8, [x19]
00104c38  cbnz     w8, #0x100318
00104c3c  ldr      x1, [x20]
00104c40  mov      x0, x19
00104c44  bl       #0x147734
00104c48  ldr      w8, [x19]
00104c4c  cbnz     w8, #0x100318
00104c50  mov      w21, w0
00104c54  ldr      x1, [x20]
00104c58  mov      x0, x19
00104c5c  bl       #0x147734
00104c60  ldr      w8, [x19]
00104c64  cbnz     w8, #0x100318
00104c68  ldr      x1, [x20]
00104c6c  lsr      w2, w21, w0
00104c70  mov      x0, x19
00104c74  bl       #0x147630
00104c78  ldr      w8, [x19]
00104c7c  cbnz     w8, #0x100318
00104c80  ldr      x1, [x20]
00104c84  mov      x0, x19
00104c88  mov      w2, #3
00104c8c  bl       #0x14784c
00104c90  ldr      w8, [x19]
00104c94  cbnz     w8, #0x100318
00104c98  ldr      x1, [x20]
00104c9c  mov      x0, x19
00104ca0  mov      w2, #3
00104ca4  bl       #0x147630
00104ca8  ldr      w8, [x19]
00104cac  cbnz     w8, #0x100318
00104cb0  ldr      x1, [x20]
00104cb4  mov      x0, x19
00104cb8  bl       #0x147734
00104cbc  ldr      w8, [x19]
00104cc0  cbnz     w8, #0x100318
00104cc4  mov      w21, w0
00104cc8  ldr      x1, [x20]
00104ccc  mov      x0, x19
00104cd0  bl       #0x147734
00104cd4  ldr      w8, [x19]
00104cd8  cbnz     w8, #0x100318
00104cdc  ldr      x1, [x20]
00104ce0  sub      w2, w21, w0
00104ce4  mov      x0, x19
00104ce8  bl       #0x147630
00104cec  ldr      w8, [x19]
00104cf0  cbnz     w8, #0x100318
00104cf4  ldr      x1, [x20]
00104cf8  mov      x0, x19
00104cfc  mov      w2, #8
00104d00  bl       #0x147630
00104d04  ldr      w8, [x19]
00104d08  cbnz     w8, #0x100318
00104d0c  ldr      x1, [x20]
00104d10  mov      x0, x19
00104d14  bl       #0x147734
00104d18  ldr      w8, [x19]
00104d1c  cbnz     w8, #0x100318
00104d20  mov      w21, w0
00104d24  ldr      x1, [x20]
00104d28  mov      x0, x19
00104d2c  bl       #0x147734
00104d30  ldr      w8, [x19]
00104d34  cbnz     w8, #0x100318
00104d38  mul      w2, w0, w21
00104d3c  ldr      x1, [x20]
00104d40  mov      x0, x19
00104d44  bl       #0x147630
00104d48  ldr      w8, [x19]
00104d4c  cbnz     w8, #0x100318
00104d50  ldr      x1, [x20]
00104d54  mov      x0, x19
00104d58  bl       #0x147a18
00104d5c  ldr      w8, [x19]
00104d60  cbnz     w8, #0x100318
00104d64  ldr      x1, [x20]
00104d68  mov      x0, x19
00104d6c  mov      w2, #2
00104d70  bl       #0x147a20
00104d74  ldr      w8, [x19]
00104d78  cbnz     w8, #0x100318
00104d7c  ldr      x1, [x20]
00104d80  mov      x0, x19
00104d84  bl       #0x147734
00104d88  ldr      w8, [x19]
00104d8c  cbnz     w8, #0x100318
00104d90  mov      w21, w0
00104d94  ldr      x1, [x20]
00104d98  mov      x0, x19
00104d9c  bl       #0x147734
00104da0  ldr      w8, [x19]
00104da4  cbnz     w8, #0x100318
00104da8  ldr      x1, [x20]
00104dac  lsl      w2, w21, w0
00104db0  mov      x0, x19
00104db4  bl       #0x147630
00104db8  ldr      w8, [x19]
00104dbc  cbnz     w8, #0x100318
00104dc0  ldr      x1, [x20]
00104dc4  mov      x0, x19
00104dc8  mov      w2, #1
00104dcc  bl       #0x147a20
00104dd0  ldr      w8, [x19]
00104dd4  cbnz     w8, #0x100318
00104dd8  ldr      x1, [x20]
00104ddc  mov      x0, x19
00104de0  mov      w2, #0xff
00104de4  bl       #0x147630
00104de8  ldr      w8, [x19]
00104dec  cbnz     w8, #0x100318
00104df0  ldr      x1, [x20]
00104df4  mov      x0, x19
00104df8  bl       #0x147734
00104dfc  ldr      w8, [x19]
00104e00  cbnz     w8, #0x100318
00104e04  mov      w21, w0
00104e08  ldr      x1, [x20]
00104e0c  mov      x0, x19
00104e10  bl       #0x147734
00104e14  ldr      w8, [x19]
00104e18  cbnz     w8, #0x100318
00104e1c  ldr      x1, [x20]
00104e20  lsl      w2, w21, w0
00104e24  mov      x0, x19
00104e28  bl       #0x147630
00104e2c  ldr      w8, [x19]
00104e30  cbnz     w8, #0x100318
00104e34  ldr      x1, [x20]
00104e38  mov      x0, x19
00104e3c  bl       #0x147734
00104e40  ldr      w8, [x19]
00104e44  cbnz     w8, #0x100318
00104e48  ldr      x1, [x20]
00104e4c  mvn      w2, w0
00104e50  mov      x0, x19
00104e54  bl       #0x147630
00104e58  ldr      w8, [x19]
00104e5c  cbnz     w8, #0x100318
00104e60  ldr      x1, [x20]
00104e64  mov      x0, x19
00104e68  mov      w2, #5
00104e6c  bl       #0x14784c
00104e70  ldr      w8, [x19]
00104e74  cbnz     w8, #0x100318
00104e78  ldr      x1, [x20]
00104e7c  mov      x0, x19
00104e80  bl       #0x147734
00104e84  ldr      w8, [x19]
00104e88  cbnz     w8, #0x100318
00104e8c  mov      w1, w0
00104e90  ldp      x21, x0, [x20]
00104e94  bl       #0x147304
00104e98  mov      w2, w0
00104e9c  mov      x0, x19
00104ea0  mov      x1, x21
00104ea4  bl       #0x147630
00104ea8  ldr      w8, [x19]
00104eac  cbnz     w8, #0x100318
00104eb0  ldr      x1, [x20]
00104eb4  mov      x0, x19
00104eb8  bl       #0x147734
00104ebc  ldr      w8, [x19]
00104ec0  cbnz     w8, #0x100318
00104ec4  mov      w21, w0
00104ec8  ldr      x1, [x20]
00104ecc  mov      x0, x19
00104ed0  bl       #0x147734
00104ed4  ldr      w8, [x19]
00104ed8  cbnz     w8, #0x100318
00104edc  ldr      x1, [x20]
00104ee0  and      w2, w0, w21
00104ee4  mov      x0, x19
00104ee8  bl       #0x147630
00104eec  ldr      w8, [x19]
00104ef0  cbnz     w8, #0x100318
00104ef4  ldr      x1, [x20]
00104ef8  mov      x0, x19
00104efc  bl       #0x147734
00104f00  ldr      w8, [x19]
00104f04  cbnz     w8, #0x100318
00104f08  mov      w21, w0
00104f0c  ldr      x1, [x20]
00104f10  mov      x0, x19
00104f14  bl       #0x147734
00104f18  ldr      w8, [x19]
00104f1c  cbnz     w8, #0x100318
00104f20  ldr      x1, [x20]
00104f24  orr      w2, w0, w21
00104f28  mov      x0, x19
00104f2c  bl       #0x147630
00104f30  ldr      w8, [x19]
00104f34  cbnz     w8, #0x100318
00104f38  ldr      x1, [x20]
00104f3c  mov      x0, x19
00104f40  mov      w2, #4
00104f44  bl       #0x14784c
00104f48  ldr      w8, [x19]
00104f4c  cbnz     w8, #0x100318
00104f50  ldr      x1, [x20]
00104f54  mov      x0, x19
00104f58  bl       #0x147734
00104f5c  ldr      w8, [x19]
00104f60  cbnz     w8, #0x100318
00104f64  mov      w21, w0
00104f68  ldr      x1, [x20]
00104f6c  mov      x0, x19
00104f70  bl       #0x147734
00104f74  ldr      w8, [x19]
00104f78  cbnz     w8, #0x100318
00104f7c  mov      w3, w0
00104f80  ldr      x1, [x26]
00104f84  mov      x0, x19
00104f88  mov      w2, w21
00104f8c  bl       #0x146ed8
00104f90  ldr      w8, [x19]
00104f94  cbnz     w8, #0x100318
00104f98  ldr      x1, [x20]
00104f9c  mov      x0, x19
00104fa0  bl       #0x147734
00104fa4  ldr      w8, [x19]
00104fa8  cbnz     w8, #0x100318
00104fac  ldr      x1, [x20]
00104fb0  add      w2, w0, #1
00104fb4  mov      x0, x19
00104fb8  bl       #0x147630
00104fbc  ldr      w8, [x19]
00104fc0  cbnz     w8, #0x100318
00104fc4  ldr      x1, [x20]
00104fc8  mov      x0, x19
00104fcc  bl       #0x147a18
00104fd0  ldr      w8, [x19]
00104fd4  cbnz     w8, #0x100318
00104fd8  ldr      x1, [x20]
00104fdc  mov      x0, x19
00104fe0  mov      w2, #4
00104fe4  bl       #0x147630
00104fe8  ldr      w8, [x19]
00104fec  cbnz     w8, #0x100318
00104ff0  ldr      x1, [x20]
00104ff4  mov      x0, x19
00104ff8  bl       #0x147734
00104ffc  ldr      w8, [x19]
