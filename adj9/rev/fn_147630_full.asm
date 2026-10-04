FDE function: 0x1452d0 .. 0x149630 size 0x4360
0x1452d0  mov      x10, x25
0x1452d4  mov      w11, w28
0x1452d8  mov      x12, x23
0x1452dc  csel     x15, x14, x13, ne
0x1452e0  b        #0x14543c
0x1452e4  sub      x8, x20, #1
0x1452e8  mov      x9, #0x6436
0x1452ec  movk     x9, #0x2869, lsl #16
0x1452f0  cmp      w28, #0
0x1452f4  movk     x9, #0xc5df, lsl #32
0x1452f8  mov      x10, x25
0x1452fc  stur     x8, [x29, #-0x80]
0x145300  ldrb     w8, [x25]
0x145304  movk     x9, #0x56de, lsl #48
0x145308  mov      w11, w28
0x14530c  mov      x12, x23
0x145310  mov      x13, x21
0x145314  stur     w8, [x29, #-0x4c]
0x145318  mov      x8, #0x25ce
0x14531c  movk     x8, #0x8c3e, lsl #16
0x145320  str      w28, [sp, #0x94]
0x145324  movk     x8, #0xdec2, lsl #32
0x145328  stp      x25, x27, [sp, #0x30]
0x14532c  movk     x8, #0xf201, lsl #48
0x145330  stur     w28, [x29, #-0x8c]
0x145334  csel     x15, x8, x9, eq
0x145338  mov      x8, x20
0x14533c  mov      x9, x27
0x145340  mov      x16, x24
0x145344  b        #0x144498
0x145348  ldur     x8, [x29, #-0x80]
0x14534c  mov      x13, #0xb031
0x145350  mov      x14, #0x4c0d
0x145354  movk     x13, #0x9cc1, lsl #16
0x145358  movk     x14, #0x52dd, lsl #16
0x14535c  movk     x13, #0xffeb, lsl #32
0x145360  cmp      x8, #0
0x145364  ldur     w8, [x29, #-0x4c]
0x145368  movk     x14, #0x7dcf, lsl #32
0x14536c  movk     x13, #0x2516, lsl #48
0x145370  movk     x14, #0x48fe, lsl #48
0x145374  mov      x9, x27
0x145378  ccmp     w8, #0, #4, ne
0x14537c  mov      x8, x20
0x145380  mov      x10, x25
0x145384  mov      w11, w28
0x145388  mov      x12, x23
0x14538c  csel     x15, x13, x14, ne
0x145390  b        #0x14543c
0x145394  ldur     x8, [x29, #-0x60]
0x145398  add      x8, x8, #1
0x14539c  stur     x8, [x29, #-0x88]
0x1453a0  mov      x15, #0x9bd
0x1453a4  mov      x8, x20
0x1453a8  movk     x15, #0xb5f6, lsl #16
0x1453ac  mov      x9, x27
0x1453b0  movk     x15, #0xce8f, lsl #32
0x1453b4  mov      x10, x25
0x1453b8  mov      w11, w28
0x1453bc  mov      x12, x23
0x1453c0  mov      x13, x21
0x1453c4  mov      x16, x24
0x1453c8  movk     x15, #0x62d5, lsl #48
0x1453cc  b        #0x144498
0x1453d0  ldur     w12, [x29, #-0x8c]
0x1453d4  ldur     w11, [x29, #-0x4c]
0x1453d8  sub      w8, w12, #0x5b
0x1453dc  orr      w9, w12, #0x20
0x1453e0  sub      w10, w11, #0x5b
0x1453e4  cmn      w8, #0x1a
0x1453e8  csel     w9, w12, w9, lo
0x1453ec  cmn      w10, #0x1a
0x1453f0  ldur     x10, [x29, #-0x30]
0x1453f4  orr      w8, w11, #0x20
0x1453f8  csel     w8, w11, w8, lo
0x1453fc  cmp      w9, w8
0x145400  mov      x9, #0xea12
0x145404  add      x0, x10, #1
0x145408  mov      x10, #0xcd53
0x14540c  movk     x9, #0x2ac8, lsl #16
0x145410  movk     x10, #0xade6, lsl #16
0x145414  movk     x9, #0x1d60, lsl #32
0x145418  movk     x10, #0xefff, lsl #32
0x14541c  movk     x9, #0x1023, lsl #48
0x145420  movk     x10, #0x13d4, lsl #48
0x145424  mov      x8, x20
0x145428  csel     x15, x10, x9, eq
0x14542c  mov      x9, x27
0x145430  mov      x10, x25
0x145434  mov      w11, w28
0x145438  mov      x12, x23
0x14543c  mov      x13, x21
0x145440  mov      x16, x24
0x145444  b        #0x144498
0x145448  mov      x22, x24
0x14544c  mov      x13, #0xa74a
0x145450  mov      x14, #0xd2d1
0x145454  movk     x13, #0x5ea3, lsl #16
0x145458  movk     x14, #0xf825, lsl #16
0x14545c  movk     x13, #0xa04f, lsl #32
0x145460  ldrb     w12, [x22], #1
0x145464  movk     x14, #0xee0c, lsl #32
0x145468  movk     x13, #0xfa1e, lsl #48
0x14546c  movk     x14, #0x5c23, lsl #48
0x145470  mov      x8, x20
0x145474  cmp      w12, #0
0x145478  mov      x9, x27
0x14547c  mov      x10, x25
0x145480  str      x24, [sp, #0x78]
0x145484  mov      w11, w28
0x145488  mov      x12, x23
0x14548c  csel     x15, x14, x13, eq
0x145490  b        #0x14543c
0x145494  ldp      x2, x3, [sp, #0x10]
0x145498  mov      x26, x0
0x14549c  ldur     x0, [x29, #-0x20]
0x1454a0  ldur     w1, [x29, #-0x18]
0x1454a4  bl       #0x145d84   ; -> None
0x1454a8  mov      x11, #0x113f
0x1454ac  mov      x12, #0xee15
0x1454b0  mov      x17, #0xb7cc
0x1454b4  mov      x30, #0xd05b
0x1454b8  mov      x6, #0x1859
0x1454bc  mov      x5, #0xc2a2
0x1454c0  mov      x4, #0x8d87
0x1454c4  mov      x3, #0x865
0x1454c8  mov      x2, #0xc335
0x1454cc  mov      x19, #0xe386
0x1454d0  mov      x1, #0x507b
0x1454d4  movk     x11, #0xceaf, lsl #16
0x1454d8  movk     x12, #0x1fe1, lsl #16
0x1454dc  movk     x17, #0xff64, lsl #16
0x1454e0  movk     x30, #0xef20, lsl #16
0x1454e4  movk     x6, #0x2b53, lsl #16
0x1454e8  movk     x5, #0x1048, lsl #16
0x1454ec  movk     x4, #0xa2f3, lsl #16
0x1454f0  movk     x3, #0x5362, lsl #16
0x1454f4  movk     x2, #0x1484, lsl #16
0x1454f8  movk     x19, #0xeab8, lsl #16
0x1454fc  movk     x1, #0x2c50, lsl #16
0x145500  movk     x11, #0x4fe6, lsl #32
0x145504  movk     x12, #0x5376, lsl #32
0x145508  movk     x17, #0xf23e, lsl #32
0x14550c  movk     x30, #0x96cc, lsl #32
0x145510  movk     x6, #0x6ffc, lsl #32
0x145514  movk     x5, #0x7104, lsl #32
0x145518  movk     x4, #0x8648, lsl #32
0x14551c  movk     x3, #0x98ea, lsl #32
0x145520  movk     x2, #0x16b3, lsl #32
0x145524  movk     x19, #0xc1ec, lsl #32
0x145528  movk     x1, #0x48ac, lsl #32
0x14552c  cmp      x0, #0
0x145530  movk     x11, #0xe9ff, lsl #48
0x145534  movk     x12, #0x6aa9, lsl #48
0x145538  movk     x17, #0x8f3d, lsl #48
0x14553c  movk     x30, #0x8753, lsl #48
0x145540  movk     x6, #0x930b, lsl #48
0x145544  movk     x5, #0x9ffe, lsl #48
0x145548  movk     x4, #0xa5e3, lsl #48
0x14554c  movk     x3, #0xabfd, lsl #48
0x145550  movk     x2, #0xb3cc, lsl #48
0x145554  movk     x19, #0x808f, lsl #48
0x145558  movk     x1, #0xc90b, lsl #48
0x14555c  mov      x8, x20
0x145560  mov      x9, x27
0x145564  str      x0, [sp, #0x60]
0x145568  mov      x0, x26
0x14556c  mov      x10, x25
0x145570  csel     x15, x12, x11, eq
0x145574  b        #0x145434
0x145578  ldur     x8, [x29, #-0x28]
0x14557c  mov      x15, #0x1859
0x145580  ldr      x9, [sp, #0x40]
0x145584  movk     x15, #0x2b53, lsl #16
0x145588  ldur     x12, [x29, #-0x48]
0x14558c  movk     x15, #0x6ffc, lsl #32
0x145590  mov      w11, w28
0x145594  mov      x13, x21
0x145598  subs     x8, x9, x8
0x14559c  mov      x9, x27
0x1455a0  cset     w10, eq
0x1455a4  mov      x16, x24
0x1455a8  movk     x15, #0x930b, lsl #48
0x1455ac  stur     x8, [x29, #-0x40]
0x1455b0  mov      x8, x20
0x1455b4  str      w10, [sp, #0x6c]
0x1455b8  mov      x10, x25
0x1455bc  b        #0x144498
0x1455c0  ldr      x8, [sp, #0x80]
0x1455c4  mov      x15, #0x507b
0x1455c8  ldur     x9, [x29, #-0x60]
0x1455cc  movk     x15, #0x2c50, lsl #16
0x1455d0  movk     x15, #0x48ac, lsl #32
0x1455d4  mov      x10, x25
0x1455d8  ldr      x8, [x8]
0x1455dc  mov      w11, w28
0x1455e0  mov      x12, x23
0x1455e4  mov      x16, x24
0x1455e8  ldr      x13, [x8, x9, lsl #3]
0x1455ec  mov      x8, x20
0x1455f0  mov      x9, x27
0x1455f4  movk     x15, #0xc90b, lsl #48
0x1455f8  stur     x13, [x29, #-0x28]
0x1455fc  b        #0x144498
0x145600  ldur     x0, [x29, #-0x68]
0x145604  bl       #0x148a00   ; -> free
0x145608  ldur     x0, [x29, #-0x58]
0x14560c  bl       #0x148a00   ; -> free
0x145610  ldr      x8, [sp]
0x145614  ldr      x8, [x8, #0x28]
0x145618  ldur     x9, [x29, #-0x10]
0x14561c  cmp      x8, x9
0x145620  b.ne     #0x14564c
0x145624  ldur     w8, [x29, #-0x50]
0x145628  ldp      x20, x19, [sp, #0x1a0]
0x14562c  ldp      x22, x21, [sp, #0x190]
0x145630  and      w0, w8, #1
0x145634  ldp      x24, x23, [sp, #0x180]
0x145638  ldp      x26, x25, [sp, #0x170]
0x14563c  ldp      x28, x27, [sp, #0x160]
0x145640  ldp      x29, x30, [sp, #0x150]
0x145644  add      sp, sp, #0x1b0
0x145648  ret      
0x14564c  bl       #0x148a10   ; -> __stack_chk_fail
0x145650  sub      sp, sp, #0x100
0x145654  stp      x29, x30, [sp, #0xa0]
0x145658  stp      x28, x27, [sp, #0xb0]
0x14565c  stp      x26, x25, [sp, #0xc0]
0x145660  stp      x24, x23, [sp, #0xd0]
0x145664  stp      x22, x21, [sp, #0xe0]
0x145668  stp      x20, x19, [sp, #0xf0]
0x14566c  add      x29, sp, #0xa0
0x145670  str      x2, [sp]
0x145674  mov      x23, #0xe4da
0x145678  stur     x1, [x29, #-0x48]
0x14567c  mov      x12, #0xb0b0
0x145680  stp      xzr, x0, [sp, #0x48]
0x145684  mov      x13, #0x2214
0x145688  mov      x15, #0xe11a
0x14568c  mov      x17, #0x692
0x145690  mov      x0, #0xafca
0x145694  mov      x20, #0x8f9b
0x145698  mov      x1, #0xdfbb
0x14569c  mov      x2, #0xc6bd
0x1456a0  mov      x27, #0x540b
0x1456a4  mov      x28, #0x259
0x1456a8  mov      x26, #0x4905
0x1456ac  mov      x4, #0x1c0f
0x1456b0  mov      x5, #0x30e
0x1456b4  mov      x6, #0x64c6
0x1456b8  mov      x7, #0x933c
0x1456bc  mov      x30, #0x208d
0x1456c0  mov      x16, #0xe6b2
0x1456c4  mov      x11, #0x692
0x1456c8  movk     x23, #0x60f6, lsl #16
0x1456cc  movk     x12, #0x4891, lsl #16
0x1456d0  movk     x13, #0x6e6c, lsl #16
0x1456d4  movk     x15, #0xe707, lsl #16
0x1456d8  movk     x17, #0x8807, lsl #16
0x1456dc  movk     x0, #0x7c1a, lsl #16
0x1456e0  movk     x20, #0xc267, lsl #16
0x1456e4  movk     x1, #0xfd40, lsl #16
0x1456e8  movk     x2, #0xda71, lsl #16
0x1456ec  movk     x27, #0x5e6a, lsl #16
0x1456f0  movk     x28, #0x6e2a, lsl #16
0x1456f4  movk     x26, #0x4d4c, lsl #16
0x1456f8  movk     x4, #0x6b47, lsl #16
0x1456fc  movk     x5, #0x1b5, lsl #16
0x145700  movk     x6, #0xb4df, lsl #16
0x145704  movk     x7, #0x4138, lsl #16
0x145708  movk     x30, #0x44b3, lsl #16
0x14570c  movk     x16, #0xa01a, lsl #16
0x145710  movk     x11, #0x8807, lsl #16
0x145714  movk     x23, #0xb0ba, lsl #32
0x145718  movk     x12, #0xd7d8, lsl #32
0x14571c  movk     x13, #0x2705, lsl #32
0x145720  movk     x15, #0x5296, lsl #32
0x145724  movk     x17, #0xfbe3, lsl #32
0x145728  movk     x0, #0x1e39, lsl #32
0x14572c  movk     x20, #0xf353, lsl #32
0x145730  movk     x1, #0xeac0, lsl #32
0x145734  movk     x2, #0x6422, lsl #32
0x145738  movk     x27, #0x5fdc, lsl #32
0x14573c  movk     x28, #0xc6cb, lsl #32
0x145740  movk     x26, #0xa445, lsl #32
0x145744  movk     x4, #0x4b03, lsl #32
0x145748  movk     x5, #0x9ee9, lsl #32
0x14574c  movk     x6, #0xca87, lsl #32
0x145750  movk     x7, #0xbb88, lsl #32
0x145754  movk     x30, #0xb99f, lsl #32
0x145758  movk     x16, #0x11ba, lsl #32
0x14575c  movk     x11, #0xfbe3, lsl #32
0x145760  mov      x14, xzr
0x145764  movk     x23, #0x8940, lsl #48
0x145768  movk     x12, #0x3df5, lsl #48
0x14576c  movk     x13, #0x2e9a, lsl #48
0x145770  movk     x15, #0x1df3, lsl #48
0x145774  movk     x17, #0xa1b3, lsl #48
0x145778  movk     x0, #0x6f3, lsl #48
0x14577c  movk     x20, #0x853c, lsl #48
0x145780  movk     x1, #0x1ca0, lsl #48
0x145784  movk     x2, #0x3b0d, lsl #48
0x145788  movk     x27, #0x9974, lsl #48
0x14578c  movk     x28, #0x176e, lsl #48
0x145790  movk     x26, #0x9d91, lsl #48
0x145794  movk     x4, #0xc1bd, lsl #48
0x145798  movk     x5, #0xcf73, lsl #48
0x14579c  movk     x6, #0x162c, lsl #48
0x1457a0  movk     x7, #0x5c22, lsl #48
0x1457a4  movk     x30, #0x3ef2, lsl #48
0x1457a8  movk     x16, #0x26d0, lsl #48
0x1457ac  movk     x11, #0xa1b3, lsl #48
0x1457b0  mov      x9, x11
0x1457b4  mov      x11, #0xf23e
0x1457b8  movk     x11, #0xeb9c, lsl #16
0x1457bc  cmp      x9, x20
0x1457c0  movk     x11, #0x667e, lsl #32
0x1457c4  movk     x11, #0x7c8, lsl #48
0x1457c8  b.eq     #0x1457b0
0x1457cc  mov      x19, x10
0x1457d0  mov      x25, x8
0x1457d4  cmp      x9, x23
0x1457d8  b.eq     #0x145944
0x1457dc  cmp      x9, x27
0x1457e0  b.eq     #0x145964
0x1457e4  cmp      x9, x26
0x1457e8  b.eq     #0x145a74
0x1457ec  mov      x11, #0xe11a
0x1457f0  mov      x8, x25
0x1457f4  movk     x11, #0xe707, lsl #16
0x1457f8  mov      x10, x19
0x1457fc  movk     x11, #0x5296, lsl #32
0x145800  cmp      x9, x17
0x145804  movk     x11, #0x1df3, lsl #48
0x145808  b.eq     #0x1457b0
0x14580c  mov      x11, #0xb0b0
0x145810  mov      x8, x25
0x145814  movk     x11, #0x4891, lsl #16
0x145818  mov      x10, x21
0x14581c  movk     x11, #0xd7d8, lsl #32
0x145820  cmp      x9, x4
0x145824  movk     x11, #0x3df5, lsl #48
0x145828  b.eq     #0x1457b0
0x14582c  mov      x11, #0xe4da
0x145830  mov      x8, x22
0x145834  movk     x11, #0x60f6, lsl #16
0x145838  mov      x10, x19
0x14583c  movk     x11, #0xb0ba, lsl #32
0x145840  cmp      x9, x5
0x145844  movk     x11, #0x8940, lsl #48
0x145848  b.eq     #0x1457b0
0x14584c  cmp      x9, x0
0x145850  b.eq     #0x145a94
0x145854  cmp      x9, x6
0x145858  b.eq     #0x145abc
0x14585c  cmp      x9, x28
0x145860  b.eq     #0x145adc
0x145864  mov      x8, x24
0x145868  mov      x10, x19
0x14586c  cmp      x9, x1
0x145870  b.eq     #0x1457b0
0x145874  cmp      x9, x15
0x145878  b.eq     #0x145ae8
0x14587c  cmp      x9, x16
0x145880  b.eq     #0x145b04
0x145884  cmp      x9, x13
0x145888  b.eq     #0x145b30
0x14588c  mov      x8, #0x4fa1
0x145890  movk     x8, #0x3fc2, lsl #16
0x145894  movk     x8, #0x4b99, lsl #32
0x145898  movk     x8, #0x365c, lsl #48
0x14589c  cmp      x9, x8
0x1458a0  b.eq     #0x145b58
0x1458a4  cmp      x9, x2
0x1458a8  b.eq     #0x145b8c
0x1458ac  cmp      x9, x12
0x1458b0  b.eq     #0x145bc4
0x1458b4  cmp      x9, x30
0x1458b8  b.eq     #0x145bf4
0x1458bc  cmp      x9, x7
0x1458c0  b.eq     #0x145d14
0x1458c4  mov      x11, #0xf23e
0x1458c8  mov      x3, #0x4bb4
0x1458cc  movk     x11, #0xeb9c, lsl #16
0x1458d0  movk     x3, #0x877, lsl #16
0x1458d4  movk     x11, #0x667e, lsl #32
0x1458d8  mov      x8, x25
0x1458dc  mov      x10, x19
0x1458e0  movk     x11, #0x7c8, lsl #48
0x1458e4  movk     x3, #0x5974, lsl #32
0x1458e8  movk     x3, #0x5eff, lsl #48
0x1458ec  cmp      x9, x3
0x1458f0  b.eq     #0x1457b0
0x1458f4  mov      x8, #0xd62d
0x1458f8  movk     x8, #0xa717, lsl #16
0x1458fc  movk     x8, #0xd684, lsl #32
0x145900  movk     x8, #0x75ea, lsl #48
0x145904  cmp      x9, x8
0x145908  b.eq     #0x145d3c
0x14590c  mov      x16, #0xf23e
0x145910  mov      x8, x25
0x145914  movk     x16, #0xeb9c, lsl #16
0x145918  mov      x10, x19
0x14591c  movk     x16, #0x667e, lsl #32
0x145920  mov      x11, x9
0x145924  movk     x16, #0x7c8, lsl #48
0x145928  cmp      x9, x16
0x14592c  mov      x16, #0xe6b2
0x145930  movk     x16, #0xa01a, lsl #16
0x145934  movk     x16, #0x11ba, lsl #32
0x145938  movk     x16, #0x26d0, lsl #48
0x14593c  b.ne     #0x1457b0
0x145940  b        #0x145d60
0x145944  mov      x24, x25
0x145948  str      x25, [sp, #0x18]
0x14594c  mov      x10, x19
0x145950  ldrb     w8, [x24], #1
0x145954  cmp      w8, #0
0x145958  mov      x8, x25
0x14595c  csel     x11, x2, x1, eq
0x145960  b        #0x1457b0
0x145964  ldur     x8, [x29, #-8]
0x145968  mov      w1, #1
0x14596c  mov      x22, x14
0x145970  add      x0, x8, #1
0x145974  bl       #0x148b90   ; -> calloc
0x145978  mov      x28, #0x259
0x14597c  mov      x16, #0xe6b2
0x145980  mov      x30, #0x208d
0x145984  mov      x7, #0x933c
0x145988  mov      x6, #0x64c6
0x14598c  mov      x5, #0x30e
0x145990  mov      x4, #0x1c0f
0x145994  movk     x28, #0x6e2a, lsl #16
0x145998  mov      x2, #0xc6bd
0x14599c  mov      x1, #0xdfbb
0x1459a0  mov      x17, #0x692
0x1459a4  mov      x15, #0xe11a
0x1459a8  mov      x14, x22
0x1459ac  mov      x13, #0x2214
0x1459b0  mov      x12, #0xb0b0
0x1459b4  mov      x22, x0
0x1459b8  mov      x0, #0xafca
0x1459bc  movk     x16, #0xa01a, lsl #16
0x1459c0  movk     x30, #0x44b3, lsl #16
0x1459c4  movk     x7, #0x4138, lsl #16
0x1459c8  movk     x6, #0xb4df, lsl #16
0x1459cc  movk     x5, #0x1b5, lsl #16
0x1459d0  movk     x4, #0x6b47, lsl #16
0x1459d4  movk     x28, #0xc6cb, lsl #32
0x1459d8  movk     x2, #0xda71, lsl #16
0x1459dc  movk     x1, #0xfd40, lsl #16
0x1459e0  movk     x17, #0x8807, lsl #16
0x1459e4  movk     x15, #0xe707, lsl #16
0x1459e8  movk     x13, #0x6e6c, lsl #16
0x1459ec  movk     x12, #0x4891, lsl #16
0x1459f0  movk     x0, #0x7c1a, lsl #16
0x1459f4  movk     x16, #0x11ba, lsl #32
0x1459f8  movk     x30, #0xb99f, lsl #32
0x1459fc  movk     x7, #0xbb88, lsl #32
0x145a00  movk     x6, #0xca87, lsl #32
0x145a04  movk     x5, #0x9ee9, lsl #32
0x145a08  movk     x4, #0x4b03, lsl #32
0x145a0c  movk     x28, #0x176e, lsl #48
0x145a10  movk     x2, #0x6422, lsl #32
0x145a14  movk     x1, #0xeac0, lsl #32
0x145a18  movk     x17, #0xfbe3, lsl #32
0x145a1c  movk     x15, #0x5296, lsl #32
0x145a20  movk     x13, #0x2705, lsl #32
0x145a24  movk     x12, #0xd7d8, lsl #32
0x145a28  movk     x0, #0x1e39, lsl #32
0x145a2c  cmp      x22, #0
0x145a30  movk     x16, #0x26d0, lsl #48
0x145a34  movk     x30, #0x3ef2, lsl #48
0x145a38  movk     x7, #0x5c22, lsl #48
0x145a3c  movk     x6, #0x162c, lsl #48
0x145a40  movk     x5, #0xcf73, lsl #48
0x145a44  movk     x4, #0xc1bd, lsl #48
0x145a48  movk     x2, #0x3b0d, lsl #48
0x145a4c  movk     x1, #0x1ca0, lsl #48
0x145a50  movk     x17, #0xa1b3, lsl #48
0x145a54  movk     x15, #0x1df3, lsl #48
0x145a58  movk     x13, #0x2e9a, lsl #48
0x145a5c  movk     x12, #0x3df5, lsl #48
0x145a60  movk     x0, #0x6f3, lsl #48
0x145a64  mov      x8, x25
0x145a68  csel     x11, x20, x28, eq
0x145a6c  mov      x10, x19
0x145a70  b        #0x1457b0
0x145a74  ldr      x8, [sp, #0x20]
0x145a78  add      x8, x8, #1
0x145a7c  stur     x8, [x29, #-0x38]
0x145a80  ldr      x8, [sp, #0x28]
0x145a84  add      x8, x8, #1
0x145a88  stur     x8, [x29, #-0x40]
0x145a8c  mov      x8, x25
0x145a90  b        #0x145b74
0x145a94  ldur     x3, [x29, #-0x18]
0x145a98  mov      x10, x19
0x145a9c  ldur     x19, [x29, #-0x30]
0x145aa0  mov      x8, x25
0x145aa4  ldrb     w9, [x3]
0x145aa8  stp      x3, x19, [sp, #8]
0x145aac  cmp      w9, #0
0x145ab0  strb     w9, [x19]
0x145ab4  csel     x11, x7, x6, eq
0x145ab8  b        #0x1457b0
0x145abc  ldr      x8, [sp, #8]
0x145ac0  add      x8, x8, #1
0x145ac4  stur     x8, [x29, #-0x18]
0x145ac8  ldr      x8, [sp, #0x10]
0x145acc  add      x8, x8, #1
0x145ad0  stur     x8, [x29, #-0x30]
0x145ad4  mov      x8, x25
0x145ad8  b        #0x145bac
0x145adc  stur     xzr, [x29, #-0x20]
0x145ae0  stur     x22, [x29, #-0x10]
0x145ae4  b        #0x145d20
0x145ae8  ldur     x8, [x29, #-0x48]
0x145aec  str      x14, [sp, #0x38]
0x145af0  cmp      x14, x8
0x145af4  ldr      x8, [sp, #0x48]
0x145af8  csel     x11, x27, x30, eq
0x145afc  stur     x8, [x29, #-8]
0x145b00  b        #0x145be8
0x145b04  ldur     x9, [x29, #-0x28]
0x145b08  mov      x11, #0xb0b0
0x145b0c  ldr      x8, [sp, #0x50]
0x145b10  movk     x11, #0x4891, lsl #16
0x145b14  movk     x11, #0xd7d8, lsl #32
0x145b18  mov      x10, x22
0x145b1c  ldr      x8, [x8, x9, lsl #3]
0x145b20  movk     x11, #0x3df5, lsl #48
0x145b24  str      x8, [sp, #0x40]
0x145b28  mov      x8, x25
0x145b2c  b        #0x1457b0
0x145b30  ldur     x8, [x29, #-0x48]
0x145b34  ldur     x9, [x29, #-0x20]
0x145b38  cmp      x9, x8
0x145b3c  mov      x8, #0x4bb4
0x145b40  movk     x8, #0x877, lsl #16
0x145b44  stur     x9, [x29, #-0x28]
0x145b48  movk     x8, #0x5974, lsl #32
0x145b4c  movk     x8, #0x5eff, lsl #48
0x145b50  csel     x11, x8, x16, eq
0x145b54  b        #0x145be8
0x145b58  ldur     x8, [x29, #-0x10]
0x145b5c  ldr      x9, [sp, #0x30]
0x145b60  ldr      x10, [sp, #0x40]
0x145b64  sub      x9, x9, x8
0x145b68  mov      x8, x25
0x145b6c  add      x9, x22, x9
0x145b70  stp      x9, x10, [x29, #-0x40]
0x145b74  mov      x11, #0xd62d
0x145b78  mov      x10, x19
0x145b7c  movk     x11, #0xa717, lsl #16
0x145b80  movk     x11, #0xd684, lsl #32
0x145b84  movk     x11, #0x75ea, lsl #48
0x145b88  b        #0x1457b0
0x145b8c  ldur     x8, [x29, #-0x10]
0x145b90  ldr      x9, [sp, #0x18]
0x145b94  sub      x9, x9, x8
0x145b98  ldr      x8, [sp]
0x145b9c  add      x9, x22, x9
0x145ba0  stur     x8, [x29, #-0x18]
0x145ba4  mov      x8, x25
0x145ba8  stur     x9, [x29, #-0x30]
0x145bac  mov      x11, #0xafca
0x145bb0  mov      x10, x19
0x145bb4  movk     x11, #0x7c1a, lsl #16
0x145bb8  movk     x11, #0x1e39, lsl #32
0x145bbc  movk     x11, #0x6f3, lsl #48
0x145bc0  b        #0x1457b0
0x145bc4  mov      x21, x19
0x145bc8  str      x19, [sp, #0x30]
0x145bcc  ldrb     w8, [x21], #1
0x145bd0  cmp      w8, #0
0x145bd4  mov      x8, #0x4fa1
0x145bd8  movk     x8, #0x3fc2, lsl #16
0x145bdc  movk     x8, #0x4b99, lsl #32
0x145be0  movk     x8, #0x365c, lsl #48
0x145be4  csel     x11, x8, x4, eq
0x145be8  mov      x8, x25
0x145bec  mov      x10, x19
0x145bf0  b        #0x1457b0
0x145bf4  ldr      x26, [sp, #0x38]
0x145bf8  ldr      x8, [sp, #0x50]
0x145bfc  ldr      x0, [x8, x26, lsl #3]
0x145c00  bl       #0x148ce0   ; -> strlen
0x145c04  ldur     x8, [x29, #-8]
0x145c08  mov      x16, #0xe6b2
0x145c0c  mov      x30, #0x208d
0x145c10  mov      x7, #0x933c
0x145c14  mov      x6, #0x64c6
0x145c18  mov      x5, #0x30e
0x145c1c  add      x9, x8, x0
0x145c20  mov      x4, #0x1c0f
0x145c24  mov      x2, #0xc6bd
0x145c28  mov      x1, #0xdfbb
0x145c2c  mov      x17, #0x692
0x145c30  mov      x15, #0xe11a
0x145c34  mov      x13, #0x2214
0x145c38  mov      x12, #0xb0b0
0x145c3c  add      x14, x26, #1
0x145c40  mov      x26, #0x4905
0x145c44  mov      x0, #0xafca
0x145c48  add      x9, x9, #1
0x145c4c  mov      x11, #0xe11a
0x145c50  movk     x16, #0xa01a, lsl #16
0x145c54  movk     x30, #0x44b3, lsl #16
0x145c58  movk     x7, #0x4138, lsl #16
0x145c5c  movk     x6, #0xb4df, lsl #16
0x145c60  movk     x5, #0x1b5, lsl #16
0x145c64  movk     x4, #0x6b47, lsl #16
0x145c68  movk     x2, #0xda71, lsl #16
0x145c6c  movk     x1, #0xfd40, lsl #16
0x145c70  movk     x17, #0x8807, lsl #16
0x145c74  movk     x15, #0xe707, lsl #16
0x145c78  movk     x13, #0x6e6c, lsl #16
0x145c7c  movk     x12, #0x4891, lsl #16
0x145c80  movk     x26, #0x4d4c, lsl #16
0x145c84  movk     x0, #0x7c1a, lsl #16
0x145c88  movk     x11, #0xe707, lsl #16
0x145c8c  movk     x16, #0x11ba, lsl #32
0x145c90  movk     x30, #0xb99f, lsl #32
0x145c94  movk     x7, #0xbb88, lsl #32
0x145c98  movk     x6, #0xca87, lsl #32
0x145c9c  movk     x5, #0x9ee9, lsl #32
0x145ca0  movk     x4, #0x4b03, lsl #32
0x145ca4  movk     x2, #0x6422, lsl #32
0x145ca8  movk     x1, #0xeac0, lsl #32
0x145cac  movk     x17, #0xfbe3, lsl #32
0x145cb0  movk     x15, #0x5296, lsl #32
0x145cb4  movk     x13, #0x2705, lsl #32
0x145cb8  movk     x12, #0xd7d8, lsl #32
0x145cbc  movk     x26, #0xa445, lsl #32
0x145cc0  movk     x0, #0x1e39, lsl #32
0x145cc4  movk     x11, #0x5296, lsl #32
0x145cc8  movk     x16, #0x26d0, lsl #48
0x145ccc  movk     x30, #0x3ef2, lsl #48
0x145cd0  movk     x7, #0x5c22, lsl #48
0x145cd4  movk     x6, #0x162c, lsl #48
0x145cd8  movk     x5, #0xcf73, lsl #48
0x145cdc  movk     x4, #0xc1bd, lsl #48
0x145ce0  movk     x2, #0x3b0d, lsl #48
0x145ce4  movk     x1, #0x1ca0, lsl #48
0x145ce8  movk     x17, #0xa1b3, lsl #48
0x145cec  movk     x15, #0x1df3, lsl #48
0x145cf0  movk     x13, #0x2e9a, lsl #48
0x145cf4  movk     x12, #0x3df5, lsl #48
0x145cf8  movk     x26, #0x9d91, lsl #48
0x145cfc  movk     x0, #0x6f3, lsl #48
0x145d00  mov      x8, x25
0x145d04  str      x9, [sp, #0x48]
0x145d08  mov      x10, x19
0x145d0c  movk     x11, #0x1df3, lsl #48
0x145d10  b        #0x1457b0
0x145d14  ldur     x8, [x29, #-0x28]
0x145d18  add      x8, x8, #1
0x145d1c  stur     x8, [x29, #-0x20]
0x145d20  mov      x11, #0x2214
0x145d24  mov      x8, x25
0x145d28  movk     x11, #0x6e6c, lsl #16
0x145d2c  mov      x10, x19
0x145d30  movk     x11, #0x2705, lsl #32
0x145d34  movk     x11, #0x2e9a, lsl #48
0x145d38  b        #0x1457b0
0x145d3c  ldp      x3, x10, [x29, #-0x40]
0x145d40  mov      x8, x25
0x145d44  ldrb     w9, [x10]
0x145d48  stp      x10, x3, [sp, #0x20]
0x145d4c  mov      x10, x19
0x145d50  cmp      w9, #0
0x145d54  strb     w9, [x3]
0x145d58  csel     x11, x5, x26, eq
0x145d5c  b        #0x1457b0
0x145d60  mov      x0, x22
0x145d64  ldp      x20, x19, [sp, #0xf0]
0x145d68  ldp      x22, x21, [sp, #0xe0]
0x145d6c  ldp      x24, x23, [sp, #0xd0]
0x145d70  ldp      x26, x25, [sp, #0xc0]
0x145d74  ldp      x28, x27, [sp, #0xb0]
0x145d78  ldp      x29, x30, [sp, #0xa0]
0x145d7c  add      sp, sp, #0x100
0x145d80  ret      
0x145d84  sub      sp, sp, #0x130
0x145d88  stp      x29, x30, [sp, #0xd0]
0x145d8c  stp      x28, x27, [sp, #0xe0]
0x145d90  stp      x26, x25, [sp, #0xf0]
0x145d94  stp      x24, x23, [sp, #0x100]
0x145d98  stp      x22, x21, [sp, #0x110]
0x145d9c  stp      x20, x19, [sp, #0x120]
0x145da0  add      x29, sp, #0xd0
0x145da4  sub      x8, x3, #1
0x145da8  mov      x11, #0xdfb
0x145dac  mov      x12, #0xde08
0x145db0  mov      x13, #0x7df3
0x145db4  mov      x14, #0x892a
0x145db8  mov      x15, #0x55a2
0x145dbc  stp      x8, x3, [sp]
0x145dc0  and      x8, x1, #0xffffffff
0x145dc4  mov      x16, #0x657a
0x145dc8  mov      x17, #0xc0f4
0x145dcc  mov      x7, #0x2cec
0x145dd0  mov      x30, #0xf039
0x145dd4  stp      x8, x0, [sp, #0x60]
0x145dd8  mov      x9, #0x892a
0x145ddc  movk     x11, #0x2958, lsl #16
0x145de0  movk     x12, #0xc909, lsl #16
0x145de4  movk     x13, #0xc080, lsl #16
0x145de8  movk     x14, #0xf589, lsl #16
0x145dec  movk     x15, #0xf7da, lsl #16
0x145df0  movk     x16, #0xfdaf, lsl #16
0x145df4  movk     x17, #0x5f9, lsl #16
0x145df8  movk     x7, #0x1b16, lsl #16
0x145dfc  movk     x30, #0x4336, lsl #16
0x145e00  movk     x9, #0xf589, lsl #16
0x145e04  movk     x11, #0x9f87, lsl #32
0x145e08  movk     x12, #0x3343, lsl #32
0x145e0c  movk     x13, #0x5a98, lsl #32
0x145e10  movk     x14, #0xee2f, lsl #32
0x145e14  movk     x15, #0xd1ac, lsl #32
0x145e18  movk     x16, #0x9ffd, lsl #32
0x145e1c  movk     x17, #0x5b42, lsl #32
0x145e20  movk     x7, #0x9030, lsl #32
0x145e24  movk     x30, #0xfc62, lsl #32
0x145e28  movk     x9, #0xee2f, lsl #32
0x145e2c  movk     x11, #0xd5b5, lsl #48
0x145e30  movk     x12, #0xa7a4, lsl #48
0x145e34  movk     x13, #0x1704, lsl #48
0x145e38  movk     x14, #0x24c0, lsl #48
0x145e3c  movk     x15, #0x87a9, lsl #48
0x145e40  movk     x16, #0xb4b1, lsl #48
0x145e44  movk     x17, #0xc20e, lsl #48
0x145e48  movk     x7, #0xb6c1, lsl #48
0x145e4c  movk     x30, #0xd078, lsl #48
0x145e50  movk     x9, #0x24c0, lsl #48
0x145e54  stp      x2, xzr, [sp, #0x40]
0x145e58  mov      x8, x9
0x145e5c  mov      x9, #0xde08
0x145e60  mov      x22, x0
0x145e64  mov      x24, x1
0x145e68  ldp      x1, x0, [x29, #-0x18]
0x145e6c  movk     x9, #0xc909, lsl #16
0x145e70  mov      x21, x6
0x145e74  movk     x9, #0x3343, lsl #32
0x145e78  mov      x28, x5
0x145e7c  mov      x25, x4
0x145e80  mov      x23, x2
0x145e84  mov      x2, x26
0x145e88  mov      x4, x20
0x145e8c  mov      x5, x27
0x145e90  ldur     x6, [x29, #-0x20]
0x145e94  movk     x9, #0xa7a4, lsl #48
0x145e98  cmp      x8, x15
0x145e9c  b.eq     #0x145e58
0x145ea0  mov      x19, x3
0x145ea4  cmp      x8, x12
0x145ea8  b.eq     #0x146064
0x145eac  cmp      x8, x16
0x145eb0  b.eq     #0x1460ac
0x145eb4  cmp      x8, x7
0x145eb8  b.eq     #0x146194
0x145ebc  mov      x9, #0xdfb
0x145ec0  cmp      x8, x17
0x145ec4  movk     x9, #0x2958, lsl #16
0x145ec8  mov      x1, x24
0x145ecc  movk     x9, #0x9f87, lsl #32
0x145ed0  mov      x2, x23
0x145ed4  ccmp     x8, x30, #4, ne
0x145ed8  mov      x0, x22
0x145edc  mov      x4, x25
0x145ee0  mov      x3, x19
0x145ee4  mov      x5, x28
0x145ee8  mov      x6, x21
0x145eec  movk     x9, #0xd5b5, lsl #48
0x145ef0  b.eq     #0x145e58
0x145ef4  mov      x9, #0x6c7b
0x145ef8  mov      x1, x24
0x145efc  movk     x9, #0xdbb6, lsl #16
0x145f00  mov      x2, x23
0x145f04  movk     x9, #0x615, lsl #32
0x145f08  mov      x0, x22
0x145f0c  mov      x4, x25
0x145f10  ldur     x3, [x29, #-0x28]
0x145f14  mov      x5, x28
0x145f18  mov      x6, x21
0x145f1c  movk     x9, #0x1904, lsl #48
0x145f20  cmp      x8, x11
0x145f24  b.eq     #0x145e58
0x145f28  mov      x9, #0x23f8
0x145f2c  movk     x9, #0x4d22, lsl #16
0x145f30  movk     x9, #0x706a, lsl #32
0x145f34  movk     x9, #0xe104, lsl #48
0x145f38  cmp      x8, x9
0x145f3c  b.eq     #0x1461c4
0x145f40  cmp      x8, x13
0x145f44  b.eq     #0x1462a8
0x145f48  mov      x9, #0x7df3
0x145f4c  mov      x1, x24
0x145f50  movk     x9, #0xc080, lsl #16
0x145f54  mov      x2, x23
0x145f58  movk     x9, #0x5a98, lsl #32
0x145f5c  mov      x0, x22
0x145f60  mov      x4, x25
0x145f64  mov      x3, x19
0x145f68  mov      x5, x28
0x145f6c  mov      x6, x21
0x145f70  movk     x9, #0x1704, lsl #48
0x145f74  cmp      x8, x14
0x145f78  b.eq     #0x145e58
0x145f7c  mov      x9, #0x7fe0
0x145f80  movk     x9, #0xb22d, lsl #16
0x145f84  movk     x9, #0x6acd, lsl #32
0x145f88  movk     x9, #0x2fb9, lsl #48
0x145f8c  cmp      x8, x9
0x145f90  b.eq     #0x146308
0x145f94  mov      x9, #0xde08
0x145f98  mov      x10, #0xc59
0x145f9c  ldp      x0, x1, [x29, #-0x40]
0x145fa0  movk     x9, #0xc909, lsl #16
0x145fa4  movk     x10, #0x6b1, lsl #16
0x145fa8  movk     x9, #0x3343, lsl #32
0x145fac  mov      x2, x26
0x145fb0  ldur     x4, [x29, #-0x48]
0x145fb4  mov      x3, x19
0x145fb8  mov      x5, x27
0x145fbc  ldur     x6, [x29, #-0x30]
0x145fc0  movk     x9, #0xa7a4, lsl #48
0x145fc4  movk     x10, #0xace6, lsl #32
0x145fc8  movk     x10, #0x316a, lsl #48
0x145fcc  cmp      x8, x10
0x145fd0  b.eq     #0x145e58
0x145fd4  mov      x9, #0x2a77
0x145fd8  movk     x9, #0xf078, lsl #16
0x145fdc  movk     x9, #0x8200, lsl #32
0x145fe0  movk     x9, #0x3d54, lsl #48
0x145fe4  cmp      x8, x9
0x145fe8  b.eq     #0x146364
0x145fec  mov      x9, #0xde08
0x145ff0  mov      x10, #0x2807
0x145ff4  ldp      x1, x0, [x29, #-0x18]
0x145ff8  movk     x9, #0xc909, lsl #16
0x145ffc  movk     x10, #0xc9ce, lsl #16
0x146000  ldp      x2, x5, [x29, #-0x60]
0x146004  movk     x9, #0x3343, lsl #32
0x146008  mov      x4, x20
0x14600c  mov      x3, x19
0x146010  ldur     x6, [x29, #-0x20]
0x146014  movk     x9, #0xa7a4, lsl #48
0x146018  movk     x10, #0x58a8, lsl #32
0x14601c  movk     x10, #0x4339, lsl #48
0x146020  cmp      x8, x10
0x146024  b.eq     #0x145e58
0x146028  mov      x10, #0x6c7b
0x14602c  mov      x1, x24
0x146030  movk     x10, #0xdbb6, lsl #16
0x146034  mov      x2, x23
0x146038  mov      x0, x22
0x14603c  mov      x4, x25
0x146040  mov      x3, x19
0x146044  mov      x5, x28
0x146048  mov      x6, x21
0x14604c  mov      x9, x8
0x146050  movk     x10, #0x615, lsl #32
0x146054  movk     x10, #0x1904, lsl #48
0x146058  cmp      x8, x10
0x14605c  b.ne     #0x145e58
0x146060  b        #0x146448
0x146064  ldur     x8, [x29, #-0x50]
0x146068  mov      x9, #0x7df3
0x14606c  movk     x9, #0xc080, lsl #16
0x146070  mov      x1, x24
0x146074  movk     x9, #0x5a98, lsl #32
0x146078  mov      x2, x23
0x14607c  add      x8, x8, #1
0x146080  mov      x0, x22
0x146084  mov      x4, x25
0x146088  mov      x3, x19
0x14608c  mov      x5, x28
0x146090  mov      x6, x21
0x146094  str      x8, [sp, #0x48]
0x146098  movk     x9, #0x1704, lsl #48
0x14609c  stp      x22, x25, [sp, #0x30]
0x1460a0  stp      x24, x23, [sp, #0x20]
0x1460a4  stp      x21, x28, [sp, #0x10]
0x1460a8  b        #0x145e58
0x1460ac  ldr      x8, [sp, #0x40]
0x1460b0  and      x10, x27, #0xffffffff00000000
0x1460b4  ldur     x9, [x29, #-0x50]
0x1460b8  ldp      x11, x0, [sp, #0x60]
0x1460bc  add      x8, x8, x9, lsl #5
0x1460c0  orr      x1, x10, x11
0x1460c4  and      x10, x26, #0xffffffff00000000
0x1460c8  ldr      w9, [x8, #0x28]
0x1460cc  ldr      x2, [x8, #0x20]
0x1460d0  orr      x3, x10, x9
0x1460d4  stp      x3, x1, [x29, #-0x60]
0x1460d8  bl       #0x13d5b8   ; -> None
0x1460dc  mov      x17, #0xc0f4
0x1460e0  mov      x8, #0x2807
0x1460e4  mov      x30, #0xf039
0x1460e8  mov      x7, #0x2cec
0x1460ec  movk     x17, #0x5f9, lsl #16
0x1460f0  mov      x16, #0x657a
0x1460f4  mov      x15, #0x55a2
0x1460f8  mov      x14, #0x892a
0x1460fc  mov      x13, #0x7df3
0x146100  mov      x12, #0xde08
0x146104  mov      x11, #0xdfb
0x146108  movk     x8, #0xc9ce, lsl #16
0x14610c  movk     x30, #0x4336, lsl #16
0x146110  movk     x7, #0x1b16, lsl #16
0x146114  movk     x17, #0x5b42, lsl #32
0x146118  movk     x16, #0xfdaf, lsl #16
0x14611c  movk     x15, #0xf7da, lsl #16
0x146120  movk     x14, #0xf589, lsl #16
0x146124  movk     x13, #0xc080, lsl #16
0x146128  movk     x12, #0xc909, lsl #16
0x14612c  movk     x11, #0x2958, lsl #16
0x146130  movk     x8, #0x58a8, lsl #32
0x146134  movk     x30, #0xfc62, lsl #32
0x146138  movk     x7, #0x9030, lsl #32
0x14613c  movk     x17, #0xc20e, lsl #48
0x146140  movk     x16, #0x9ffd, lsl #32
0x146144  movk     x15, #0xd1ac, lsl #32
0x146148  movk     x14, #0xee2f, lsl #32
0x14614c  movk     x13, #0x5a98, lsl #32
0x146150  movk     x12, #0x3343, lsl #32
0x146154  movk     x11, #0x9f87, lsl #32
0x146158  cmp      w0, #0
0x14615c  movk     x8, #0x4339, lsl #48
0x146160  movk     x30, #0xd078, lsl #48
0x146164  movk     x7, #0xb6c1, lsl #48
0x146168  movk     x16, #0xb4b1, lsl #48
0x14616c  movk     x15, #0x87a9, lsl #48
0x146170  movk     x14, #0x24c0, lsl #48
0x146174  movk     x13, #0x1704, lsl #48
0x146178  movk     x12, #0xa7a4, lsl #48
0x14617c  movk     x11, #0xd5b5, lsl #48
0x146180  mov      x1, x24
0x146184  mov      x2, x23
0x146188  mov      x0, x22
0x14618c  csel     x9, x17, x8, lt
0x146190  b        #0x146434
0x146194  mov      x9, #0x6c7b
0x146198  mov      x3, xzr
0x14619c  movk     x9, #0xdbb6, lsl #16
0x1461a0  mov      x1, x24
0x1461a4  movk     x9, #0x615, lsl #32
0x1461a8  mov      x2, x23
0x1461ac  mov      x0, x22
0x1461b0  mov      x4, x25
0x1461b4  mov      x5, x28
0x1461b8  mov      x6, x21
0x1461bc  movk     x9, #0x1904, lsl #48
0x1461c0  b        #0x145e58
0x1461c4  ldur     x8, [x29, #-0x10]
0x1461c8  and      x9, x20, #0xffffffff00000000
0x1461cc  ldp      x10, x0, [sp, #0x60]
0x1461d0  and      x8, x8, #0xffffffff00000000
0x1461d4  ldr      x2, [sp, #0x58]
0x1461d8  orr      x1, x8, x10
0x1461dc  ldr      x8, [sp, #0x50]
0x1461e0  orr      x3, x8, x9
0x1461e4  stur     x1, [x29, #-0x40]
0x1461e8  stur     x3, [x29, #-0x48]
0x1461ec  bl       #0x13d7a0   ; -> None
0x1461f0  mov      x30, #0xf039
0x1461f4  mov      x8, #0xc59
0x1461f8  movk     x30, #0x4336, lsl #16
0x1461fc  mov      x7, #0x2cec
0x146200  mov      x17, #0xc0f4
0x146204  mov      x16, #0x657a
0x146208  mov      x15, #0x55a2
0x14620c  mov      x14, #0x892a
0x146210  mov      x13, #0x7df3
0x146214  mov      x12, #0xde08
0x146218  mov      x11, #0xdfb
0x14621c  movk     x8, #0x6b1, lsl #16
0x146220  movk     x30, #0xfc62, lsl #32
0x146224  movk     x7, #0x1b16, lsl #16
0x146228  movk     x17, #0x5f9, lsl #16
0x14622c  movk     x16, #0xfdaf, lsl #16
0x146230  movk     x15, #0xf7da, lsl #16
0x146234  movk     x14, #0xf589, lsl #16
0x146238  movk     x13, #0xc080, lsl #16
0x14623c  movk     x12, #0xc909, lsl #16
0x146240  movk     x11, #0x2958, lsl #16
0x146244  movk     x8, #0xace6, lsl #32
0x146248  movk     x30, #0xd078, lsl #48
0x14624c  movk     x7, #0x9030, lsl #32
0x146250  movk     x17, #0x5b42, lsl #32
0x146254  movk     x16, #0x9ffd, lsl #32
0x146258  movk     x15, #0xd1ac, lsl #32
0x14625c  movk     x14, #0xee2f, lsl #32
0x146260  movk     x13, #0x5a98, lsl #32
0x146264  movk     x12, #0x3343, lsl #32
0x146268  movk     x11, #0x9f87, lsl #32
0x14626c  tst      w0, #1
0x146270  movk     x8, #0x316a, lsl #48
0x146274  movk     x7, #0xb6c1, lsl #48
0x146278  movk     x17, #0xc20e, lsl #48
0x14627c  movk     x16, #0xb4b1, lsl #48
0x146280  movk     x15, #0x87a9, lsl #48
0x146284  movk     x14, #0x24c0, lsl #48
0x146288  movk     x13, #0x1704, lsl #48
0x14628c  movk     x12, #0xa7a4, lsl #48
0x146290  movk     x11, #0xd5b5, lsl #48
0x146294  mov      x1, x24
0x146298  mov      x2, x23
0x14629c  mov      x0, x22
0x1462a0  csel     x9, x30, x8, ne
0x1462a4  b        #0x146434
0x1462a8  ldr      x8, [sp, #8]
0x1462ac  mov      x1, x24
0x1462b0  ldr      x10, [sp, #0x48]
0x1462b4  mov      x2, x23
0x1462b8  ldr      x20, [sp, #0x38]
0x1462bc  mov      x0, x22
0x1462c0  mov      x4, x25
0x1462c4  mov      x3, x19
0x1462c8  cmp      x10, x8
0x1462cc  mov      x8, #0x7fe0
0x1462d0  movk     x8, #0xb22d, lsl #16
0x1462d4  mov      x5, x28
0x1462d8  movk     x8, #0x6acd, lsl #32
0x1462dc  mov      x6, x21
0x1462e0  movk     x8, #0x2fb9, lsl #48
0x1462e4  stur     x10, [x29, #-0x50]
0x1462e8  csel     x9, x7, x8, eq
0x1462ec  ldr      x8, [sp, #0x10]
0x1462f0  stur     x8, [x29, #-0x30]
0x1462f4  ldp      x27, x8, [sp, #0x18]
0x1462f8  stur     x8, [x29, #-0x38]
0x1462fc  ldp      x26, x8, [sp, #0x28]
0x146300  stur     x8, [x29, #-0x10]
0x146304  b        #0x145e58
0x146308  ldr      x8, [sp, #0x40]
0x14630c  mov      x1, x24
0x146310  ldur     x9, [x29, #-0x50]
0x146314  mov      x2, x23
0x146318  mov      x0, x22
0x14631c  add      x10, x8, x9, lsl #5
0x146320  ldr      x8, [sp]
0x146324  cmp      x9, x8
0x146328  ldr      x8, [x10]
0x14632c  mov      x9, #0x2a77
0x146330  stur     x10, [x29, #-0x28]
0x146334  movk     x9, #0xf078, lsl #16
0x146338  str      x8, [sp, #0x58]
0x14633c  mov      x8, #0x23f8
0x146340  movk     x8, #0x4d22, lsl #16
0x146344  movk     x9, #0x8200, lsl #32
0x146348  movk     x8, #0x706a, lsl #32
0x14634c  movk     x9, #0x3d54, lsl #48
0x146350  movk     x8, #0xe104, lsl #48
0x146354  csel     x9, x9, x8, lo
0x146358  ldr      w8, [x10, #8]
0x14635c  str      x8, [sp, #0x50]
0x146360  b        #0x146434
0x146364  ldp      x8, x9, [x29, #-0x38]
0x146368  ldp      x10, x0, [sp, #0x60]
0x14636c  and      x8, x8, #0xffffffff00000000
0x146370  ldr      x2, [sp, #0x58]
0x146374  and      x9, x9, #0xffffffff00000000
0x146378  orr      x1, x8, x10
0x14637c  ldr      x8, [sp, #0x50]
0x146380  orr      x3, x8, x9
0x146384  stur     x1, [x29, #-0x18]
0x146388  stur     x3, [x29, #-0x20]
0x14638c  bl       #0x13d5b8   ; -> None
0x146390  mov      x16, #0x657a
0x146394  mov      x15, #0x55a2
0x146398  mov      x30, #0xf039
0x14639c  mov      x7, #0x2cec
0x1463a0  mov      x17, #0xc0f4
0x1463a4  movk     x16, #0xfdaf, lsl #16
0x1463a8  movk     x15, #0xf7da, lsl #16
0x1463ac  mov      x14, #0x892a
0x1463b0  mov      x13, #0x7df3
0x1463b4  mov      x12, #0xde08
0x1463b8  mov      x11, #0xdfb
0x1463bc  movk     x30, #0x4336, lsl #16
0x1463c0  movk     x7, #0x1b16, lsl #16
0x1463c4  movk     x17, #0x5f9, lsl #16
0x1463c8  movk     x16, #0x9ffd, lsl #32
0x1463cc  movk     x15, #0xd1ac, lsl #32
0x1463d0  movk     x14, #0xf589, lsl #16
0x1463d4  movk     x13, #0xc080, lsl #16
0x1463d8  movk     x12, #0xc909, lsl #16
0x1463dc  movk     x11, #0x2958, lsl #16
0x1463e0  movk     x30, #0xfc62, lsl #32
0x1463e4  movk     x7, #0x9030, lsl #32
0x1463e8  movk     x17, #0x5b42, lsl #32
0x1463ec  movk     x16, #0xb4b1, lsl #48
0x1463f0  movk     x15, #0x87a9, lsl #48
0x1463f4  movk     x14, #0xee2f, lsl #32
0x1463f8  movk     x13, #0x5a98, lsl #32
0x1463fc  movk     x12, #0x3343, lsl #32
0x146400  movk     x11, #0x9f87, lsl #32
0x146404  cmp      w0, #0
0x146408  movk     x30, #0xd078, lsl #48
0x14640c  movk     x7, #0xb6c1, lsl #48
0x146410  movk     x17, #0xc20e, lsl #48
0x146414  movk     x14, #0x24c0, lsl #48
0x146418  movk     x13, #0x1704, lsl #48
0x14641c  movk     x12, #0xa7a4, lsl #48
0x146420  movk     x11, #0xd5b5, lsl #48
0x146424  mov      x1, x24
0x146428  mov      x2, x23
0x14642c  mov      x0, x22
0x146430  csel     x9, x16, x15, ge
0x146434  mov      x4, x25
0x146438  mov      x3, x19
0x14643c  mov      x5, x28
0x146440  mov      x6, x21
0x146444  b        #0x145e58
0x146448  mov      x0, x19
0x14644c  ldp      x20, x19, [sp, #0x120]
0x146450  ldp      x22, x21, [sp, #0x110]
0x146454  ldp      x24, x23, [sp, #0x100]
0x146458  ldp      x26, x25, [sp, #0xf0]
0x14645c  ldp      x28, x27, [sp, #0xe0]
0x146460  ldp      x29, x30, [sp, #0xd0]
0x146464  add      sp, sp, #0x130
0x146468  ret      
0x14646c  b        #0x147548
0x146470  b        #0x147630
0x146474  b        #0x147620
0x146478  b        #0x147734
0x14647c  b        #0x147c68
0x146480  stp      x29, x30, [sp, #-0x20]!
0x146484  stp      x20, x19, [sp, #0x10]
0x146488  mov      x29, sp
0x14648c  mov      x19, x0
0x146490  mov      x20, #0xd2d1
0x146494  mov      w0, #1
0x146498  mov      w1, #8
0x14649c  movk     x20, #0xf825, lsl #16
0x1464a0  movk     x20, #0xee0c, lsl #32
0x1464a4  movk     x20, #0x5c23, lsl #48
0x1464a8  bl       #0x148b90   ; -> calloc
0x1464ac  mov      x8, #0x5dae
0x1464b0  mov      x9, #0xa74a
0x1464b4  movk     x8, #0xbd6e, lsl #16
0x1464b8  movk     x9, #0x5ea3, lsl #16
0x1464bc  mov      x10, #0x8e81
0x1464c0  mov      x13, #0x8e81
0x1464c4  movk     x8, #0x6aaa, lsl #32
0x1464c8  movk     x9, #0xa04f, lsl #32
0x1464cc  movk     x10, #0xe154, lsl #16
0x1464d0  movk     x13, #0xe154, lsl #16
0x1464d4  movk     x8, #0x28f0, lsl #48
0x1464d8  movk     x9, #0xfa1e, lsl #48
0x1464dc  cmp      x0, #0
0x1464e0  movk     x10, #0x3b5e, lsl #32
0x1464e4  movk     x13, #0x3b5e, lsl #32
0x1464e8  movk     x10, #0x7cc5, lsl #48
0x1464ec  csel     x11, x9, x8, eq
0x1464f0  mov      w12, #2
0x1464f4  movk     x13, #0x7cc5, lsl #48
0x1464f8  cmp      x13, x9
0x1464fc  b.eq     #0x14652c
0x146500  cmp      x13, x10
0x146504  b.eq     #0x146544
0x146508  cmp      x13, x20
0x14650c  b.eq     #0x14654c
0x146510  cmp      x13, x8
0x146514  b.ne     #0x1464f8
0x146518  mov      x13, #0xd2d1
0x14651c  movk     x13, #0xf825, lsl #16
0x146520  movk     x13, #0xee0c, lsl #32
0x146524  movk     x13, #0x5c23, lsl #48
0x146528  b        #0x1464f8
0x14652c  mov      x13, #0xd2d1
0x146530  str      w12, [x19]
0x146534  movk     x13, #0xf825, lsl #16
0x146538  movk     x13, #0xee0c, lsl #32
0x14653c  movk     x13, #0x5c23, lsl #48
0x146540  b        #0x1464f8
0x146544  mov      x13, x11
0x146548  b        #0x1464f8
0x14654c  ldp      x20, x19, [sp, #0x10]
0x146550  ldp      x29, x30, [sp], #0x20
0x146554  ret      
0x146558  stp      x29, x30, [sp, #-0x30]!
0x14655c  stp      x22, x21, [sp, #0x10]
0x146560  stp      x20, x19, [sp, #0x20]
0x146564  mov      x29, sp
0x146568  mov      x20, x1
0x14656c  mov      x21, x0
0x146570  mov      x22, #0xdf4a
0x146574  mov      w0, #1
0x146578  mov      w1, #0x10
0x14657c  movk     x22, #0xbdc8, lsl #16
0x146580  movk     x22, #0xceb, lsl #32
0x146584  mov      w19, w2
0x146588  movk     x22, #0xc8d5, lsl #48
0x14658c  bl       #0x148b90   ; -> calloc
0x146590  mov      x8, #0xb7cc
0x146594  mov      x9, #0xc335
0x146598  movk     x8, #0xff64, lsl #16
0x14659c  movk     x9, #0x1484, lsl #16
0x1465a0  mov      x10, #0x9a1f
0x1465a4  mov      x13, #0x9a1f
0x1465a8  movk     x8, #0xf23e, lsl #32
0x1465ac  movk     x9, #0x16b3, lsl #32
0x1465b0  movk     x10, #0xd6a5, lsl #16
0x1465b4  movk     x13, #0xd6a5, lsl #16
0x1465b8  movk     x8, #0x8f3d, lsl #48
0x1465bc  movk     x9, #0xb3cc, lsl #48
0x1465c0  cmp      x0, #0
0x1465c4  movk     x10, #0xc885, lsl #32
0x1465c8  movk     x13, #0xc885, lsl #32
0x1465cc  movk     x10, #0xf611, lsl #48
0x1465d0  csel     x11, x9, x8, eq
0x1465d4  mov      w12, #2
0x1465d8  movk     x13, #0xf611, lsl #48
0x1465dc  cmp      x13, x8
0x1465e0  b.eq     #0x146614
0x1465e4  cmp      x13, x10
0x1465e8  b.eq     #0x146638
0x1465ec  cmp      x13, x22
0x1465f0  b.eq     #0x146640
0x1465f4  cmp      x13, x9
0x1465f8  b.ne     #0x1465dc
0x1465fc  mov      x13, #0xdf4a
0x146600  str      w12, [x21]
0x146604  movk     x13, #0xbdc8, lsl #16
0x146608  movk     x13, #0xceb, lsl #32
0x14660c  movk     x13, #0xc8d5, lsl #48
0x146610  b        #0x1465dc
0x146614  ldr      x14, [x20]
0x146618  mov      x13, #0xdf4a
0x14661c  movk     x13, #0xbdc8, lsl #16
0x146620  str      w19, [x0]
0x146624  movk     x13, #0xceb, lsl #32
0x146628  str      x0, [x20]
0x14662c  movk     x13, #0xc8d5, lsl #48
0x146630  str      x14, [x0, #8]
0x146634  b        #0x1465dc
0x146638  mov      x13, x11
0x14663c  b        #0x1465dc
0x146640  ldp      x20, x19, [sp, #0x20]
0x146644  ldp      x22, x21, [sp, #0x10]
0x146648  ldp      x29, x30, [sp], #0x30
0x14664c  ret      
0x146650  stp      x29, x30, [sp, #-0x50]!
0x146654  stp      x26, x25, [sp, #0x10]
0x146658  stp      x24, x23, [sp, #0x20]
0x14665c  stp      x22, x21, [sp, #0x30]
0x146660  stp      x20, x19, [sp, #0x40]
0x146664  mov      x29, sp
0x146668  ldr      x20, [x0]
0x14666c  mov      x22, #0x3581
0x146670  mov      x23, #0x2f9c
0x146674  movk     x22, #0xbcba, lsl #16
0x146678  movk     x23, #0xc396, lsl #16
0x14667c  mov      x24, #0xafb5
0x146680  ldr      w8, [x20]
0x146684  mov      x26, #0x7515
0x146688  movk     x22, #0x133, lsl #32
0x14668c  movk     x23, #0x5e8f, lsl #32
0x146690  movk     x24, #0xa12b, lsl #16
0x146694  movk     x26, #0xb217, lsl #16
0x146698  subs     w21, w8, #1
0x14669c  mov      x8, #0x7515
0x1466a0  movk     x8, #0xb217, lsl #16
0x1466a4  movk     x22, #0x761f, lsl #48
0x1466a8  movk     x23, #0xf2cd, lsl #48
0x1466ac  movk     x24, #0xce93, lsl #32
0x1466b0  movk     x26, #0xdfc8, lsl #32
0x1466b4  movk     x8, #0xdfc8, lsl #32
0x1466b8  mov      x19, x0
0x1466bc  movk     x24, #0xb225, lsl #48
0x1466c0  csel     x25, x23, x22, eq
0x1466c4  movk     x26, #0x768a, lsl #48
0x1466c8  movk     x8, #0x768a, lsl #48
0x1466cc  str      w21, [x20]
0x1466d0  cmp      x8, x24
0x1466d4  b.eq     #0x146720
0x1466d8  cmp      x8, x23
0x1466dc  b.eq     #0x1466f4
0x1466e0  cmp      x8, x26
0x1466e4  b.eq     #0x146718
0x1466e8  cmp      x8, x22
0x1466ec  b.ne     #0x1466d0
0x1466f0  b        #0x146704
0x1466f4  ldr      x8, [x20, #8]
0x1466f8  mov      x0, x20
0x1466fc  str      x8, [x19]
0x146700  bl       #0x148a00   ; -> free
0x146704  mov      x8, #0xafb5
0x146708  movk     x8, #0xa12b, lsl #16
0x14670c  movk     x8, #0xce93, lsl #32
0x146710  movk     x8, #0xb225, lsl #48
0x146714  b        #0x1466d0
0x146718  mov      x8, x25
0x14671c  b        #0x1466d0
0x146720  mov      w0, w21
0x146724  ldp      x20, x19, [sp, #0x40]
0x146728  ldp      x22, x21, [sp, #0x30]
0x14672c  ldp      x24, x23, [sp, #0x20]
0x146730  ldp      x26, x25, [sp, #0x10]
0x146734  ldp      x29, x30, [sp], #0x50
0x146738  ret      
0x14673c  stp      x29, x30, [sp, #-0x40]!
0x146740  stp      x24, x23, [sp, #0x10]
0x146744  stp      x22, x21, [sp, #0x20]
0x146748  stp      x20, x19, [sp, #0x30]
0x14674c  mov      x29, sp
0x146750  mov      x20, #0xee15
0x146754  mov      x21, #0x8779
0x146758  movk     x20, #0x1fe1, lsl #16
0x14675c  movk     x21, #0xf1b8, lsl #16
0x146760  mov      x22, #0x7811
0x146764  mov      x24, #0x28cc
0x146768  mov      x8, #0x28cc
0x14676c  movk     x20, #0x5376, lsl #32
0x146770  movk     x21, #0x3378, lsl #32
0x146774  movk     x22, #0x740, lsl #16
0x146778  movk     x24, #0xc3e2, lsl #16
0x14677c  movk     x8, #0xc3e2, lsl #16
0x146780  movk     x20, #0x6aa9, lsl #48
0x146784  movk     x21, #0xeb0, lsl #48
0x146788  cmp      x0, #0
0x14678c  movk     x22, #0x67ad, lsl #32
0x146790  movk     x24, #0x7819, lsl #32
0x146794  movk     x8, #0x7819, lsl #32
0x146798  mov      x19, x0
0x14679c  movk     x22, #0xf79c, lsl #48
0x1467a0  csel     x23, x21, x20, eq
0x1467a4  movk     x24, #0x6b85, lsl #48
0x1467a8  movk     x8, #0x6b85, lsl #48
0x1467ac  cmp      x8, x22
0x1467b0  b.eq     #0x1467fc
0x1467b4  cmp      x8, x24
0x1467b8  b.eq     #0x1467d0
0x1467bc  cmp      x8, x20
0x1467c0  b.eq     #0x1467d8
0x1467c4  cmp      x8, x21
0x1467c8  b.ne     #0x1467ac
0x1467cc  b        #0x1467e8
0x1467d0  mov      x8, x23
0x1467d4  b        #0x1467ac
0x1467d8  ldr      x0, [x19, #8]
0x1467dc  bl       #0x14673c   ; -> None
0x1467e0  mov      x0, x19
0x1467e4  bl       #0x148a00   ; -> free
0x1467e8  mov      x8, #0x7811
0x1467ec  movk     x8, #0x740, lsl #16
0x1467f0  movk     x8, #0x67ad, lsl #32
0x1467f4  movk     x8, #0xf79c, lsl #48
0x1467f8  b        #0x1467ac
0x1467fc  ldp      x20, x19, [sp, #0x30]
0x146800  ldp      x22, x21, [sp, #0x20]
0x146804  ldp      x24, x23, [sp, #0x10]
0x146808  ldp      x29, x30, [sp], #0x40
0x14680c  ret      
0x146810  stp      x29, x30, [sp, #-0x40]!
0x146814  stp      x24, x23, [sp, #0x10]
0x146818  stp      x22, x21, [sp, #0x20]
0x14681c  stp      x20, x19, [sp, #0x30]
0x146820  mov      x29, sp
0x146824  mov      x20, #0xd282
0x146828  mov      x21, #0x9bd
0x14682c  movk     x20, #0x957d, lsl #16
0x146830  movk     x21, #0xb5f6, lsl #16
0x146834  mov      x22, #0x8a0
0x146838  mov      x24, #0x113f
0x14683c  mov      x8, #0x113f
0x146840  movk     x20, #0xadd, lsl #32
0x146844  movk     x21, #0xce8f, lsl #32
0x146848  movk     x22, #0xbd15, lsl #16
0x14684c  movk     x24, #0xceaf, lsl #16
0x146850  movk     x8, #0xceaf, lsl #16
0x146854  movk     x20, #0x549f, lsl #48
0x146858  movk     x21, #0x62d5, lsl #48
0x14685c  cmp      x0, #0
0x146860  movk     x22, #0xb02c, lsl #32
0x146864  movk     x24, #0x4fe6, lsl #32
0x146868  movk     x8, #0x4fe6, lsl #32
0x14686c  mov      x19, x0
0x146870  movk     x22, #0x93e7, lsl #48
0x146874  csel     x23, x21, x20, eq
0x146878  movk     x24, #0xe9ff, lsl #48
0x14687c  movk     x8, #0xe9ff, lsl #48
0x146880  cmp      x8, x22
0x146884  b.eq     #0x1468d0
0x146888  cmp      x8, x24
0x14688c  b.eq     #0x1468a4
0x146890  cmp      x8, x20
0x146894  b.eq     #0x1468ac
0x146898  cmp      x8, x21
0x14689c  b.ne     #0x146880
0x1468a0  b        #0x1468bc
0x1468a4  mov      x8, x23
0x1468a8  b        #0x146880
0x1468ac  ldr      x0, [x19]
0x1468b0  bl       #0x14673c   ; -> None
0x1468b4  mov      x0, x19
0x1468b8  bl       #0x148a00   ; -> free
0x1468bc  mov      x8, #0x8a0
0x1468c0  movk     x8, #0xbd15, lsl #16
0x1468c4  movk     x8, #0xb02c, lsl #32
0x1468c8  movk     x8, #0x93e7, lsl #48
0x1468cc  b        #0x146880
0x1468d0  ldp      x20, x19, [sp, #0x30]
0x1468d4  ldp      x22, x21, [sp, #0x20]
0x1468d8  ldp      x24, x23, [sp, #0x10]
0x1468dc  ldp      x29, x30, [sp], #0x40
0x1468e0  ret      
0x1468e4  sub      sp, sp, #0x80
0x1468e8  stp      x29, x30, [sp, #0x20]
0x1468ec  stp      x28, x27, [sp, #0x30]
0x1468f0  stp      x26, x25, [sp, #0x40]
0x1468f4  stp      x24, x23, [sp, #0x50]
0x1468f8  stp      x22, x21, [sp, #0x60]
0x1468fc  stp      x20, x19, [sp, #0x70]
0x146900  add      x29, sp, #0x20
0x146904  mov      w21, w1
0x146908  str      x0, [sp, #0x10]
0x14690c  mov      x24, #0xdf4a
0x146910  mov      w0, #1
0x146914  mov      w1, #0x20
0x146918  movk     x24, #0xbdc8, lsl #16
0x14691c  movk     x24, #0xceb, lsl #32
0x146920  movk     x24, #0xc8d5, lsl #48
0x146924  bl       #0x148b90   ; -> calloc
0x146928  neg      w8, w21
0x14692c  mov      x28, #0xa74a
0x146930  and      w8, w8, #0x7f
0x146934  mov      x26, #0x5dae
0x146938  movk     x28, #0x5ea3, lsl #16
0x14693c  add      w8, w8, w21
0x146940  movk     x26, #0xbd6e, lsl #16
0x146944  mov      x19, #0xb7cc
0x146948  mov      x25, #0xc335
0x14694c  mov      x21, #0x9a1f
0x146950  mov      x27, #0xd2d1
0x146954  mov      x9, #0x8e81
0x146958  movk     x28, #0xa04f, lsl #32
0x14695c  movk     x26, #0x6aaa, lsl #32
0x146960  movk     x19, #0xff64, lsl #16
0x146964  movk     x25, #0x1484, lsl #16
0x146968  movk     x21, #0xd6a5, lsl #16
0x14696c  movk     x27, #0xf825, lsl #16
0x146970  movk     x9, #0xe154, lsl #16
0x146974  cmp      x0, #0
0x146978  movk     x28, #0xfa1e, lsl #48
0x14697c  movk     x26, #0x28f0, lsl #48
0x146980  movk     x19, #0xf23e, lsl #32
0x146984  movk     x25, #0x16b3, lsl #32
0x146988  movk     x21, #0xc885, lsl #32
0x14698c  movk     x27, #0xee0c, lsl #32
0x146990  movk     x9, #0x3b5e, lsl #32
0x146994  mov      x20, x0
0x146998  str      x8, [sp, #8]
0x14699c  csel     x8, x26, x28, eq
0x1469a0  movk     x19, #0x8f3d, lsl #48
0x1469a4  movk     x25, #0xb3cc, lsl #48
0x1469a8  movk     x21, #0xf611, lsl #48
0x1469ac  movk     x27, #0x5c23, lsl #48
0x1469b0  movk     x9, #0x7cc5, lsl #48
0x1469b4  stur     x8, [x29, #-8]
0x1469b8  mov      x23, x1
0x1469bc  cmp      x9, x19
0x1469c0  b.eq     #0x146a90
0x1469c4  mov      x8, x9
0x1469c8  mov      x9, #0x3581
0x1469cc  movk     x9, #0xbcba, lsl #16
0x1469d0  mov      x1, x20
0x1469d4  movk     x9, #0x133, lsl #32
0x1469d8  cmp      x8, x25
0x1469dc  movk     x9, #0x761f, lsl #48
0x1469e0  b.eq     #0x1469b8
0x1469e4  cmp      x8, x24
0x1469e8  b.eq     #0x146ab0
0x1469ec  cmp      x8, x21
0x1469f0  b.eq     #0x146ad0
0x1469f4  cmp      x8, x28
0x1469f8  b.eq     #0x146af8
0x1469fc  mov      x9, #0x7515
0x146a00  mov      x1, x23
0x146a04  movk     x9, #0xb217, lsl #16
0x146a08  cmp      x8, x26
0x146a0c  movk     x9, #0xdfc8, lsl #32
0x146a10  movk     x9, #0x768a, lsl #48
0x146a14  b.eq     #0x1469b8
0x146a18  mov      x9, #0xdf4a
0x146a1c  mov      x1, x23
0x146a20  movk     x9, #0xbdc8, lsl #16
0x146a24  cmp      x8, x27
0x146a28  movk     x9, #0xceb, lsl #32
0x146a2c  movk     x9, #0xc8d5, lsl #48
0x146a30  b.eq     #0x1469b8
0x146a34  mov      x9, #0x7515
0x146a38  movk     x9, #0xb217, lsl #16
0x146a3c  movk     x9, #0xdfc8, lsl #32
0x146a40  movk     x9, #0x768a, lsl #48
0x146a44  cmp      x8, x9
0x146a48  b.eq     #0x146b20
0x146a4c  mov      x10, #0x8e81
0x146a50  mov      x1, x23
0x146a54  movk     x10, #0xe154, lsl #16
0x146a58  ldur     x9, [x29, #-8]
0x146a5c  movk     x10, #0x3b5e, lsl #32
0x146a60  movk     x10, #0x7cc5, lsl #48
0x146a64  cmp      x8, x10
0x146a68  b.eq     #0x1469b8
0x146a6c  mov      x10, #0x3581
0x146a70  mov      x1, x23
0x146a74  movk     x10, #0xbcba, lsl #16
0x146a78  mov      x9, x8
0x146a7c  movk     x10, #0x133, lsl #32
0x146a80  movk     x10, #0x761f, lsl #48
0x146a84  cmp      x8, x10
0x146a88  b.ne     #0x1469b8
0x146a8c  b        #0x146b44
0x146a90  mov      x0, x22
0x146a94  bl       #0x148a00   ; -> free
0x146a98  mov      x9, #0xdf4a
0x146a9c  mov      x1, x23
0x146aa0  movk     x9, #0xbdc8, lsl #16
0x146aa4  movk     x9, #0xceb, lsl #32
0x146aa8  movk     x9, #0xc8d5, lsl #48
0x146aac  b        #0x1469b8
0x146ab0  mov      x0, x20
0x146ab4  bl       #0x148a00   ; -> free
0x146ab8  mov      x9, #0x7515
0x146abc  mov      x1, x23
0x146ac0  movk     x9, #0xb217, lsl #16
0x146ac4  movk     x9, #0xdfc8, lsl #32
0x146ac8  movk     x9, #0x768a, lsl #48
0x146acc  b        #0x1469b8
0x146ad0  mov      w8, #1
0x146ad4  mov      w0, #1
0x146ad8  mov      w1, #4
0x146adc  str      w8, [x20, #0x14]
0x146ae0  bl       #0x148b90   ; -> calloc
0x146ae4  cmp      x0, #0
0x146ae8  mov      x1, x23
0x146aec  csel     x9, x19, x25, eq
0x146af0  str      x0, [x20, #0x18]
0x146af4  b        #0x1469b8
0x146af8  ldr      x0, [sp, #8]
0x146afc  mov      w1, #4
0x146b00  str      w0, [x20]
0x146b04  bl       #0x148b90   ; -> calloc
0x146b08  cmp      x0, #0
0x146b0c  mov      x22, x0
0x146b10  mov      x1, x23
0x146b14  csel     x9, x27, x21, eq
0x146b18  str      x0, [x20, #8]
0x146b1c  b        #0x1469b8
0x146b20  mov      x9, #0x3581
0x146b24  ldr      x8, [sp, #0x10]
0x146b28  mov      w10, #2
0x146b2c  movk     x9, #0xbcba, lsl #16
0x146b30  movk     x9, #0x133, lsl #32
0x146b34  mov      x1, xzr
0x146b38  movk     x9, #0x761f, lsl #48
0x146b3c  str      w10, [x8]
0x146b40  b        #0x1469b8
0x146b44  mov      x0, x23
0x146b48  ldp      x20, x19, [sp, #0x70]
0x146b4c  ldp      x22, x21, [sp, #0x60]
0x146b50  ldp      x24, x23, [sp, #0x50]
0x146b54  ldp      x26, x25, [sp, #0x40]
0x146b58  ldp      x28, x27, [sp, #0x30]
0x146b5c  ldp      x29, x30, [sp, #0x20]
0x146b60  add      sp, sp, #0x80
0x146b64  ret      
0x146b68  sub      sp, sp, #0x80
0x146b6c  stp      x29, x30, [sp, #0x20]
0x146b70  stp      x28, x27, [sp, #0x30]
0x146b74  stp      x26, x25, [sp, #0x40]
0x146b78  stp      x24, x23, [sp, #0x50]
0x146b7c  stp      x22, x21, [sp, #0x60]
0x146b80  stp      x20, x19, [sp, #0x70]
0x146b84  add      x29, sp, #0x20
0x146b88  mov      x11, #0x8779
0x146b8c  mov      x12, #0x7811
0x146b90  lsr      w8, w3, #2
0x146b94  movk     x11, #0xf1b8, lsl #16
0x146b98  movk     x12, #0x740, lsl #16
0x146b9c  movk     x11, #0x3378, lsl #32
0x146ba0  movk     x12, #0x67ad, lsl #32
0x146ba4  tst      w3, #3
0x146ba8  movk     x11, #0xeb0, lsl #48
0x146bac  movk     x12, #0xf79c, lsl #48
0x146bb0  mov      x14, #0x28cc
0x146bb4  mov      x27, #0xafb5
0x146bb8  mov      x24, #0x507b
0x146bbc  mov      x25, #0x8a0
0x146bc0  stp      w8, w2, [sp, #8]
0x146bc4  csel     x20, x12, x11, eq
0x146bc8  cmp      w3, #0
0x146bcc  movk     x14, #0xc3e2, lsl #16
0x146bd0  movk     x27, #0xa12b, lsl #16
0x146bd4  add      w8, w3, w2
0x146bd8  mov      x15, #0x2f9c
0x146bdc  mov      x21, #0xd05b
0x146be0  mov      x16, #0x7408
0x146be4  mov      x22, #0x113f
0x146be8  mov      x17, #0x9bd
0x146bec  mov      x2, #0xd282
0x146bf0  mov      x3, #0xee15
0x146bf4  mov      x9, #0x2f9c
0x146bf8  movk     x24, #0x2c50, lsl #16
0x146bfc  movk     x25, #0xbd15, lsl #16
0x146c00  movk     x14, #0x7819, lsl #32
0x146c04  movk     x27, #0xce93, lsl #32
0x146c08  movk     x15, #0xc396, lsl #16
0x146c0c  movk     x21, #0xef20, lsl #16
0x146c10  movk     x16, #0x4e14, lsl #16
0x146c14  movk     x22, #0xceaf, lsl #16
0x146c18  movk     x17, #0xb5f6, lsl #16
0x146c1c  movk     x2, #0x957d, lsl #16
0x146c20  movk     x3, #0x1fe1, lsl #16
0x146c24  movk     x9, #0xc396, lsl #16
0x146c28  movk     x24, #0x48ac, lsl #32
0x146c2c  movk     x25, #0xb02c, lsl #32
0x146c30  movk     x14, #0x6b85, lsl #48
0x146c34  movk     x27, #0xb225, lsl #48
0x146c38  movk     x15, #0x5e8f, lsl #32
0x146c3c  movk     x21, #0x96cc, lsl #32
0x146c40  movk     x16, #0x43cd, lsl #32
0x146c44  movk     x22, #0x4fe6, lsl #32
0x146c48  movk     x17, #0xce8f, lsl #32
0x146c4c  movk     x2, #0xadd, lsl #32
0x146c50  movk     x3, #0x5376, lsl #32
0x146c54  movk     x9, #0x5e8f, lsl #32
0x146c58  mov      x26, x1
0x146c5c  mov      x19, x0
0x146c60  movk     x24, #0xc90b, lsl #48
0x146c64  movk     x25, #0x93e7, lsl #48
0x146c68  csel     x23, x27, x14, eq
0x146c6c  str      w8, [sp, #4]
0x146c70  sub      w8, w8, #1
0x146c74  movk     x15, #0xf2cd, lsl #48
0x146c78  movk     x21, #0x8753, lsl #48
0x146c7c  movk     x16, #0x7f74, lsl #48
0x146c80  movk     x22, #0xe9ff, lsl #48
0x146c84  movk     x17, #0x62d5, lsl #48
0x146c88  movk     x2, #0x549f, lsl #48
0x146c8c  movk     x3, #0x6aa9, lsl #48
0x146c90  movk     x9, #0xf2cd, lsl #48
0x146c94  str      x4, [sp, #0x10]
0x146c98  str      w8, [sp]
0x146c9c  cmp      x9, x21
0x146ca0  b.eq     #0x146d80
0x146ca4  mov      x8, x9
0x146ca8  cmp      x9, x25
0x146cac  b.eq     #0x146db8
0x146cb0  mov      x9, #0x1859
0x146cb4  cmp      x8, x27
0x146cb8  movk     x9, #0x2b53, lsl #16
0x146cbc  movk     x9, #0x6ffc, lsl #32
0x146cc0  movk     x9, #0x930b, lsl #48
0x146cc4  b.eq     #0x146c9c
0x146cc8  cmp      x8, x24
0x146ccc  b.eq     #0x146dd0
0x146cd0  cmp      x8, x22
0x146cd4  b.eq     #0x146de4
0x146cd8  mov      x9, x23
0x146cdc  cmp      x8, x15
0x146ce0  b.eq     #0x146c9c
0x146ce4  cmp      x8, x12
0x146ce8  b.eq     #0x146e88
0x146cec  cmp      x8, x11
0x146cf0  b.eq     #0x146e9c
0x146cf4  mov      x9, #0x8a0
0x146cf8  cmp      x8, x2
0x146cfc  movk     x9, #0xbd15, lsl #16
0x146d00  movk     x9, #0xb02c, lsl #32
0x146d04  movk     x9, #0x93e7, lsl #48
0x146d08  b.eq     #0x146c9c
0x146d0c  mov      x9, #0x1859
0x146d10  cmp      x8, x17
0x146d14  movk     x9, #0x2b53, lsl #16
0x146d18  movk     x9, #0x6ffc, lsl #32
0x146d1c  movk     x9, #0x930b, lsl #48
0x146d20  b.eq     #0x146c9c
0x146d24  mov      x9, #0x8a0
0x146d28  cmp      x8, x3
0x146d2c  movk     x9, #0xbd15, lsl #16
0x146d30  movk     x9, #0xb02c, lsl #32
0x146d34  movk     x9, #0x93e7, lsl #48
0x146d38  b.eq     #0x146c9c
0x146d3c  mov      x9, x20
0x146d40  cmp      x8, x14
0x146d44  b.eq     #0x146c9c
0x146d48  mov      x9, #0x1859
0x146d4c  cmp      x8, x16
0x146d50  movk     x9, #0x2b53, lsl #16
0x146d54  movk     x9, #0x6ffc, lsl #32
0x146d58  movk     x9, #0x930b, lsl #48
0x146d5c  b.eq     #0x146c9c
0x146d60  mov      x10, #0x1859
0x146d64  mov      x9, x8
0x146d68  movk     x10, #0x2b53, lsl #16
0x146d6c  movk     x10, #0x6ffc, lsl #32
0x146d70  movk     x10, #0x930b, lsl #48
0x146d74  cmp      x8, x10
0x146d78  b.ne     #0x146c9c
0x146d7c  b        #0x146eb8
0x146d80  ldr      w8, [sp, #0xc]
0x146d84  ldur     w4, [x29, #-4]
0x146d88  ldr      x9, [x26, #8]
0x146d8c  ldr      x10, [sp, #0x10]
0x146d90  add      w8, w4, w8
0x146d94  add      w28, w4, #1
0x146d98  ldr      w8, [x9, w8, uxtw #2]
0x146d9c  mov      x9, #0x507b
0x146da0  movk     x9, #0x2c50, lsl #16
0x146da4  movk     x9, #0x48ac, lsl #32
0x146da8  movk     x9, #0xc90b, lsl #48
0x146dac  rev      w8, w8
0x146db0  str      w8, [x10, w4, uxtw #2]
0x146db4  b        #0x146c9c
0x146db8  mov      x9, #0x507b
0x146dbc  mov      w28, wzr
0x146dc0  movk     x9, #0x2c50, lsl #16
0x146dc4  movk     x9, #0x48ac, lsl #32
0x146dc8  movk     x9, #0xc90b, lsl #48
0x146dcc  b        #0x146c9c
0x146dd0  ldr      w8, [sp, #8]
0x146dd4  stur     w28, [x29, #-4]
0x146dd8  cmp      w8, w28
0x146ddc  csel     x9, x21, x16, hi
0x146de0  b        #0x146c9c
0x146de4  mov      x0, x19
0x146de8  mov      x1, x26
0x146dec  ldr      w2, [sp]
0x146df0  mov      w3, wzr
0x146df4  bl       #0x146ed8   ; -> None
0x146df8  mov      x2, #0xd282
0x146dfc  mov      x17, #0x9bd
0x146e00  ldr      w8, [x19]
0x146e04  mov      x3, #0xee15
0x146e08  movk     x2, #0x957d, lsl #16
0x146e0c  movk     x17, #0xb5f6, lsl #16
0x146e10  mov      x16, #0x7408
0x146e14  mov      x15, #0x2f9c
0x146e18  mov      x14, #0x28cc
0x146e1c  mov      x12, #0x7811
0x146e20  mov      x11, #0x8779
0x146e24  movk     x3, #0x1fe1, lsl #16
0x146e28  movk     x2, #0xadd, lsl #32
0x146e2c  movk     x17, #0xce8f, lsl #32
0x146e30  movk     x16, #0x4e14, lsl #16
0x146e34  movk     x15, #0xc396, lsl #16
0x146e38  movk     x14, #0xc3e2, lsl #16
0x146e3c  movk     x12, #0x740, lsl #16
0x146e40  movk     x11, #0xf1b8, lsl #16
0x146e44  movk     x3, #0x5376, lsl #32
0x146e48  movk     x2, #0x549f, lsl #48
0x146e4c  movk     x17, #0x62d5, lsl #48
0x146e50  movk     x16, #0x43cd, lsl #32
0x146e54  movk     x15, #0x5e8f, lsl #32
0x146e58  movk     x14, #0x7819, lsl #32
0x146e5c  movk     x12, #0x67ad, lsl #32
0x146e60  movk     x11, #0x3378, lsl #32
0x146e64  cmp      w8, #0
0x146e68  movk     x3, #0x6aa9, lsl #48
0x146e6c  movk     x16, #0x7f74, lsl #48
0x146e70  movk     x15, #0xf2cd, lsl #48
0x146e74  movk     x14, #0x6b85, lsl #48
0x146e78  movk     x12, #0xf79c, lsl #48
0x146e7c  movk     x11, #0xeb0, lsl #48
0x146e80  csel     x9, x2, x17, eq
0x146e84  b        #0x146c9c
0x146e88  ldr      w8, [x26]
0x146e8c  ldr      w9, [sp, #4]
0x146e90  cmp      w8, w9
0x146e94  csel     x9, x22, x3, lo
0x146e98  b        #0x146c9c
0x146e9c  mov      x9, #0x1859
0x146ea0  mov      w8, #6
0x146ea4  movk     x9, #0x2b53, lsl #16
0x146ea8  movk     x9, #0x6ffc, lsl #32
0x146eac  movk     x9, #0x930b, lsl #48
0x146eb0  str      w8, [x19]
0x146eb4  b        #0x146c9c
0x146eb8  ldp      x20, x19, [sp, #0x70]
0x146ebc  ldp      x22, x21, [sp, #0x60]
0x146ec0  ldp      x24, x23, [sp, #0x50]
0x146ec4  ldp      x26, x25, [sp, #0x40]
0x146ec8  ldp      x28, x27, [sp, #0x30]
0x146ecc  ldp      x29, x30, [sp, #0x20]
0x146ed0  add      sp, sp, #0x80
0x146ed4  ret      
0x146ed8  sub      sp, sp, #0x80
0x146edc  stp      x29, x30, [sp, #0x20]
0x146ee0  stp      x28, x27, [sp, #0x30]
0x146ee4  stp      x26, x25, [sp, #0x40]
0x146ee8  stp      x24, x23, [sp, #0x50]
0x146eec  stp      x22, x21, [sp, #0x60]
0x146ef0  stp      x20, x19, [sp, #0x70]
0x146ef4  add      x29, sp, #0x20
0x146ef8  mov      x11, #0x5cb8
0x146efc  mov      x26, #0x1dac
0x146f00  mov      x28, #0x1381
0x146f04  mov      x24, #0x25ce
0x146f08  mov      x19, #0x4c0d
0x146f0c  mov      x12, #0x6436
0x146f10  mov      x22, #0xb3d0
0x146f14  mov      x25, #0xb031
0x146f18  mov      x9, #0x1dac
0x146f1c  movk     x11, #0x2795, lsl #16
0x146f20  movk     x26, #0x9f5e, lsl #16
0x146f24  movk     x28, #0xa58a, lsl #16
0x146f28  movk     x24, #0x8c3e, lsl #16
0x146f2c  movk     x19, #0x52dd, lsl #16
0x146f30  movk     x12, #0x2869, lsl #16
0x146f34  movk     x22, #0x566, lsl #16
0x146f38  movk     x25, #0x9cc1, lsl #16
0x146f3c  movk     x9, #0x9f5e, lsl #16
0x146f40  movk     x11, #0x15f4, lsl #32
0x146f44  movk     x26, #0xb762, lsl #32
0x146f48  movk     x28, #0xb763, lsl #32
0x146f4c  movk     x24, #0xdec2, lsl #32
0x146f50  movk     x19, #0x7dcf, lsl #32
0x146f54  movk     x12, #0xc5df, lsl #32
0x146f58  movk     x22, #0xa50d, lsl #32
0x146f5c  movk     x25, #0xffeb, lsl #32
0x146f60  movk     x9, #0xb762, lsl #32
0x146f64  mov      x21, x1
0x146f68  movk     x11, #0x77a4, lsl #48
0x146f6c  movk     x26, #0x3b4a, lsl #48
0x146f70  ldr      w27, [x1]
0x146f74  movk     x28, #0xbbcd, lsl #48
0x146f78  movk     x24, #0xf201, lsl #48
0x146f7c  movk     x19, #0x48fe, lsl #48
0x146f80  movk     x12, #0x56de, lsl #48
0x146f84  movk     x22, #0x204a, lsl #48
0x146f88  movk     x25, #0x2516, lsl #48
0x146f8c  movk     x9, #0x3b4a, lsl #48
0x146f90  stp      w2, w3, [x29, #-0xc]
0x146f94  str      x0, [sp, #8]
0x146f98  cmp      x9, x28
0x146f9c  b.eq     #0x14701c
0x146fa0  mov      x8, x9
0x146fa4  cmp      x9, x24
0x146fa8  b.eq     #0x14703c
0x146fac  cmp      x8, x22
0x146fb0  b.eq     #0x147054
0x146fb4  cmp      x8, x25
0x146fb8  b.eq     #0x147074
0x146fbc  mov      x9, #0x5cb8
0x146fc0  cmp      x8, x26
0x146fc4  movk     x9, #0x2795, lsl #16
0x146fc8  movk     x9, #0x15f4, lsl #32
0x146fcc  movk     x9, #0x77a4, lsl #48
0x146fd0  b.eq     #0x146f98
0x146fd4  cmp      x8, x19
0x146fd8  b.eq     #0x1470b8
0x146fdc  mov      x9, #0xe386
0x146fe0  cmp      x8, x12
0x146fe4  movk     x9, #0xeab8, lsl #16
0x146fe8  movk     x9, #0xc1ec, lsl #32
0x146fec  movk     x9, #0x808f, lsl #48
0x146ff0  b.eq     #0x146f98
0x146ff4  cmp      x8, x11
0x146ff8  b.eq     #0x1470d4
0x146ffc  mov      x10, #0xe386
0x147000  mov      x9, x8
0x147004  movk     x10, #0xeab8, lsl #16
0x147008  movk     x10, #0xc1ec, lsl #32
0x14700c  movk     x10, #0x808f, lsl #48
0x147010  cmp      x8, x10
0x147014  b.ne     #0x146f98
0x147018  b        #0x147100
0x14701c  ldr      w8, [x21]
0x147020  mov      x9, #0x5cb8
0x147024  movk     x9, #0x2795, lsl #16
0x147028  movk     x9, #0x15f4, lsl #32
0x14702c  add      w27, w8, #0x80
0x147030  movk     x9, #0x77a4, lsl #48
0x147034  str      w27, [x21]
0x147038  b        #0x146f98
0x14703c  ldur     w8, [x29, #-8]
0x147040  str      w8, [x23, w20, uxtw #2]
0x147044  ldr      w8, [x21, #0x10]
0x147048  cmp      w8, w20
0x14704c  csel     x9, x12, x19, hi
0x147050  b        #0x146f98
0x147054  mov      x9, #0xe386
0x147058  ldr      x8, [sp, #8]
0x14705c  mov      w10, #2
0x147060  movk     x9, #0xeab8, lsl #16
0x147064  movk     x9, #0xc1ec, lsl #32
0x147068  movk     x9, #0x808f, lsl #48
0x14706c  str      w10, [x8]
0x147070  b        #0x146f98
0x147074  ldur     w8, [x29, #-4]
0x147078  mov      x0, x23
0x14707c  add      w8, w8, #0x80
0x147080  ubfiz    x1, x8, #2, #0x20
0x147084  bl       #0x148c80   ; -> realloc
0x147088  mov      x12, #0x6436
0x14708c  mov      x11, #0x5cb8
0x147090  movk     x12, #0x2869, lsl #16
0x147094  movk     x11, #0x2795, lsl #16
0x147098  movk     x12, #0xc5df, lsl #32
0x14709c  movk     x11, #0x15f4, lsl #32
0x1470a0  cmp      x0, #0
0x1470a4  movk     x12, #0x56de, lsl #48
0x1470a8  movk     x11, #0x77a4, lsl #48
0x1470ac  csel     x9, x22, x28, eq
0x1470b0  str      x0, [x21, #8]
0x1470b4  b        #0x146f98
0x1470b8  add      w8, w20, #1
0x1470bc  mov      x9, #0xe386
0x1470c0  movk     x9, #0xeab8, lsl #16
0x1470c4  movk     x9, #0xc1ec, lsl #32
0x1470c8  movk     x9, #0x808f, lsl #48
0x1470cc  str      w8, [x21, #0x10]
0x1470d0  b        #0x146f98
0x1470d4  ldr      w8, [x21, #0x14]
0x1470d8  stur     w27, [x29, #-4]
0x1470dc  ldr      x9, [x21, #0x18]
0x1470e0  ldr      x23, [x21, #8]
0x1470e4  sub      w8, w8, #1
0x1470e8  ldr      w8, [x9, w8, uxtw #2]
0x1470ec  ldur     w9, [x29, #-0xc]
0x1470f0  add      w20, w8, w9
0x1470f4  cmp      w20, w27
0x1470f8  csel     x9, x24, x25, lo
0x1470fc  b        #0x146f98
0x147100  ldp      x20, x19, [sp, #0x70]
0x147104  ldp      x22, x21, [sp, #0x60]
0x147108  ldp      x24, x23, [sp, #0x50]
0x14710c  ldp      x26, x25, [sp, #0x40]
0x147110  ldp      x28, x27, [sp, #0x30]
0x147114  ldp      x29, x30, [sp, #0x20]
0x147118  add      sp, sp, #0x80
0x14711c  ret      
0x147120  stp      x29, x30, [sp, #-0x30]!
0x147124  str      x21, [sp, #0x10]
0x147128  stp      x20, x19, [sp, #0x20]
0x14712c  mov      x29, sp
0x147130  ldr      w8, [x1, #0x14]
0x147134  mov      x19, x1
0x147138  mov      x20, x0
0x14713c  mov      x21, #0x8d87
0x147140  ldr      x0, [x1, #0x18]
0x147144  movk     x21, #0xa2f3, lsl #16
0x147148  add      w8, w8, #1
0x14714c  movk     x21, #0x8648, lsl #32
0x147150  ubfiz    x1, x8, #2, #0x20
0x147154  movk     x21, #0xa5e3, lsl #48
0x147158  bl       #0x148c80   ; -> realloc
0x14715c  mov      x8, #0x865
0x147160  mov      x9, #0xcdf8
0x147164  movk     x8, #0x5362, lsl #16
0x147168  movk     x9, #0xd72b, lsl #16
0x14716c  mov      x10, #0xc2a2
0x147170  mov      x13, #0xc2a2
0x147174  movk     x8, #0x98ea, lsl #32
0x147178  movk     x9, #0x55aa, lsl #32
0x14717c  movk     x10, #0x1048, lsl #16
0x147180  movk     x13, #0x1048, lsl #16
0x147184  movk     x8, #0xabfd, lsl #48
0x147188  movk     x9, #0xfe6b, lsl #48
0x14718c  cmp      x0, #0
0x147190  movk     x10, #0x7104, lsl #32
0x147194  movk     x13, #0x7104, lsl #32
0x147198  movk     x10, #0x9ffe, lsl #48
0x14719c  csel     x11, x9, x8, eq
0x1471a0  mov      w12, #2
0x1471a4  movk     x13, #0x9ffe, lsl #48
0x1471a8  cmp      x13, x10
0x1471ac  b.eq     #0x1471e0
0x1471b0  cmp      x13, x21
0x1471b4  b.eq     #0x147210
0x1471b8  cmp      x13, x8
0x1471bc  b.eq     #0x1471e8
0x1471c0  cmp      x13, x9
0x1471c4  b.ne     #0x1471a8
0x1471c8  mov      x13, #0x8d87
0x1471cc  str      w12, [x20]
0x1471d0  movk     x13, #0xa2f3, lsl #16
0x1471d4  movk     x13, #0x8648, lsl #32
0x1471d8  movk     x13, #0xa5e3, lsl #48
0x1471dc  b        #0x1471a8
0x1471e0  mov      x13, x11
0x1471e4  b        #0x1471a8
0x1471e8  ldp      w15, w14, [x19, #0x10]
0x1471ec  mov      x13, #0x8d87
0x1471f0  str      x0, [x19, #0x18]
0x1471f4  movk     x13, #0xa2f3, lsl #16
0x1471f8  movk     x13, #0x8648, lsl #32
0x1471fc  add      w16, w14, #1
0x147200  movk     x13, #0xa5e3, lsl #48
0x147204  str      w15, [x0, x14, lsl #2]
0x147208  str      w16, [x19, #0x14]
0x14720c  b        #0x1471a8
0x147210  ldp      x20, x19, [sp, #0x20]
0x147214  ldr      x21, [sp, #0x10]
0x147218  ldp      x29, x30, [sp], #0x30
0x14721c  ret      
0x147220  ldr      w12, [x1, #0x14]
0x147224  mov      x9, #0x92
0x147228  mov      x10, #0xcd53
0x14722c  mov      x8, #0x1471
0x147230  movk     x9, #0x16d6, lsl #16
0x147234  movk     x10, #0xade6, lsl #16
0x147238  mov      x11, #0xea12
0x14723c  mov      x15, #0xea12
0x147240  movk     x8, #0x4a0, lsl #16
0x147244  movk     x9, #0x9d06, lsl #32
0x147248  movk     x10, #0xefff, lsl #32
0x14724c  movk     x11, #0x2ac8, lsl #16
0x147250  movk     x15, #0x2ac8, lsl #16
0x147254  movk     x8, #0x5fd, lsl #32
0x147258  movk     x9, #0x2680, lsl #48
0x14725c  movk     x10, #0x13d4, lsl #48
0x147260  movk     x11, #0x1d60, lsl #32
0x147264  cmp      w12, #0
0x147268  movk     x15, #0x1d60, lsl #32
0x14726c  movk     x8, #0xa11a, lsl #48
0x147270  movk     x11, #0x1023, lsl #48
0x147274  sub      w12, w12, #1
0x147278  csel     x13, x10, x9, eq
0x14727c  mov      w14, #7
0x147280  movk     x15, #0x1023, lsl #48
0x147284  cmp      x15, x8
0x147288  b.eq     #0x1472e4
0x14728c  cmp      x15, x11
0x147290  b.eq     #0x1472bc
0x147294  cmp      x15, x9
0x147298  b.eq     #0x1472c4
0x14729c  cmp      x15, x10
0x1472a0  b.ne     #0x147284
0x1472a4  mov      x15, #0x1471
0x1472a8  str      w14, [x0]
0x1472ac  movk     x15, #0x4a0, lsl #16
0x1472b0  movk     x15, #0x5fd, lsl #32
0x1472b4  movk     x15, #0xa11a, lsl #48
0x1472b8  b        #0x147284
0x1472bc  mov      x15, x13
0x1472c0  b        #0x147284
0x1472c4  ldr      x15, [x1, #0x18]
0x1472c8  ldr      w16, [x15, x12, lsl #2]
0x1472cc  mov      x15, #0x1471
0x1472d0  movk     x15, #0x4a0, lsl #16
0x1472d4  movk     x15, #0x5fd, lsl #32
0x1472d8  movk     x15, #0xa11a, lsl #48
0x1472dc  stp      w16, w12, [x1, #0x10]
0x1472e0  b        #0x147284
0x1472e4  ret      
0x1472e8  ldr      w8, [x0, #0x14]
0x1472ec  ldr      x9, [x0, #0x18]
0x1472f0  sub      w8, w8, #1
0x1472f4  ldr      w8, [x9, w8, uxtw #2]
0x1472f8  ldr      w9, [x0, #0x10]
0x1472fc  sub      w0, w9, w8
0x147300  ret      
0x147304  ldr      w8, [x0, #0x14]
0x147308  mov      x9, #0x6dbb
0x14730c  ldr      x10, [x0, #0x18]
0x147310  mov      x11, #0x1968
0x147314  ldr      w12, [x0]
0x147318  movk     x9, #0xc058, lsl #16
0x14731c  sub      w8, w8, #1
0x147320  movk     x11, #0x5932, lsl #16
0x147324  mov      x14, #0x7801
0x147328  mov      x15, #0x754
0x14732c  movk     x9, #0xf56d, lsl #32
0x147330  movk     x11, #0x8339, lsl #32
0x147334  ldr      w8, [x10, w8, uxtw #2]
0x147338  movk     x14, #0xa06d, lsl #16
0x14733c  movk     x15, #0xa078, lsl #16
0x147340  movk     x9, #0x7e88, lsl #48
0x147344  movk     x11, #0xb13, lsl #48
0x147348  movk     x14, #0xab5f, lsl #32
0x14734c  movk     x15, #0x1f94, lsl #32
0x147350  movk     x14, #0x22db, lsl #48
0x147354  add      w10, w8, w1
0x147358  movk     x15, #0x3282, lsl #48
0x14735c  cmp      w10, w12
0x147360  mov      x12, #0x754
0x147364  movk     x12, #0xa078, lsl #16
0x147368  csel     x13, x11, x9, lo
0x14736c  movk     x12, #0x1f94, lsl #32
0x147370  movk     x12, #0x3282, lsl #48
0x147374  cmp      x15, x9
0x147378  b.eq     #0x1473b0
0x14737c  cmp      x15, x14
0x147380  b.eq     #0x1473d0
0x147384  cmp      x15, x12
0x147388  b.eq     #0x1473c8
0x14738c  cmp      x15, x11
0x147390  b.ne     #0x147374
0x147394  ldr      x8, [x0, #8]
0x147398  mov      x15, #0x7801
0x14739c  movk     x15, #0xa06d, lsl #16
0x1473a0  ldr      w8, [x8, x10, lsl #2]
0x1473a4  movk     x15, #0xab5f, lsl #32
0x1473a8  movk     x15, #0x22db, lsl #48
0x1473ac  b        #0x147374
0x1473b0  mov      x15, #0x7801
0x1473b4  mov      w8, wzr
0x1473b8  movk     x15, #0xa06d, lsl #16
0x1473bc  movk     x15, #0xab5f, lsl #32
0x1473c0  movk     x15, #0x22db, lsl #48
0x1473c4  b        #0x147374
0x1473c8  mov      x15, x13
0x1473cc  b        #0x147374
0x1473d0  mov      w0, w8
0x1473d4  ret      
0x1473d8  stp      x29, x30, [sp, #-0x60]!
0x1473dc  stp      x28, x27, [sp, #0x10]
0x1473e0  stp      x26, x25, [sp, #0x20]
0x1473e4  stp      x24, x23, [sp, #0x30]
0x1473e8  stp      x22, x21, [sp, #0x40]
0x1473ec  stp      x20, x19, [sp, #0x50]
0x1473f0  mov      x29, sp
0x1473f4  mov      x22, #0xe11a
0x1473f8  mov      x23, #0x692
0x1473fc  mov      x21, #0x208d
0x147400  movk     x22, #0xe707, lsl #16
0x147404  movk     x23, #0x8807, lsl #16
0x147408  mov      x24, #0x259
0x14740c  mov      x26, #0xfe0a
0x147410  mov      x27, #0x8f9b
0x147414  mov      x28, #0x540b
0x147418  mov      x8, #0xfe0a
0x14741c  movk     x21, #0x44b3, lsl #16
0x147420  movk     x22, #0x5296, lsl #32
0x147424  movk     x23, #0xfbe3, lsl #32
0x147428  movk     x24, #0x6e2a, lsl #16
0x14742c  movk     x26, #0x69fd, lsl #16
0x147430  movk     x27, #0xc267, lsl #16
0x147434  movk     x28, #0x5e6a, lsl #16
0x147438  movk     x8, #0x69fd, lsl #16
0x14743c  movk     x21, #0xb99f, lsl #32
0x147440  movk     x22, #0x1df3, lsl #48
0x147444  cmp      x0, #0
0x147448  movk     x23, #0xa1b3, lsl #48
0x14744c  movk     x24, #0xc6cb, lsl #32
0x147450  movk     x26, #0x5f3a, lsl #32
0x147454  movk     x27, #0xf353, lsl #32
0x147458  movk     x28, #0x5fdc, lsl #32
0x14745c  movk     x8, #0x5f3a, lsl #32
0x147460  mov      x19, x0
0x147464  movk     x21, #0x3ef2, lsl #48
0x147468  movk     x24, #0x176e, lsl #48
0x14746c  csel     x25, x23, x22, eq
0x147470  movk     x26, #0xbdc7, lsl #48
0x147474  movk     x27, #0x853c, lsl #48
0x147478  movk     x28, #0x9974, lsl #48
0x14747c  movk     x8, #0xbdc7, lsl #48
0x147480  cmp      x8, x27
0x147484  b.eq     #0x1474bc
0x147488  cmp      x8, x28
0x14748c  b.eq     #0x1474dc
0x147490  cmp      x8, x21
0x147494  b.eq     #0x14752c
0x147498  cmp      x8, x26
0x14749c  b.eq     #0x1474f0
0x1474a0  cmp      x8, x24
0x1474a4  b.eq     #0x1474f8
0x1474a8  cmp      x8, x22
0x1474ac  b.eq     #0x14751c
0x1474b0  cmp      x8, x23
0x1474b4  b.ne     #0x147480
0x1474b8  b        #0x147508
0x1474bc  mov      x0, x20
0x1474c0  bl       #0x148a00   ; -> free
0x1474c4  mov      x8, #0x259
0x1474c8  str      xzr, [x19, #8]
0x1474cc  movk     x8, #0x6e2a, lsl #16
0x1474d0  movk     x8, #0xc6cb, lsl #32
0x1474d4  movk     x8, #0x176e, lsl #48
0x1474d8  b        #0x147480
0x1474dc  mov      x8, #0x259
0x1474e0  movk     x8, #0x6e2a, lsl #16
0x1474e4  movk     x8, #0xc6cb, lsl #32
0x1474e8  movk     x8, #0x176e, lsl #48
0x1474ec  b        #0x147480
0x1474f0  mov      x8, x25
0x1474f4  b        #0x147480
0x1474f8  ldr      x0, [x19, #0x18]
0x1474fc  bl       #0x148a00   ; -> free
0x147500  mov      x0, x19
0x147504  bl       #0x148a00   ; -> free
0x147508  mov      x8, #0x208d
0x14750c  movk     x8, #0x44b3, lsl #16
0x147510  movk     x8, #0xb99f, lsl #32
0x147514  movk     x8, #0x3ef2, lsl #48
0x147518  b        #0x147480
0x14751c  ldr      x20, [x19, #8]
0x147520  cmp      x20, #0
0x147524  csel     x8, x28, x27, eq
0x147528  b        #0x147480
0x14752c  ldp      x20, x19, [sp, #0x50]
0x147530  ldp      x22, x21, [sp, #0x40]
0x147534  ldp      x24, x23, [sp, #0x30]
0x147538  ldp      x26, x25, [sp, #0x20]
0x14753c  ldp      x28, x27, [sp, #0x10]
0x147540  ldp      x29, x30, [sp], #0x60
0x147544  ret      
0x147548  stp      x29, x30, [sp, #-0x20]!
0x14754c  stp      x20, x19, [sp, #0x10]
0x147550  mov      x29, sp
0x147554  mov      x19, x0
0x147558  mov      x20, #0xd2d1
0x14755c  mov      w0, #1
0x147560  mov      w1, #0x10
0x147564  movk     x20, #0xf825, lsl #16
0x147568  movk     x20, #0xee0c, lsl #32
0x14756c  movk     x20, #0x5c23, lsl #48
0x147570  bl       #0x148b90   ; -> calloc
0x147574  mov      x8, #0x5dae
0x147578  mov      x9, #0xa74a
0x14757c  movk     x8, #0xbd6e, lsl #16
0x147580  movk     x9, #0x5ea3, lsl #16
0x147584  mov      x10, #0x8e81
0x147588  mov      x13, #0x8e81
0x14758c  movk     x8, #0x6aaa, lsl #32
0x147590  movk     x9, #0xa04f, lsl #32
0x147594  movk     x10, #0xe154, lsl #16
0x147598  movk     x13, #0xe154, lsl #16
0x14759c  movk     x8, #0x28f0, lsl #48
0x1475a0  movk     x9, #0xfa1e, lsl #48
0x1475a4  cmp      x0, #0
0x1475a8  movk     x10, #0x3b5e, lsl #32
0x1475ac  movk     x13, #0x3b5e, lsl #32
0x1475b0  movk     x10, #0x7cc5, lsl #48
0x1475b4  csel     x11, x9, x8, eq
0x1475b8  mov      w12, #2
0x1475bc  movk     x13, #0x7cc5, lsl #48
0x1475c0  cmp      x13, x9
0x1475c4  b.eq     #0x1475f4
0x1475c8  cmp      x13, x10
0x1475cc  b.eq     #0x14760c
0x1475d0  cmp      x13, x20
0x1475d4  b.eq     #0x147614
0x1475d8  cmp      x13, x8
0x1475dc  b.ne     #0x1475c0
0x1475e0  mov      x13, #0xd2d1
0x1475e4  movk     x13, #0xf825, lsl #16
0x1475e8  movk     x13, #0xee0c, lsl #32
0x1475ec  movk     x13, #0x5c23, lsl #48
0x1475f0  b        #0x1475c0
0x1475f4  mov      x13, #0xd2d1
0x1475f8  str      w12, [x19]
0x1475fc  movk     x13, #0xf825, lsl #16
0x147600  movk     x13, #0xee0c, lsl #32
0x147604  movk     x13, #0x5c23, lsl #48
0x147608  b        #0x1475c0
0x14760c  mov      x13, x11
0x147610  b        #0x1475c0
0x147614  ldp      x20, x19, [sp, #0x10]
0x147618  ldp      x29, x30, [sp], #0x20
0x14761c  ret      
0x147620  ldr      w8, [x0]
0x147624  cmp      w8, #0
0x147628  cset     w0, eq
0x14762c  ret      
0x147630  stp      x29, x30, [sp, #-0x30]!
0x147634  stp      x22, x21, [sp, #0x10]
0x147638  stp      x20, x19, [sp, #0x20]
0x14763c  mov      x29, sp
0x147640  mov      x20, x1
0x147644  mov      x21, x0
0x147648  mov      x22, #0xdf4a
0x14764c  mov      w0, #1
0x147650  mov      w1, #0x10
0x147654  movk     x22, #0xbdc8, lsl #16
0x147658  movk     x22, #0xceb, lsl #32
0x14765c  mov      w19, w2
0x147660  movk     x22, #0xc8d5, lsl #48
0x147664  bl       #0x148b90   ; -> calloc
0x147668  mov      x8, #0xb7cc
0x14766c  mov      x9, #0xc335
0x147670  movk     x8, #0xff64, lsl #16
0x147674  movk     x9, #0x1484, lsl #16
0x147678  mov      x10, #0x9a1f
0x14767c  mov      x13, #0x9a1f
0x147680  movk     x8, #0xf23e, lsl #32
0x147684  movk     x9, #0x16b3, lsl #32
0x147688  movk     x10, #0xd6a5, lsl #16
0x14768c  movk     x13, #0xd6a5, lsl #16
0x147690  movk     x8, #0x8f3d, lsl #48
0x147694  movk     x9, #0xb3cc, lsl #48
0x147698  cmp      x0, #0
0x14769c  movk     x10, #0xc885, lsl #32
0x1476a0  movk     x13, #0xc885, lsl #32
0x1476a4  movk     x10, #0xf611, lsl #48
0x1476a8  csel     x11, x9, x8, eq
0x1476ac  mov      w12, #2
0x1476b0  movk     x13, #0xf611, lsl #48
0x1476b4  cmp      x13, x8
0x1476b8  b.eq     #0x1476ec
0x1476bc  cmp      x13, x10
0x1476c0  b.eq     #0x14771c
0x1476c4  cmp      x13, x22
0x1476c8  b.eq     #0x147724
0x1476cc  cmp      x13, x9
0x1476d0  b.ne     #0x1476b4
0x1476d4  mov      x13, #0xdf4a
0x1476d8  str      w12, [x21]
0x1476dc  movk     x13, #0xbdc8, lsl #16
0x1476e0  movk     x13, #0xceb, lsl #32
0x1476e4  movk     x13, #0xc8d5, lsl #48
0x1476e8  b        #0x1476b4
0x1476ec  ldr      w13, [x20]
0x1476f0  str      w19, [x0]
0x1476f4  ldr      x14, [x20, #8]
0x1476f8  str      x0, [x20, #8]
0x1476fc  add      w15, w13, #1
0x147700  mov      x13, #0xdf4a
0x147704  movk     x13, #0xbdc8, lsl #16
0x147708  str      x14, [x0, #8]
0x14770c  movk     x13, #0xceb, lsl #32
0x147710  movk     x13, #0xc8d5, lsl #48
0x147714  str      w15, [x20]
0x147718  b        #0x1476b4
0x14771c  mov      x13, x11
0x147720  b        #0x1476b4
0x147724  ldp      x20, x19, [sp, #0x20]
0x147728  ldp      x22, x21, [sp, #0x10]
0x14772c  ldp      x29, x30, [sp], #0x30
0x147730  ret      
0x147734  stp      x29, x30, [sp, #-0x60]!
0x147738  stp      x28, x27, [sp, #0x10]
0x14773c  stp      x26, x25, [sp, #0x20]
0x147740  stp      x24, x23, [sp, #0x30]
0x147744  stp      x22, x21, [sp, #0x40]
0x147748  stp      x20, x19, [sp, #0x50]
0x14774c  mov      x29, sp
0x147750  ldr      w8, [x1]
0x147754  mov      x22, #0x7811
0x147758  mov      x23, #0x8779
0x14775c  movk     x22, #0x740, lsl #16
0x147760  movk     x23, #0xf1b8, lsl #16
0x147764  mov      x24, #0x28cc
0x147768  mov      x25, #0xee15
0x14776c  cmp      w8, #0
0x147770  sub      w26, w8, #1
0x147774  mov      x8, #0x28cc
0x147778  movk     x22, #0x67ad, lsl #32
0x14777c  movk     x23, #0x3378, lsl #32
0x147780  movk     x24, #0xc3e2, lsl #16
0x147784  movk     x25, #0x1fe1, lsl #16
0x147788  movk     x8, #0xc3e2, lsl #16
0x14778c  movk     x22, #0xf79c, lsl #48
0x147790  movk     x23, #0xeb0, lsl #48
0x147794  movk     x24, #0x7819, lsl #32
0x147798  movk     x25, #0x5376, lsl #32
0x14779c  movk     x8, #0x7819, lsl #32
0x1477a0  mov      x19, x1
0x1477a4  mov      x20, x0
0x1477a8  movk     x24, #0x6b85, lsl #48
0x1477ac  movk     x25, #0x6aa9, lsl #48
0x1477b0  csel     x27, x23, x22, eq
0x1477b4  mov      w28, #3
0x1477b8  movk     x8, #0x6b85, lsl #48
0x1477bc  cmp      x8, x22
0x1477c0  b.eq     #0x1477f8
0x1477c4  cmp      x8, x24
0x1477c8  b.eq     #0x147824
0x1477cc  cmp      x8, x25
0x1477d0  b.eq     #0x14782c
0x1477d4  cmp      x8, x23
0x1477d8  b.ne     #0x1477bc
0x1477dc  mov      x8, #0xee15
0x1477e0  mov      w21, wzr
0x1477e4  movk     x8, #0x1fe1, lsl #16
0x1477e8  str      w28, [x20]
0x1477ec  movk     x8, #0x5376, lsl #32
0x1477f0  movk     x8, #0x6aa9, lsl #48
0x1477f4  b        #0x1477bc
0x1477f8  ldr      x0, [x19, #8]
0x1477fc  str      w26, [x19]
0x147800  ldr      x8, [x0, #8]
0x147804  ldr      w21, [x0]
0x147808  str      x8, [x19, #8]
0x14780c  bl       #0x148a00   ; -> free
0x147810  mov      x8, #0xee15
0x147814  movk     x8, #0x1fe1, lsl #16
0x147818  movk     x8, #0x5376, lsl #32
0x14781c  movk     x8, #0x6aa9, lsl #48
0x147820  b        #0x1477bc
0x147824  mov      x8, x27
0x147828  b        #0x1477bc
0x14782c  mov      w0, w21
0x147830  ldp      x20, x19, [sp, #0x50]
0x147834  ldp      x22, x21, [sp, #0x40]
0x147838  ldp      x24, x23, [sp, #0x30]
0x14783c  ldp      x26, x25, [sp, #0x20]
0x147840  ldp      x28, x27, [sp, #0x10]
0x147844  ldp      x29, x30, [sp], #0x60
0x147848  ret      
0x14784c  sub      sp, sp, #0xa0
0x147850  stp      x29, x30, [sp, #0x40]
0x147854  stp      x28, x27, [sp, #0x50]
0x147858  stp      x26, x25, [sp, #0x60]
0x14785c  stp      x24, x23, [sp, #0x70]
0x147860  stp      x22, x21, [sp, #0x80]
0x147864  stp      x20, x19, [sp, #0x90]
0x147868  add      x29, sp, #0x40
0x14786c  stur     x1, [x29, #-0x10]
0x147870  mov      x24, #0x9bd
0x147874  ldr      w8, [x1], #8
0x147878  mov      x25, #0xd282
0x14787c  movk     x24, #0xb5f6, lsl #16
0x147880  movk     x25, #0x957d, lsl #16
0x147884  movk     x24, #0xce8f, lsl #32
0x147888  movk     x25, #0xadd, lsl #32
0x14788c  movk     x24, #0x62d5, lsl #48
0x147890  movk     x25, #0x549f, lsl #48
0x147894  cmp      w8, w2
0x147898  csel     x8, x25, x24, hi
0x14789c  mov      x22, #0xd05b
0x1478a0  mov      x26, #0x113f
0x1478a4  mov      x27, #0x8a0
0x1478a8  mov      x28, #0x7408
0x1478ac  mov      x19, #0x507b
0x1478b0  str      x8, [sp, #0x20]
0x1478b4  mov      x8, #0x113f
0x1478b8  movk     x22, #0xef20, lsl #16
0x1478bc  movk     x26, #0xceaf, lsl #16
0x1478c0  movk     x27, #0xbd15, lsl #16
0x1478c4  movk     x28, #0x4e14, lsl #16
0x1478c8  movk     x19, #0x2c50, lsl #16
0x1478cc  movk     x8, #0xceaf, lsl #16
0x1478d0  movk     x22, #0x96cc, lsl #32
0x1478d4  movk     x26, #0x4fe6, lsl #32
0x1478d8  movk     x27, #0xb02c, lsl #32
0x1478dc  movk     x28, #0x43cd, lsl #32
0x1478e0  movk     x19, #0x48ac, lsl #32
0x1478e4  movk     x8, #0x4fe6, lsl #32
0x1478e8  mov      x23, x0
0x1478ec  movk     x22, #0x8753, lsl #48
0x1478f0  movk     x26, #0xe9ff, lsl #48
0x1478f4  movk     x27, #0x93e7, lsl #48
0x1478f8  movk     x28, #0x7f74, lsl #48
0x1478fc  movk     x19, #0xc90b, lsl #48
0x147900  movk     x8, #0xe9ff, lsl #48
0x147904  stur     x1, [x29, #-0x18]
0x147908  stur     w2, [x29, #-4]
0x14790c  add      x20, x21, #8
0x147910  add      w14, w12, #1
0x147914  cmp      x8, x22
0x147918  b.eq     #0x1479f8
0x14791c  cmp      x8, x27
0x147920  b.eq     #0x1479e4
0x147924  cmp      x8, x19
0x147928  b.eq     #0x147968
0x14792c  cmp      x8, x26
0x147930  b.eq     #0x1479a4
0x147934  cmp      x8, x25
0x147938  b.eq     #0x1479c8
0x14793c  cmp      x8, x28
0x147940  b.eq     #0x1479ac
0x147944  cmp      x8, x24
0x147948  b.ne     #0x147914
0x14794c  mov      x8, #0xd05b
0x147950  mov      w9, #4
0x147954  movk     x8, #0xef20, lsl #16
0x147958  movk     x8, #0x96cc, lsl #32
0x14795c  movk     x8, #0x8753, lsl #48
0x147960  str      w9, [x23]
0x147964  b        #0x147914
0x147968  ldr      w2, [x21]
0x14796c  mov      x0, x23
0x147970  ldur     x1, [x29, #-0x10]
0x147974  str      x10, [sp, #0x10]
0x147978  str      w12, [sp, #0x1c]
0x14797c  str      w14, [sp, #0xc]
0x147980  bl       #0x147630   ; -> None
0x147984  mov      x8, #0xd05b
0x147988  ldr      w14, [sp, #0xc]
0x14798c  ldr      w12, [sp, #0x1c]
0x147990  movk     x8, #0xef20, lsl #16
0x147994  ldr      x10, [sp, #0x10]
0x147998  movk     x8, #0x96cc, lsl #32
0x14799c  movk     x8, #0x8753, lsl #48
0x1479a0  b        #0x147914
0x1479a4  ldr      x8, [sp, #0x20]
0x1479a8  b        #0x147914
0x1479ac  mov      x8, #0x8a0
0x1479b0  mov      x10, x20
0x1479b4  movk     x8, #0xbd15, lsl #16
0x1479b8  mov      w12, w14
0x1479bc  movk     x8, #0xb02c, lsl #32
0x1479c0  movk     x8, #0x93e7, lsl #48
0x1479c4  b        #0x147914
0x1479c8  mov      x8, #0x8a0
0x1479cc  ldur     x10, [x29, #-0x18]
0x1479d0  movk     x8, #0xbd15, lsl #16
0x1479d4  mov      w12, wzr
0x1479d8  movk     x8, #0xb02c, lsl #32
0x1479dc  movk     x8, #0x93e7, lsl #48
0x1479e0  b        #0x147914
0x1479e4  ldur     w8, [x29, #-4]
0x1479e8  ldr      x21, [x10]
0x1479ec  cmp      w12, w8
0x1479f0  csel     x8, x19, x28, eq
0x1479f4  b        #0x14790c
0x1479f8  ldp      x20, x19, [sp, #0x90]
0x1479fc  ldp      x22, x21, [sp, #0x80]
0x147a00  ldp      x24, x23, [sp, #0x70]
0x147a04  ldp      x26, x25, [sp, #0x60]
0x147a08  ldp      x28, x27, [sp, #0x50]
0x147a0c  ldp      x29, x30, [sp, #0x40]
0x147a10  add      sp, sp, #0xa0
0x147a14  ret      
0x147a18  mov      w2, wzr
0x147a1c  b        #0x14784c
0x147a20  str      x21, [sp, #-0x20]!
0x147a24  stp      x20, x19, [sp, #0x10]
0x147a28  ldr      w14, [x1]
0x147a2c  mov      x10, #0x1dac
0x147a30  mov      x11, #0x5cb8
0x147a34  mov      x8, #0x25ce
0x147a38  mov      x9, #0xb031
0x147a3c  movk     x10, #0x9f5e, lsl #16
0x147a40  movk     x11, #0x2795, lsl #16
0x147a44  mov      x12, #0x1859
0x147a48  mov      x13, #0x4c0d
0x147a4c  cmp      w14, w2
0x147a50  mov      x14, #0x6436
0x147a54  mov      x19, #0x1859
0x147a58  movk     x8, #0x8c3e, lsl #16
0x147a5c  movk     x9, #0x9cc1, lsl #16
0x147a60  movk     x10, #0xb762, lsl #32
0x147a64  movk     x11, #0x15f4, lsl #32
0x147a68  movk     x12, #0x2b53, lsl #16
0x147a6c  movk     x13, #0x52dd, lsl #16
0x147a70  movk     x14, #0x2869, lsl #16
0x147a74  movk     x19, #0x2b53, lsl #16
0x147a78  movk     x8, #0xdec2, lsl #32
0x147a7c  movk     x9, #0xffeb, lsl #32
0x147a80  movk     x10, #0x3b4a, lsl #48
0x147a84  movk     x11, #0x77a4, lsl #48
0x147a88  movk     x12, #0x6ffc, lsl #32
0x147a8c  movk     x13, #0x7dcf, lsl #32
0x147a90  movk     x14, #0xc5df, lsl #32
0x147a94  movk     x19, #0x6ffc, lsl #32
0x147a98  movk     x8, #0xf201, lsl #48
0x147a9c  movk     x9, #0x2516, lsl #48
0x147aa0  movk     x12, #0x930b, lsl #48
0x147aa4  movk     x13, #0x48fe, lsl #48
0x147aa8  movk     x14, #0x56de, lsl #48
0x147aac  csel     x15, x11, x10, hi
0x147ab0  mov      w16, #4
0x147ab4  movk     x19, #0x930b, lsl #48
0x147ab8  mov      w7, wzr
0x147abc  mov      x6, x17
0x147ac0  add      w20, w5, #1
0x147ac4  cmp      x19, x12
0x147ac8  b.eq     #0x147b14
0x147acc  cmp      x19, x8
0x147ad0  b.eq     #0x147b58
0x147ad4  cmp      x19, x9
0x147ad8  b.eq     #0x147b88
0x147adc  cmp      x19, x11
0x147ae0  b.eq     #0x147b6c
0x147ae4  cmp      x19, x13
0x147ae8  b.eq     #0x147b1c
0x147aec  cmp      x19, x14
0x147af0  b.eq     #0x147b38
0x147af4  cmp      x19, x10
0x147af8  b.ne     #0x147ac4
0x147afc  mov      x19, #0xb031
0x147b00  str      w16, [x0]
0x147b04  movk     x19, #0x9cc1, lsl #16
0x147b08  movk     x19, #0xffeb, lsl #32
0x147b0c  movk     x19, #0x2516, lsl #48
0x147b10  b        #0x147ac4
0x147b14  mov      x19, x15
0x147b18  b        #0x147ac4
0x147b1c  mov      x19, #0x25ce
0x147b20  ldr      x6, [x4, #8]
0x147b24  movk     x19, #0x8c3e, lsl #16
0x147b28  mov      w7, w20
0x147b2c  movk     x19, #0xdec2, lsl #32
0x147b30  movk     x19, #0xf201, lsl #48
0x147b34  b        #0x147ac4
0x147b38  ldr      w21, [x4]
0x147b3c  mov      x19, #0xb031
0x147b40  movk     x19, #0x9cc1, lsl #16
0x147b44  movk     x19, #0xffeb, lsl #32
0x147b48  movk     x19, #0x2516, lsl #48
0x147b4c  str      w21, [x17]
0x147b50  str      w3, [x4]
0x147b54  b        #0x147ac4
0x147b58  cmp      w7, w2
0x147b5c  mov      x4, x6
0x147b60  csel     x19, x14, x13, eq
0x147b64  mov      w5, w7
0x147b68  b        #0x147ac0
0x147b6c  ldr      x17, [x1, #8]
0x147b70  mov      x19, #0x25ce
0x147b74  movk     x19, #0x8c3e, lsl #16
0x147b78  movk     x19, #0xdec2, lsl #32
0x147b7c  ldr      w3, [x17]
0x147b80  movk     x19, #0xf201, lsl #48
0x147b84  b        #0x147ab8
0x147b88  ldp      x20, x19, [sp, #0x10]
0x147b8c  ldr      x21, [sp], #0x20
0x147b90  ret      
0x147b94  stp      x29, x30, [sp, #-0x40]!
0x147b98  stp      x24, x23, [sp, #0x10]
0x147b9c  stp      x22, x21, [sp, #0x20]
0x147ba0  stp      x20, x19, [sp, #0x30]
0x147ba4  mov      x29, sp
0x147ba8  mov      x20, #0xc2a2
0x147bac  mov      x21, #0x1381
0x147bb0  movk     x20, #0x1048, lsl #16
0x147bb4  movk     x21, #0xa58a, lsl #16
0x147bb8  mov      x22, #0xe386
0x147bbc  mov      x24, #0xb3d0
0x147bc0  mov      x8, #0xb3d0
0x147bc4  movk     x20, #0x7104, lsl #32
0x147bc8  movk     x21, #0xb763, lsl #32
0x147bcc  movk     x22, #0xeab8, lsl #16
0x147bd0  movk     x24, #0x566, lsl #16
0x147bd4  movk     x8, #0x566, lsl #16
0x147bd8  movk     x20, #0x9ffe, lsl #48
0x147bdc  movk     x21, #0xbbcd, lsl #48
0x147be0  cmp      x0, #0
0x147be4  movk     x22, #0xc1ec, lsl #32
0x147be8  movk     x24, #0xa50d, lsl #32
0x147bec  movk     x8, #0xa50d, lsl #32
0x147bf0  mov      x19, x0
0x147bf4  movk     x22, #0x808f, lsl #48
0x147bf8  csel     x23, x21, x20, eq
0x147bfc  movk     x24, #0x204a, lsl #48
0x147c00  movk     x8, #0x204a, lsl #48
0x147c04  cmp      x8, x22
0x147c08  b.eq     #0x147c54
0x147c0c  cmp      x8, x20
0x147c10  b.eq     #0x147c28
0x147c14  cmp      x8, x24
0x147c18  b.eq     #0x147c4c
0x147c1c  cmp      x8, x21
0x147c20  b.ne     #0x147c04
0x147c24  b        #0x147c38
0x147c28  ldr      x0, [x19, #8]
0x147c2c  bl       #0x147b94   ; -> None
0x147c30  mov      x0, x19
0x147c34  bl       #0x148a00   ; -> free
0x147c38  mov      x8, #0xe386
0x147c3c  movk     x8, #0xeab8, lsl #16
0x147c40  movk     x8, #0xc1ec, lsl #32
0x147c44  movk     x8, #0x808f, lsl #48
0x147c48  b        #0x147c04
0x147c4c  mov      x8, x23
0x147c50  b        #0x147c04
0x147c54  ldp      x20, x19, [sp, #0x30]
0x147c58  ldp      x22, x21, [sp, #0x20]
0x147c5c  ldp      x24, x23, [sp, #0x10]
0x147c60  ldp      x29, x30, [sp], #0x40
0x147c64  ret      
0x147c68  stp      x29, x30, [sp, #-0x40]!
0x147c6c  stp      x24, x23, [sp, #0x10]
0x147c70  stp      x22, x21, [sp, #0x20]
0x147c74  stp      x20, x19, [sp, #0x30]
0x147c78  mov      x29, sp
0x147c7c  mov      x20, #0x8d87
0x147c80  mov      x21, #0x865
0x147c84  movk     x20, #0xa2f3, lsl #16
0x147c88  movk     x21, #0x5362, lsl #16
0x147c8c  mov      x22, #0xea12
0x147c90  mov      x24, #0xcdf8
0x147c94  mov      x8, #0xcdf8
0x147c98  movk     x20, #0x8648, lsl #32
0x147c9c  movk     x21, #0x98ea, lsl #32
0x147ca0  movk     x22, #0x2ac8, lsl #16
0x147ca4  movk     x24, #0xd72b, lsl #16
0x147ca8  movk     x8, #0xd72b, lsl #16
0x147cac  movk     x20, #0xa5e3, lsl #48
0x147cb0  movk     x21, #0xabfd, lsl #48
0x147cb4  cmp      x0, #0
0x147cb8  movk     x22, #0x1d60, lsl #32
0x147cbc  movk     x24, #0x55aa, lsl #32
0x147cc0  movk     x8, #0x55aa, lsl #32
0x147cc4  mov      x19, x0
0x147cc8  movk     x22, #0x1023, lsl #48
0x147ccc  csel     x23, x21, x20, eq
0x147cd0  movk     x24, #0xfe6b, lsl #48
0x147cd4  movk     x8, #0xfe6b, lsl #48
0x147cd8  cmp      x8, x20
0x147cdc  b.eq     #0x147cfc
0x147ce0  cmp      x8, x22
0x147ce4  b.eq     #0x147d28
0x147ce8  cmp      x8, x24
0x147cec  b.eq     #0x147d20
0x147cf0  cmp      x8, x21
0x147cf4  b.ne     #0x147cd8
0x147cf8  b        #0x147d0c
0x147cfc  ldr      x0, [x19, #8]
0x147d00  bl       #0x147b94   ; -> None
0x147d04  mov      x0, x19
0x147d08  bl       #0x148a00   ; -> free
0x147d0c  mov      x8, #0xea12
0x147d10  movk     x8, #0x2ac8, lsl #16
0x147d14  movk     x8, #0x1d60, lsl #32
0x147d18  movk     x8, #0x1023, lsl #48
0x147d1c  b        #0x147cd8
0x147d20  mov      x8, x23
0x147d24  b        #0x147cd8
0x147d28  ldp      x20, x19, [sp, #0x30]
0x147d2c  ldp      x22, x21, [sp, #0x20]
0x147d30  ldp      x24, x23, [sp, #0x10]
0x147d34  ldp      x29, x30, [sp], #0x40
0x147d38  ret      
0x147d3c  stp      x29, x30, [sp, #-0x30]!
0x147d40  stp      x22, x21, [sp, #0x10]
0x147d44  stp      x20, x19, [sp, #0x20]
0x147d48  mov      x29, sp
0x147d4c  mov      w20, w1
0x147d50  mov      x21, x0
0x147d54  mov      x22, #0xd2d1
0x147d58  mov      w0, #1
0x147d5c  mov      w1, #0x10
0x147d60  movk     x22, #0xf825, lsl #16
0x147d64  movk     x22, #0xee0c, lsl #32
0x147d68  mov      x19, x2
0x147d6c  movk     x22, #0x5c23, lsl #48
0x147d70  bl       #0x148b90   ; -> calloc
0x147d74  mov      x8, #0xa74a
0x147d78  mov      x9, #0x5dae
0x147d7c  movk     x8, #0x5ea3, lsl #16
0x147d80  movk     x9, #0xbd6e, lsl #16
0x147d84  mov      x10, #0x8e81
0x147d88  mov      x13, #0x8e81
0x147d8c  movk     x8, #0xa04f, lsl #32
0x147d90  movk     x9, #0x6aaa, lsl #32
0x147d94  movk     x10, #0xe154, lsl #16
0x147d98  movk     x13, #0xe154, lsl #16
0x147d9c  movk     x8, #0xfa1e, lsl #48
0x147da0  movk     x9, #0x28f0, lsl #48
0x147da4  cmp      x0, #0
0x147da8  movk     x10, #0x3b5e, lsl #32
0x147dac  movk     x13, #0x3b5e, lsl #32
0x147db0  movk     x10, #0x7cc5, lsl #48
0x147db4  csel     x11, x9, x8, eq
0x147db8  mov      w12, #2
0x147dbc  movk     x13, #0x7cc5, lsl #48
0x147dc0  cmp      x13, x8
0x147dc4  b.eq     #0x147df8
0x147dc8  cmp      x13, x10
0x147dcc  b.eq     #0x147e14
0x147dd0  cmp      x13, x22
0x147dd4  b.eq     #0x147e1c
0x147dd8  cmp      x13, x9
0x147ddc  b.ne     #0x147dc0
0x147de0  mov      x13, #0xd2d1
0x147de4  str      w12, [x21]
0x147de8  movk     x13, #0xf825, lsl #16
0x147dec  movk     x13, #0xee0c, lsl #32
0x147df0  movk     x13, #0x5c23, lsl #48
0x147df4  b        #0x147dc0
0x147df8  mov      x13, #0xd2d1
0x147dfc  str      w20, [x0]
0x147e00  movk     x13, #0xf825, lsl #16
0x147e04  str      x19, [x0, #8]
0x147e08  movk     x13, #0xee0c, lsl #32
0x147e0c  movk     x13, #0x5c23, lsl #48
0x147e10  b        #0x147dc0
0x147e14  mov      x13, x11
0x147e18  b        #0x147dc0
0x147e1c  ldp      x20, x19, [sp, #0x20]
0x147e20  ldp      x22, x21, [sp, #0x10]
0x147e24  ldp      x29, x30, [sp], #0x30
0x147e28  ret      
0x147e2c  b        #0x148a00
0x147e30  ldr      x0, [x0, #0x28]
0x147e34  mov      w1, wzr
0x147e38  b        #0x147304
0x147e3c  stp      x29, x30, [sp, #-0x30]!
0x147e40  str      x21, [sp, #0x10]
0x147e44  stp      x20, x19, [sp, #0x20]
0x147e48  mov      x29, sp
0x147e4c  mov      x20, x0
0x147e50  mov      x0, x1
0x147e54  ldr      x21, [x1, #0x20]
0x147e58  mov      x19, x2
0x147e5c  bl       #0x147e30   ; -> None
0x147e60  mov      w3, w0
0x147e64  mov      x0, x20
0x147e68  mov      x4, x19
0x147e6c  mov      x1, x21
0x147e70  ldp      x20, x19, [sp, #0x20]
0x147e74  mov      w2, wzr
0x147e78  ldr      x21, [sp, #0x10]
0x147e7c  ldp      x29, x30, [sp], #0x30
0x147e80  b        #0x146b68
0x147e84  stp      x29, x30, [sp, #-0x50]!
0x147e88  str      x25, [sp, #0x10]
0x147e8c  stp      x24, x23, [sp, #0x20]
0x147e90  stp      x22, x21, [sp, #0x30]
0x147e94  stp      x20, x19, [sp, #0x40]
0x147e98  mov      x29, sp
0x147e9c  mov      x19, x0
0x147ea0  mov      x20, #0xc335
0x147ea4  ldr      x0, [x0]
0x147ea8  movk     x20, #0x1484, lsl #16
0x147eac  movk     x20, #0x16b3, lsl #32
0x147eb0  movk     x20, #0xb3cc, lsl #48
0x147eb4  bl       #0x147c68   ; -> None
0x147eb8  ldr      x0, [x19, #8]
0x147ebc  bl       #0x1473d8   ; -> None
0x147ec0  ldr      x0, [x19, #0x10]
0x147ec4  bl       #0x146810   ; -> None
0x147ec8  ldr      x0, [x19, #0x18]
0x147ecc  bl       #0x14647c   ; -> None
0x147ed0  mov      x21, #0x9a1f
0x147ed4  mov      x22, #0xb7cc
0x147ed8  mov      x23, #0xdf4a
0x147edc  mov      x9, #0x9a1f
0x147ee0  movk     x21, #0xd6a5, lsl #16
0x147ee4  movk     x22, #0xff64, lsl #16
0x147ee8  movk     x23, #0xbdc8, lsl #16
0x147eec  movk     x9, #0xd6a5, lsl #16
0x147ef0  movk     x21, #0xc885, lsl #32
0x147ef4  movk     x22, #0xf23e, lsl #32
0x147ef8  movk     x23, #0xceb, lsl #32
0x147efc  movk     x9, #0xc885, lsl #32
0x147f00  mov      x8, xzr
0x147f04  movk     x21, #0xf611, lsl #48
0x147f08  movk     x22, #0x8f3d, lsl #48
0x147f0c  movk     x23, #0xc8d5, lsl #48
0x147f10  movk     x9, #0xf611, lsl #48
0x147f14  add      x10, x19, x8, lsl #3
0x147f18  add      x25, x8, #1
0x147f1c  add      x24, x10, #0x20
0x147f20  cmp      x9, x22
0x147f24  b.eq     #0x147f44
0x147f28  cmp      x9, x21
0x147f2c  b.eq     #0x147f50
0x147f30  cmp      x9, x23
0x147f34  b.eq     #0x147f70
0x147f38  cmp      x9, x20
0x147f3c  b.ne     #0x147f20
0x147f40  b        #0x147f64
0x147f44  ldr      x0, [x24]
0x147f48  bl       #0x1473d8   ; -> None
0x147f4c  mov      x8, x25
0x147f50  mov      x9, #0xc335
0x147f54  movk     x9, #0x1484, lsl #16
0x147f58  movk     x9, #0x16b3, lsl #32
0x147f5c  movk     x9, #0xb3cc, lsl #48
0x147f60  b        #0x147f20
0x147f64  cmp      x8, #0x10
0x147f68  csel     x9, x23, x22, eq
0x147f6c  b        #0x147f14
0x147f70  mov      x0, x19
0x147f74  ldr      x25, [sp, #0x10]
0x147f78  ldp      x20, x19, [sp, #0x40]
0x147f7c  ldp      x22, x21, [sp, #0x30]
0x147f80  ldp      x24, x23, [sp, #0x20]
0x147f84  ldp      x29, x30, [sp], #0x50
0x147f88  b        #0x148a00
0x147f8c  sub      sp, sp, #0x70
0x147f90  stp      x29, x30, [sp, #0x10]
0x147f94  stp      x28, x27, [sp, #0x20]
0x147f98  stp      x26, x25, [sp, #0x30]
0x147f9c  stp      x24, x23, [sp, #0x40]
0x147fa0  stp      x22, x21, [sp, #0x50]
0x147fa4  stp      x20, x19, [sp, #0x60]
0x147fa8  add      x29, sp, #0x10
0x147fac  mov      x19, x0
0x147fb0  mov      x23, #0xafb5
0x147fb4  mov      w0, #1
0x147fb8  mov      w1, #0xa0
0x147fbc  movk     x23, #0xa12b, lsl #16
0x147fc0  movk     x23, #0xce93, lsl #32
0x147fc4  movk     x23, #0xb225, lsl #48
0x147fc8  bl       #0x148b90   ; -> calloc
0x147fcc  mov      x8, #0xa74a
0x147fd0  mov      x9, #0x5dae
0x147fd4  movk     x8, #0x5ea3, lsl #16
0x147fd8  movk     x9, #0xbd6e, lsl #16
0x147fdc  mov      x28, #0xb7cc
0x147fe0  mov      x22, #0xdf4a
0x147fe4  mov      x27, #0xc335
0x147fe8  mov      x25, #0x2f9c
0x147fec  mov      x10, #0x8e81
0x147ff0  movk     x8, #0xa04f, lsl #32
0x147ff4  movk     x9, #0x6aaa, lsl #32
0x147ff8  movk     x28, #0xff64, lsl #16
0x147ffc  movk     x22, #0xbdc8, lsl #16
0x148000  movk     x27, #0x1484, lsl #16
0x148004  movk     x25, #0xc396, lsl #16
0x148008  movk     x10, #0xe154, lsl #16
0x14800c  movk     x8, #0xfa1e, lsl #48
0x148010  movk     x9, #0x28f0, lsl #48
0x148014  cmp      x0, #0
0x148018  movk     x28, #0xf23e, lsl #32
0x14801c  movk     x22, #0xceb, lsl #32
0x148020  movk     x27, #0x16b3, lsl #32
0x148024  movk     x25, #0x5e8f, lsl #32
0x148028  movk     x10, #0x3b5e, lsl #32
0x14802c  mov      x20, x0
0x148030  csel     x8, x9, x8, eq
0x148034  movk     x28, #0x8f3d, lsl #48
0x148038  movk     x22, #0xc8d5, lsl #48
0x14803c  movk     x27, #0xb3cc, lsl #48
0x148040  movk     x25, #0xf2cd, lsl #48
0x148044  movk     x10, #0x7cc5, lsl #48
0x148048  str      x8, [sp, #8]
0x14804c  mov      x24, x8
0x148050  mov      x21, x1
0x148054  cmp      x10, x28
0x148058  b.eq     #0x148210
0x14805c  mov      x9, x10
0x148060  cmp      x10, x23
0x148064  b.eq     #0x148244
0x148068  cmp      x9, x27
0x14806c  b.eq     #0x1481ec
0x148070  cmp      x9, x22
0x148074  b.eq     #0x1481ec
0x148078  cmp      x9, x25
0x14807c  b.eq     #0x1481ec
0x148080  mov      x8, #0x9a1f
0x148084  movk     x8, #0xd6a5, lsl #16
0x148088  movk     x8, #0xc885, lsl #32
0x14808c  movk     x8, #0xf611, lsl #48
0x148090  cmp      x9, x8
0x148094  b.eq     #0x14827c
0x148098  mov      x10, #0xafb5
0x14809c  mov      x11, #0x7811
0x1480a0  movk     x10, #0xa12b, lsl #16
0x1480a4  movk     x11, #0x740, lsl #16
0x1480a8  movk     x10, #0xce93, lsl #32
0x1480ac  mov      x1, x21
0x1480b0  mov      x8, x26
0x1480b4  movk     x10, #0xb225, lsl #48
0x1480b8  movk     x11, #0x67ad, lsl #32
0x1480bc  movk     x11, #0xf79c, lsl #48
0x1480c0  cmp      x9, x11
0x1480c4  b.eq     #0x14804c
0x1480c8  mov      x8, #0xa74a
0x1480cc  movk     x8, #0x5ea3, lsl #16
0x1480d0  movk     x8, #0xa04f, lsl #32
0x1480d4  movk     x8, #0xfa1e, lsl #48
0x1480d8  cmp      x9, x8
0x1480dc  b.eq     #0x1482a4
0x1480e0  mov      x8, #0x8779
0x1480e4  movk     x8, #0xf1b8, lsl #16
0x1480e8  movk     x8, #0x3378, lsl #32
0x1480ec  movk     x8, #0xeb0, lsl #48
0x1480f0  cmp      x9, x8
0x1480f4  b.eq     #0x1482e8
0x1480f8  mov      x8, #0x5dae
0x1480fc  movk     x8, #0xbd6e, lsl #16
0x148100  movk     x8, #0x6aaa, lsl #32
0x148104  movk     x8, #0x28f0, lsl #48
0x148108  cmp      x9, x8
0x14810c  b.eq     #0x14833c
0x148110  mov      x8, #0xd2d1
0x148114  movk     x8, #0xf825, lsl #16
0x148118  movk     x8, #0xee0c, lsl #32
0x14811c  movk     x8, #0x5c23, lsl #48
0x148120  cmp      x9, x8
0x148124  b.eq     #0x1481ec
0x148128  mov      x8, #0xee15
0x14812c  movk     x8, #0x1fe1, lsl #16
0x148130  movk     x8, #0x5376, lsl #32
0x148134  movk     x8, #0x6aa9, lsl #48
0x148138  cmp      x9, x8
0x14813c  b.eq     #0x1481ec
0x148140  mov      x10, #0x113f
0x148144  mov      x11, #0x28cc
0x148148  movk     x10, #0xceaf, lsl #16
0x14814c  movk     x11, #0xc3e2, lsl #16
0x148150  movk     x10, #0x4fe6, lsl #32
0x148154  mov      x1, x20
0x148158  mov      x8, x24
0x14815c  movk     x10, #0xe9ff, lsl #48
0x148160  movk     x11, #0x7819, lsl #32
0x148164  movk     x11, #0x6b85, lsl #48
0x148168  cmp      x9, x11
0x14816c  b.eq     #0x14804c
0x148170  mov      x8, #0x3581
0x148174  movk     x8, #0xbcba, lsl #16
0x148178  movk     x8, #0x133, lsl #32
0x14817c  movk     x8, #0x761f, lsl #48
0x148180  cmp      x9, x8
0x148184  b.eq     #0x148360
0x148188  mov      x8, #0x7515
0x14818c  movk     x8, #0xb217, lsl #16
0x148190  movk     x8, #0xdfc8, lsl #32
0x148194  movk     x8, #0x768a, lsl #48
0x148198  cmp      x9, x8
0x14819c  b.eq     #0x14837c
0x1481a0  mov      x11, #0x8e81
0x1481a4  mov      x1, x21
0x1481a8  movk     x11, #0xe154, lsl #16
0x1481ac  mov      x8, x24
0x1481b0  ldr      x10, [sp, #8]
0x1481b4  movk     x11, #0x3b5e, lsl #32
0x1481b8  movk     x11, #0x7cc5, lsl #48
0x1481bc  cmp      x9, x11
0x1481c0  b.eq     #0x14804c
0x1481c4  mov      x11, #0x113f
0x1481c8  mov      x1, x21
0x1481cc  movk     x11, #0xceaf, lsl #16
0x1481d0  mov      x8, x24
0x1481d4  mov      x10, x9
0x1481d8  movk     x11, #0x4fe6, lsl #32
0x1481dc  movk     x11, #0xe9ff, lsl #48
0x1481e0  cmp      x9, x11
0x1481e4  b.ne     #0x14804c
0x1481e8  b        #0x1483b0
0x1481ec  mov      x0, x20
0x1481f0  bl       #0x147e84   ; -> None
0x1481f4  mov      x10, #0x113f
0x1481f8  mov      x1, xzr
0x1481fc  movk     x10, #0xceaf, lsl #16
0x148200  mov      x8, x24
0x148204  movk     x10, #0x4fe6, lsl #32
0x148208  movk     x10, #0xe9ff, lsl #48
0x14820c  b        #0x14804c
0x148210  mov      x0, x19
0x148214  bl       #0x146480   ; -> None
0x148218  ldr      w8, [x19]
0x14821c  mov      x1, x21
0x148220  str      x0, [x20, #0x10]
0x148224  cmp      w8, #0
0x148228  mov      x8, #0x7515
0x14822c  movk     x8, #0xb217, lsl #16
0x148230  movk     x8, #0xdfc8, lsl #32
0x148234  movk     x8, #0x768a, lsl #48
0x148238  csel     x10, x8, x22, eq
0x14823c  mov      x8, x24
0x148240  b        #0x14804c
0x148244  mov      x8, #0x8779
0x148248  mov      x9, #0x28cc
0x14824c  movk     x8, #0xf1b8, lsl #16
0x148250  movk     x9, #0xc3e2, lsl #16
0x148254  movk     x8, #0x3378, lsl #32
0x148258  movk     x9, #0x7819, lsl #32
0x14825c  cmp      x24, #0x10
0x148260  movk     x8, #0xeb0, lsl #48
0x148264  movk     x9, #0x6b85, lsl #48
0x148268  mov      x1, x21
0x14826c  csel     x10, x9, x8, eq
0x148270  mov      x8, x24
0x148274  str      x24, [sp]
0x148278  b        #0x14804c
0x14827c  mov      x0, x19
0x148280  mov      w1, #0x100
0x148284  bl       #0x1468e4   ; -> None
0x148288  ldr      w8, [x19]
0x14828c  mov      x1, x21
0x148290  str      x0, [x20, #8]
0x148294  cmp      w8, #0
0x148298  mov      x8, x24
0x14829c  csel     x10, x28, x27, eq
0x1482a0  b        #0x14804c
0x1482a4  mov      x0, x19
0x1482a8  bl       #0x147548   ; -> None
0x1482ac  ldr      w8, [x19]
0x1482b0  mov      x9, #0xd2d1
0x1482b4  movk     x9, #0xf825, lsl #16
0x1482b8  mov      x1, x21
0x1482bc  movk     x9, #0xee0c, lsl #32
0x1482c0  str      x0, [x20]
0x1482c4  cmp      w8, #0
0x1482c8  mov      x8, #0x9a1f
0x1482cc  movk     x8, #0xd6a5, lsl #16
0x1482d0  movk     x9, #0x5c23, lsl #48
0x1482d4  movk     x8, #0xc885, lsl #32
0x1482d8  movk     x8, #0xf611, lsl #48
0x1482dc  csel     x10, x8, x9, eq
0x1482e0  mov      x8, x24
0x1482e4  b        #0x14804c
0x1482e8  mov      x0, x19
0x1482ec  mov      w1, #0x100
0x1482f0  bl       #0x1468e4   ; -> None
0x1482f4  ldr      w8, [x19]
0x1482f8  mov      x1, x21
0x1482fc  ldr      x10, [sp]
0x148300  cmp      w8, #0
0x148304  mov      x8, #0x7811
0x148308  add      x9, x20, x10, lsl #3
0x14830c  add      x26, x10, #1
0x148310  mov      x10, #0xee15
0x148314  movk     x8, #0x740, lsl #16
0x148318  movk     x10, #0x1fe1, lsl #16
0x14831c  movk     x8, #0x67ad, lsl #32
0x148320  movk     x10, #0x5376, lsl #32
0x148324  movk     x8, #0xf79c, lsl #48
0x148328  movk     x10, #0x6aa9, lsl #48
0x14832c  str      x0, [x9, #0x20]
0x148330  csel     x10, x8, x10, eq
0x148334  mov      x8, x24
0x148338  b        #0x14804c
0x14833c  mov      x10, #0x113f
0x148340  mov      w9, #2
0x148344  movk     x10, #0xceaf, lsl #16
0x148348  mov      x1, xzr
0x14834c  movk     x10, #0x4fe6, lsl #32
0x148350  mov      x8, x24
0x148354  movk     x10, #0xe9ff, lsl #48
0x148358  str      w9, [x19]
0x14835c  b        #0x14804c
0x148360  mov      x10, #0xafb5
0x148364  mov      x8, xzr
0x148368  movk     x10, #0xa12b, lsl #16
0x14836c  mov      x1, x21
0x148370  movk     x10, #0xce93, lsl #32
0x148374  movk     x10, #0xb225, lsl #48
0x148378  b        #0x14804c
0x14837c  mov      x0, x19
0x148380  bl       #0x14646c   ; -> None
0x148384  ldr      w8, [x19]
0x148388  mov      x1, x21
0x14838c  str      x0, [x20, #0x18]
0x148390  cmp      w8, #0
0x148394  mov      x8, #0x3581
0x148398  movk     x8, #0xbcba, lsl #16
0x14839c  movk     x8, #0x133, lsl #32
0x1483a0  movk     x8, #0x761f, lsl #48
0x1483a4  csel     x10, x8, x25, eq
0x1483a8  mov      x8, x24
0x1483ac  b        #0x14804c
0x1483b0  mov      x0, x21
0x1483b4  ldp      x20, x19, [sp, #0x60]
0x1483b8  ldp      x22, x21, [sp, #0x50]
0x1483bc  ldp      x24, x23, [sp, #0x40]
0x1483c0  ldp      x26, x25, [sp, #0x30]
0x1483c4  ldp      x28, x27, [sp, #0x20]
0x1483c8  ldp      x29, x30, [sp, #0x10]
0x1483cc  add      sp, sp, #0x70
0x1483d0  ret      
0x1483d4  udf      #0
0x1483d8  udf      #0
0x1483dc  udf      #0
0x1483e0  bti      c
0x1483e4  adrp     x16, #0x155000
0x1483e8  ldrb     w16, [x16, #0xe60]
0x1483ec  cbz      w16, #0x1483f8
0x1483f0  casab    w0, w1, [x2]
0x1483f4  ret      
0x1483f8  uxtb     w16, w0
0x1483fc  ldaxrb   w0, [x2]
0x148400  cmp      w0, w16
0x148404  b.ne     #0x148410
0x148408  stxrb    w17, w1, [x2]
0x14840c  cbnz     w17, #0x1483fc
0x148410  ret      
0x148414  paciasp  
0x148418  sub      sp, sp, #0x70
0x14841c  stp      x30, x19, [sp, #0x60]
0x148420  mov      w0, #0x10
0x148424  bl       #0x148e50   ; -> getauxval
0x148428  mov      x19, x0
0x14842c  tbnz     w19, #8, #0x148448
0x148430  ldp      x30, x19, [sp, #0x60]
0x148434  adrp     x9, #0x155000
0x148438  strb     wzr, [x9, #0xe60]
0x14843c  add      sp, sp, #0x70
0x148440  autiasp  
0x148444  ret      
0x148448  adrp     x0, #0x3000
0x14844c  add      x0, x0, #0x680
0x148450  add      x1, sp, #4
0x148454  bl       #0x148c20   ; -> __system_property_get
0x148458  cmp      w0, #1
0x14845c  b.lt     #0x148488
0x148460  adrp     x1, #0x3000
0x148464  add      x1, x1, #0x689
0x148468  add      x0, sp, #4
0x14846c  mov      w2, #0xa
0x148470  and      x8, x19, #0x100
0x148474  lsr      x19, x8, #8
0x148478  bl       #0x148be0   ; -> strncmp
0x14847c  cmp      w0, #0
0x148480  csel     w8, wzr, w19, eq
0x148484  b        #0x14848c
0x148488  ubfx     x8, x19, #8, #1
0x14848c  cmp      w8, #0
0x148490  cset     w8, ne
0x148494  ldp      x30, x19, [sp, #0x60]
0x148498  adrp     x9, #0x155000
0x14849c  strb     w8, [x9, #0xe60]
0x1484a0  add      sp, sp, #0x70
0x1484a4  autiasp  
0x1484a8  ret      
0x1484ac  bti      c
0x1484b0  stp      x24, x23, [sp, #-0x30]!
0x1484b4  stp      x22, x21, [sp, #0x10]
0x1484b8  stp      x20, x19, [sp, #0x20]
0x1484bc  adrp     x8, #0x155000
0x1484c0  ldr      x9, [x8, #0xe68]
0x1484c4  cbz      x9, #0x1484d8
0x1484c8  ldp      x20, x19, [sp, #0x20]
0x1484cc  ldp      x22, x21, [sp, #0x10]
0x1484d0  ldp      x24, x23, [sp], #0x30
0x1484d4  ret      
0x1484d8  tbnz     x0, #0x3e, #0x1484e4
0x1484dc  mov      x9, xzr
0x1484e0  b        #0x1484e8
0x1484e4  ldr      x9, [x1, #0x10]
0x1484e8  lsr      x10, x0, #4
0x1484ec  lsl      w11, w0, #3
0x1484f0  lsr      x12, x0, #0x1a
0x1484f4  and      x11, x11, #0x400
0x1484f8  tst      x9, #0x80
0x1484fc  and      x12, x12, #2
0x148500  mov      w13, #6
0x148504  bfi      x11, x10, #0xf, #1
0x148508  csel     x12, x12, x13, eq
0x14850c  lsr      x15, x0, #0x10
0x148510  orr      x14, x12, x11
0x148514  and      x12, x0, #0xc0000
0x148518  lsr      x16, x0, #0x14
0x14851c  orr      x13, x14, #0x20
0x148520  cmp      x12, #0xc0, lsl #12
0x148524  and      x15, x15, #0x10
0x148528  and      x16, x16, #8
0x14852c  csel     x14, x13, x14, eq
0x148530  orr      x15, x16, x15
0x148534  lsr      x16, x0, #7
0x148538  orr      x15, x15, x14
0x14853c  mov      w14, #0x100
0x148540  movk     w14, #1, lsl #16
0x148544  lsr      x17, x0, #6
0x148548  orr      x14, x15, x14
0x14854c  tst      x0, #0x200
0x148550  and      x16, x16, #0x20000
0x148554  and      x17, x17, #0x40
0x148558  csel     x15, x15, x14, eq
0x14855c  orr      x16, x17, x16
0x148560  orr      x15, x16, x15
0x148564  lsl      x17, x0, #0xb
0x148568  lsl      w1, w0, #6
0x14856c  orr      x16, x15, #0x800000
0x148570  tst      x0, #0x4000000
0x148574  and      x17, x17, #0x4000
0x148578  and      x1, x1, #0x800
0x14857c  csel     x15, x15, x16, eq
0x148580  orr      x17, x1, x17
0x148584  lsl      x1, x0, #7
0x148588  orr      x15, x17, x15
0x14858c  tst      x0, #0x40
0x148590  orr      x17, x15, #0x1000
0x148594  and      x2, x1, #0x100000
0x148598  and      x1, x1, #0x200000
0x14859c  csel     x15, x15, x17, eq
0x1485a0  orr      x1, x1, x2
0x1485a4  tst      x0, #0x20000000
0x1485a8  orr      x15, x1, x15
0x1485ac  lsl      x2, x0, #0x15
0x1485b0  orr      x1, x15, #0x400000000000
0x1485b4  and      x2, x2, #0x2000000000000
0x1485b8  csel     x15, x15, x1, eq
0x1485bc  tst      x9, #0x40000
0x1485c0  orr      x15, x2, x15
0x1485c4  lsl      x7, x9, #0x23
0x1485c8  orr      x2, x15, #0x180000000000
0x1485cc  and      x5, x7, #0x2000000000
0x1485d0  csel     x15, x15, x2, eq
0x1485d4  ands     x2, x9, #0x400000
0x1485d8  orr      x3, x15, #0x380000000000
0x1485dc  mov      x6, #0x6000000000
0x1485e0  csel     x15, x15, x3, eq
0x1485e4  tst      x9, #8
0x1485e8  csel     x5, x5, x6, eq
0x1485ec  and      x6, x7, #0x8000000000
0x1485f0  orr      x5, x6, x5
0x1485f4  mov      w19, #0x250
0x1485f8  orr      x15, x5, x15
0x1485fc  lsr      x4, x9, #4
0x148600  movk     w19, #0x2400, lsl #16
0x148604  ands     x5, x9, #0x20
0x148608  orr      x6, x15, #0x10000000000
0x14860c  lsl      w23, w9, #0xd
0x148610  and      x22, x0, x19
0x148614  csel     x19, x15, x6, eq
0x148618  and      x7, x7, #0x20000000000
0x14861c  and      x15, x9, #1
0x148620  and      x23, x23, #0x4000000
0x148624  and      x4, x4, #0x10000000
0x148628  orr      x7, x7, x19
0x14862c  lsr      x19, x0, #1
0x148630  orr      x4, x4, x23
0x148634  lsr      x23, x9, #1
0x148638  orr      x7, x7, x15, lsl #19
0x14863c  and      x19, x19, #0x80
0x148640  and      x23, x23, #0x100000000
0x148644  orr      x20, x2, x5
0x148648  orr      x21, x19, x7
0x14864c  ands     x7, x9, #0x10000
0x148650  orr      x4, x23, x4
0x148654  lsl      w23, w9, #0xa
0x148658  orr      x19, x21, #1
0x14865c  orr      x24, x20, x7
0x148660  and      x20, x23, #0x2000000
0x148664  csel     x21, x21, x19, eq
0x148668  orr      x4, x20, x4
0x14866c  ands     x20, x9, #0x100
0x148670  orr      x4, x4, x21
0x148674  orr      x23, x24, x20
0x148678  orr      x21, x4, #0x1000000
0x14867c  orr      x22, x22, x23
0x148680  csel     x4, x4, x21, eq
0x148684  cbnz     x22, #0x148690
0x148688  cmp      x12, #0xc0, lsl #12
0x14868c  b.ne     #0x1486dc
0x148690  cmp      x12, #0xc0, lsl #12
0x148694  csel     x11, x13, x11, eq
0x148698  tst      x0, #0x200
0x14869c  csel     x11, x11, x14, eq
0x1486a0  tst      x0, #0x4000000
0x1486a4  csel     x11, x11, x16, eq
0x1486a8  tst      x0, #0x40
0x1486ac  csel     x11, x11, x17, eq
0x1486b0  tst      x0, #0x20000000
0x1486b4  csel     x11, x11, x1, eq
0x1486b8  cmp      x2, #0
0x1486bc  csel     x11, x11, x3, eq
0x1486c0  cmp      x5, #0
0x1486c4  csel     x11, x11, x6, eq
0x1486c8  cmp      x7, #0
0x1486cc  csel     x11, x11, x19, eq
0x1486d0  cmp      x20, #0
0x1486d4  csel     x11, x11, x21, eq
0x1486d8  str      x11, [x8, #0xe68]
0x1486dc  lsl      x11, x9, #0x18
0x1486e0  and      x12, x11, #0x200000000
0x1486e4  and      x13, x11, #0x400000000
0x1486e8  orr      x12, x13, x12
0x1486ec  lsl      x13, x9, #0x21
0x1486f0  and      x11, x11, #0x800000000
0x1486f4  and      x13, x13, #0x4000000000000
0x1486f8  orr      x11, x11, x12
0x1486fc  lsl      w12, w9, #8
0x148700  orr      x11, x13, x11
0x148704  and      x12, x12, #0x20000000
0x148708  orr      x11, x12, x11
0x14870c  lsl      x12, x9, #0x17
0x148710  and      x12, x12, #0x40000000000000
0x148714  lsl      x13, x9, #0x13
0x148718  orr      x11, x12, x11
0x14871c  and      x12, x13, #0x40000000000
0x148720  orr      x11, x12, x11
0x148724  lsl      x12, x9, #0x20
0x148728  and      x12, x12, #0x100000000000000
0x14872c  lsl      x13, x9, #0x1e
0x148730  orr      x11, x12, x11
0x148734  and      x12, x13, #0x80000000000000
0x148738  orr      x11, x12, x11
0x14873c  orr      x11, x11, x4
0x148740  tbnz     w0, #0xb, #0x1487bc
0x148744  mov      w13, #0x201
0x148748  orr      x12, x11, #0x300
0x14874c  tst      x0, x13
0x148750  and      x13, x0, #0x10000
0x148754  csel     x11, x11, x12, eq
0x148758  orr      x12, x15, x13
0x14875c  orr      x13, x11, #0x40000
0x148760  cmp      x12, #0
0x148764  csel     x11, x11, x13, eq
0x148768  mov      w12, #0x8000
0x14876c  movk     w12, #0x400, lsl #16
0x148770  tst      x0, x12
0x148774  b.eq     #0x148780
0x148778  orr      x11, x11, #0x400000
0x14877c  str      x11, [x8, #0xe68]
0x148780  mov      x12, #0x4000
0x148784  orr      x13, x11, #0x8000000
0x148788  movk     x12, #1, lsl #32
0x14878c  and      x10, x10, #0x2000
0x148790  tst      x9, x12
0x148794  lsl      w12, w9, #0x13
0x148798  csel     x11, x11, x13, eq
0x14879c  tst      x9, #2
0x1487a0  and      x9, x0, #0x400000
0x1487a4  and      x12, x12, #0x80000000
0x1487a8  ccmp     x9, #0, #4, ne
0x1487ac  orr      x9, x12, x11
0x1487b0  orr      x11, x9, #0x1000000000
0x1487b4  csel     x9, x9, x11, eq
0x1487b8  b        #0x1488ac
0x1487bc  mrs      x9, id_aa64pfr1_el1
0x1487c0  tst      x9, #0xf00
0x1487c4  b.eq     #0x1487d0
0x1487c8  orr      x11, x11, #0x80000000000
0x1487cc  str      x11, [x8, #0xe68]
0x1487d0  and      x10, x9, #0xf0
0x1487d4  orr      x12, x11, #0x1000000000000
0x1487d8  cmp      x10, #0x10
0x1487dc  and      x9, x9, #0xf000000
0x1487e0  csel     x10, x12, x11, eq
0x1487e4  mov      w11, #0x2000000
0x1487e8  orr      x12, x10, #0x200000000000000
0x1487ec  cmp      x9, x11
0x1487f0  mrs      x11, id_aa64pfr0_el1
0x1487f4  csel     x9, x12, x10, eq
0x1487f8  mvn      w10, w11
0x1487fc  orr      x12, x9, #0x300
0x148800  tst      x10, #0xf0000
0x148804  csel     x9, x9, x12, eq
0x148808  tst      x11, #0xf00000000
0x14880c  b.eq     #0x14883c
0x148810  mrs      x10, id_aa64zfr0_el1
0x148814  and      x11, x10, #0xf
0x148818  cmp      x11, #1
0x14881c  b.eq     #0x14882c
0x148820  cbnz     x11, #0x148830
0x148824  orr      x9, x9, #0x40000000
0x148828  b        #0x148830
0x14882c  orr      x9, x9, #0x1000000000
0x148830  orr      x11, x9, #0x80000000
0x148834  tst      x10, #0xf00000
0x148838  csel     x9, x9, x11, eq
0x14883c  mrs      x10, id_aa64isar0_el1
0x148840  orr      x11, x9, #0x2000
0x148844  tst      x10, #0xf00000000
0x148848  csel     x10, x9, x11, eq
0x14884c  mrs      x9, id_aa64isar1_el1
0x148850  orr      x11, x10, #0x40000
0x148854  tst      x9, #0xf
0x148858  csel     x10, x10, x11, eq
0x14885c  tst      x9, #0xf00000
0x148860  b.eq     #0x14886c
0x148864  orr      x10, x10, #0x400000
0x148868  str      x10, [x8, #0xe68]
0x14886c  and      x11, x9, #0xf0000000000
0x148870  mov      x12, #0x20000000000
0x148874  orr      x13, x10, #0x800000000000
0x148878  cmp      x11, x12
0x14887c  csel     x10, x13, x10, eq
0x148880  tst      x9, #0xf00000000000
0x148884  orr      x12, x10, #0x8000000
0x148888  lsr      x11, x9, #0x3c
0x14888c  csel     x10, x10, x12, eq
0x148890  cbz      x11, #0x1488b0
0x148894  lsr      x9, x9, #0x3d
0x148898  cbz      x9, #0x1488c8
0x14889c  cmp      x11, #2
0x1488a0  mov      x9, #0x18000000000000
0x1488a4  mov      x11, #0x38000000000000
0x1488a8  csel     x9, x11, x9, hi
0x1488ac  orr      x10, x10, x9
0x1488b0  orr      x9, x10, #0x400000000000000
0x1488b4  str      x9, [x8, #0xe68]
0x1488b8  ldp      x20, x19, [sp, #0x20]
0x1488bc  ldp      x22, x21, [sp, #0x10]
0x1488c0  ldp      x24, x23, [sp], #0x30
0x1488c4  ret      
0x1488c8  orr      x10, x10, #0x8000000000000
0x1488cc  orr      x9, x10, #0x400000000000000
0x1488d0  str      x9, [x8, #0xe68]
0x1488d4  ldp      x20, x19, [sp, #0x20]
0x1488d8  ldp      x22, x21, [sp, #0x10]
0x1488dc  ldp      x24, x23, [sp], #0x30
0x1488e0  ret      
0x1488e4  paciasp  
0x1488e8  sub      sp, sp, #0x90
0x1488ec  stp      x30, x19, [sp, #0x80]
0x1488f0  adrp     x8, #0x155000
0x1488f4  ldr      x8, [x8, #0xe68]
0x1488f8  cbz      x8, #0x14890c
0x1488fc  ldp      x30, x19, [sp, #0x80]
0x148900  add      sp, sp, #0x90
0x148904  autiasp  
0x148908  ret      
0x14890c  adrp     x0, #0x3000
0x148910  add      x0, x0, #0x680
0x148914  add      x1, sp, #0x24
0x148918  bl       #0x148c20   ; -> __system_property_get
0x14891c  cmp      w0, #1
0x148920  b.lt     #0x14893c
0x148924  adrp     x1, #0x3000
0x148928  add      x1, x1, #0x689
0x14892c  add      x0, sp, #0x24
0x148930  mov      w2, #0xa
0x148934  bl       #0x148be0   ; -> strncmp
0x148938  cbz      w0, #0x1488fc
0x14893c  mov      w0, #0x10
0x148940  bl       #0x148e50   ; -> getauxval
0x148944  mov      x19, x0
0x148948  mov      w0, #0x1a
0x14894c  bl       #0x148e50   ; -> getauxval
0x148950  orr      x8, x19, #0x4000000000000000
0x148954  mov      w9, #0x18
0x148958  str      x0, [sp, #0x18]
0x14895c  add      x1, sp, #8
0x148960  mov      x0, x8
0x148964  stp      x9, x19, [sp, #8]
0x148968  bl       #0x1484ac   ; -> None
0x14896c  ldp      x30, x19, [sp, #0x80]
0x148970  add      sp, sp, #0x90
0x148974  autiasp  
0x148978  ret      
0x14897c  udf      #0
0x148980  bti      c
0x148984  adrp     x16, #0x155000
0x148988  ldrb     w16, [x16, #0xe60]
0x14898c  cbz      w16, #0x148998
0x148990  casa     w0, w1, [x2]
0x148994  ret      
0x148998  mov      w16, w0
0x14899c  ldaxr    w0, [x2]
0x1489a0  cmp      w0, w16
0x1489a4  b.ne     #0x1489b0
0x1489a8  stxr     w17, w1, [x2]
0x1489ac  cbnz     w17, #0x14899c
0x1489b0  ret      
0x1489b4  udf      #0
0x1489b8  udf      #0
0x1489bc  udf      #0
0x1489c0  stp      x16, x30, [sp, #-0x10]!
0x1489c4  adrp     x16, #0x14d000
0x1489c8  ldr      x17, [x16, #0x9d8]
0x1489cc  add      x16, x16, #0x9d8
0x1489d0  br       x17
0x1489d4  nop      
0x1489d8  nop      
0x1489dc  nop      
0x1489e0  adrp     x16, #0x14d000
0x1489e4  ldr      x17, [x16, #0x9e0]
0x1489e8  add      x16, x16, #0x9e0
0x1489ec  br       x17
0x1489f0  adrp     x16, #0x14d000
0x1489f4  ldr      x17, [x16, #0x9e8]
0x1489f8  add      x16, x16, #0x9e8
0x1489fc  br       x17
0x148a00  adrp     x16, #0x14d000
0x148a04  ldr      x17, [x16, #0x9f0]
0x148a08  add      x16, x16, #0x9f0
0x148a0c  br       x17
0x148a10  adrp     x16, #0x14d000
0x148a14  ldr      x17, [x16, #0x9f8]
0x148a18  add      x16, x16, #0x9f8
0x148a1c  br       x17
0x148a20  adrp     x16, #0x14d000
0x148a24  ldr      x17, [x16, #0xa00]
0x148a28  add      x16, x16, #0xa00
0x148a2c  br       x17
0x148a30  adrp     x16, #0x14d000
0x148a34  ldr      x17, [x16, #0xa08]
0x148a38  add      x16, x16, #0xa08
0x148a3c  br       x17
0x148a40  adrp     x16, #0x14d000
0x148a44  ldr      x17, [x16, #0xa10]
0x148a48  add      x16, x16, #0xa10
0x148a4c  br       x17
0x148a50  adrp     x16, #0x14d000
0x148a54  ldr      x17, [x16, #0xa18]
0x148a58  add      x16, x16, #0xa18
0x148a5c  br       x17
0x148a60  adrp     x16, #0x14d000
0x148a64  ldr      x17, [x16, #0xa20]
0x148a68  add      x16, x16, #0xa20
0x148a6c  br       x17
0x148a70  adrp     x16, #0x14d000
0x148a74  ldr      x17, [x16, #0xa28]
0x148a78  add      x16, x16, #0xa28
0x148a7c  br       x17
0x148a80  adrp     x16, #0x14d000
0x148a84  ldr      x17, [x16, #0xa30]
0x148a88  add      x16, x16, #0xa30
0x148a8c  br       x17
0x148a90  adrp     x16, #0x14d000
0x148a94  ldr      x17, [x16, #0xa38]
0x148a98  add      x16, x16, #0xa38
0x148a9c  br       x17
0x148aa0  adrp     x16, #0x14d000
0x148aa4  ldr      x17, [x16, #0xa40]
0x148aa8  add      x16, x16, #0xa40
0x148aac  br       x17
0x148ab0  adrp     x16, #0x14d000
0x148ab4  ldr      x17, [x16, #0xa48]
0x148ab8  add      x16, x16, #0xa48
0x148abc  br       x17
0x148ac0  adrp     x16, #0x14d000
0x148ac4  ldr      x17, [x16, #0xa50]
0x148ac8  add      x16, x16, #0xa50
0x148acc  br       x17
0x148ad0  adrp     x16, #0x14d000
0x148ad4  ldr      x17, [x16, #0xa58]
0x148ad8  add      x16, x16, #0xa58
0x148adc  br       x17
0x148ae0  adrp     x16, #0x14d000
0x148ae4  ldr      x17, [x16, #0xa60]
0x148ae8  add      x16, x16, #0xa60
0x148aec  br       x17
0x148af0  adrp     x16, #0x14d000
0x148af4  ldr      x17, [x16, #0xa68]
0x148af8  add      x16, x16, #0xa68
0x148afc  br       x17
0x148b00  adrp     x16, #0x14d000
0x148b04  ldr      x17, [x16, #0xa70]
0x148b08  add      x16, x16, #0xa70
0x148b0c  br       x17
0x148b10  adrp     x16, #0x14d000
0x148b14  ldr      x17, [x16, #0xa78]
0x148b18  add      x16, x16, #0xa78
0x148b1c  br       x17
0x148b20  adrp     x16, #0x14d000
0x148b24  ldr      x17, [x16, #0xa80]
0x148b28  add      x16, x16, #0xa80
0x148b2c  br       x17
0x148b30  adrp     x16, #0x14d000
0x148b34  ldr      x17, [x16, #0xa88]
0x148b38  add      x16, x16, #0xa88
0x148b3c  br       x17
0x148b40  adrp     x16, #0x14d000
0x148b44  ldr      x17, [x16, #0xa90]
0x148b48  add      x16, x16, #0xa90
0x148b4c  br       x17
0x148b50  adrp     x16, #0x14d000
0x148b54  ldr      x17, [x16, #0xa98]
0x148b58  add      x16, x16, #0xa98
0x148b5c  br       x17
0x148b60  adrp     x16, #0x14d000
0x148b64  ldr      x17, [x16, #0xaa0]
0x148b68  add      x16, x16, #0xaa0
0x148b6c  br       x17
0x148b70  adrp     x16, #0x14d000
0x148b74  ldr      x17, [x16, #0xaa8]
0x148b78  add      x16, x16, #0xaa8
0x148b7c  br       x17
0x148b80  adrp     x16, #0x14d000
0x148b84  ldr      x17, [x16, #0xab0]
0x148b88  add      x16, x16, #0xab0
0x148b8c  br       x17
0x148b90  adrp     x16, #0x14d000
0x148b94  ldr      x17, [x16, #0xab8]
0x148b98  add      x16, x16, #0xab8
0x148b9c  br       x17
0x148ba0  adrp     x16, #0x14d000
0x148ba4  ldr      x17, [x16, #0xac0]
0x148ba8  add      x16, x16, #0xac0
0x148bac  br       x17
0x148bb0  adrp     x16, #0x14d000
0x148bb4  ldr      x17, [x16, #0xac8]
0x148bb8  add      x16, x16, #0xac8
0x148bbc  br       x17
0x148bc0  adrp     x16, #0x14d000
0x148bc4  ldr      x17, [x16, #0xad0]
0x148bc8  add      x16, x16, #0xad0
0x148bcc  br       x17
0x148bd0  adrp     x16, #0x14d000
0x148bd4  ldr      x17, [x16, #0xad8]
0x148bd8  add      x16, x16, #0xad8
0x148bdc  br       x17
0x148be0  adrp     x16, #0x14d000
0x148be4  ldr      x17, [x16, #0xae0]
0x148be8  add      x16, x16, #0xae0
0x148bec  br       x17
0x148bf0  adrp     x16, #0x14d000
0x148bf4  ldr      x17, [x16, #0xae8]
0x148bf8  add      x16, x16, #0xae8
0x148bfc  br       x17
0x148c00  adrp     x16, #0x14d000
0x148c04  ldr      x17, [x16, #0xaf0]
0x148c08  add      x16, x16, #0xaf0
0x148c0c  br       x17
0x148c10  adrp     x16, #0x14d000
0x148c14  ldr      x17, [x16, #0xaf8]
0x148c18  add      x16, x16, #0xaf8
0x148c1c  br       x17
0x148c20  adrp     x16, #0x14d000
0x148c24  ldr      x17, [x16, #0xb00]
0x148c28  add      x16, x16, #0xb00
0x148c2c  br       x17
0x148c30  adrp     x16, #0x14d000
0x148c34  ldr      x17, [x16, #0xb08]
0x148c38  add      x16, x16, #0xb08
0x148c3c  br       x17
0x148c40  adrp     x16, #0x14d000
0x148c44  ldr      x17, [x16, #0xb10]
0x148c48  add      x16, x16, #0xb10
0x148c4c  br       x17
0x148c50  adrp     x16, #0x14d000
0x148c54  ldr      x17, [x16, #0xb18]
0x148c58  add      x16, x16, #0xb18
0x148c5c  br       x17
0x148c60  adrp     x16, #0x14d000
0x148c64  ldr      x17, [x16, #0xb20]
0x148c68  add      x16, x16, #0xb20
0x148c6c  br       x17
0x148c70  adrp     x16, #0x14d000
0x148c74  ldr      x17, [x16, #0xb28]
0x148c78  add      x16, x16, #0xb28
0x148c7c  br       x17
0x148c80  adrp     x16, #0x14d000
0x148c84  ldr      x17, [x16, #0xb30]
0x148c88  add      x16, x16, #0xb30
0x148c8c  br       x17
0x148c90  adrp     x16, #0x14d000
0x148c94  ldr      x17, [x16, #0xb38]
0x148c98  add      x16, x16, #0xb38
0x148c9c  br       x17
0x148ca0  adrp     x16, #0x14d000
0x148ca4  ldr      x17, [x16, #0xb40]
0x148ca8  add      x16, x16, #0xb40
0x148cac  br       x17
0x148cb0  adrp     x16, #0x14d000
0x148cb4  ldr      x17, [x16, #0xb48]
0x148cb8  add      x16, x16, #0xb48
0x148cbc  br       x17
0x148cc0  adrp     x16, #0x14d000
0x148cc4  ldr      x17, [x16, #0xb50]
0x148cc8  add      x16, x16, #0xb50
0x148ccc  br       x17
0x148cd0  adrp     x16, #0x14d000
0x148cd4  ldr      x17, [x16, #0xb58]
0x148cd8  add      x16, x16, #0xb58
0x148cdc  br       x17
0x148ce0  adrp     x16, #0x14d000
0x148ce4  ldr      x17, [x16, #0xb60]
0x148ce8  add      x16, x16, #0xb60
0x148cec  br       x17
0x148cf0  adrp     x16, #0x14d000
0x148cf4  ldr      x17, [x16, #0xb68]
0x148cf8  add      x16, x16, #0xb68
0x148cfc  br       x17
0x148d00  adrp     x16, #0x14d000
0x148d04  ldr      x17, [x16, #0xb70]
0x148d08  add      x16, x16, #0xb70
0x148d0c  br       x17
0x148d10  adrp     x16, #0x14d000
0x148d14  ldr      x17, [x16, #0xb78]
0x148d18  add      x16, x16, #0xb78
0x148d1c  br       x17
0x148d20  adrp     x16, #0x14d000
0x148d24  ldr      x17, [x16, #0xb80]
0x148d28  add      x16, x16, #0xb80
0x148d2c  br       x17
0x148d30  adrp     x16, #0x14d000
0x148d34  ldr      x17, [x16, #0xb88]
0x148d38  add      x16, x16, #0xb88
0x148d3c  br       x17
0x148d40  adrp     x16, #0x14d000
0x148d44  ldr      x17, [x16, #0xb90]
0x148d48  add      x16, x16, #0xb90
0x148d4c  br       x17
0x148d50  adrp     x16, #0x14d000
0x148d54  ldr      x17, [x16, #0xb98]
0x148d58  add      x16, x16, #0xb98
0x148d5c  br       x17
0x148d60  adrp     x16, #0x14d000
0x148d64  ldr      x17, [x16, #0xba0]
0x148d68  add      x16, x16, #0xba0
0x148d6c  br       x17
0x148d70  adrp     x16, #0x14d000
0x148d74  ldr      x17, [x16, #0xba8]
0x148d78  add      x16, x16, #0xba8
0x148d7c  br       x17
0x148d80  adrp     x16, #0x14d000
0x148d84  ldr      x17, [x16, #0xbb0]
0x148d88  add      x16, x16, #0xbb0
0x148d8c  br       x17
0x148d90  adrp     x16, #0x14d000
0x148d94  ldr      x17, [x16, #0xbb8]
0x148d98  add      x16, x16, #0xbb8
0x148d9c  br       x17
0x148da0  adrp     x16, #0x14d000
0x148da4  ldr      x17, [x16, #0xbc0]
0x148da8  add      x16, x16, #0xbc0
0x148dac  br       x17
0x148db0  adrp     x16, #0x14d000
0x148db4  ldr      x17, [x16, #0xbc8]
0x148db8  add      x16, x16, #0xbc8
0x148dbc  br       x17
0x148dc0  adrp     x16, #0x14d000
0x148dc4  ldr      x17, [x16, #0xbd0]
0x148dc8  add      x16, x16, #0xbd0
0x148dcc  br       x17
0x148dd0  adrp     x16, #0x14d000
0x148dd4  ldr      x17, [x16, #0xbd8]
0x148dd8  add      x16, x16, #0xbd8
0x148ddc  br       x17
0x148de0  adrp     x16, #0x14d000
0x148de4  ldr      x17, [x16, #0xbe0]
0x148de8  add      x16, x16, #0xbe0
0x148dec  br       x17
0x148df0  adrp     x16, #0x14d000
0x148df4  ldr      x17, [x16, #0xbe8]
0x148df8  add      x16, x16, #0xbe8
0x148dfc  br       x17
0x148e00  adrp     x16, #0x14d000
0x148e04  ldr      x17, [x16, #0xbf0]
0x148e08  add      x16, x16, #0xbf0
0x148e0c  br       x17
0x148e10  adrp     x16, #0x14d000
0x148e14  ldr      x17, [x16, #0xbf8]
0x148e18  add      x16, x16, #0xbf8
0x148e1c  br       x17
0x148e20  adrp     x16, #0x14d000
0x148e24  ldr      x17, [x16, #0xc00]
0x148e28  add      x16, x16, #0xc00
0x148e2c  br       x17
0x148e30  adrp     x16, #0x14d000
0x148e34  ldr      x17, [x16, #0xc08]
0x148e38  add      x16, x16, #0xc08
0x148e3c  br       x17
0x148e40  adrp     x16, #0x14d000
0x148e44  ldr      x17, [x16, #0xc10]
0x148e48  add      x16, x16, #0xc10
0x148e4c  br       x17
0x148e50  adrp     x16, #0x14d000
0x148e54  ldr      x17, [x16, #0xc18]
0x148e58  add      x16, x16, #0xc18
0x148e5c  br       x17
0x148e60  udf      #0
0x148e64  udf      #0
0x148e68  udf      #0
0x148e6c  udf      #0
0x148e70  udf      #0
0x148e74  udf      #0
0x148e78  udf      #0
0x148e7c  udf      #0
0x148e80  udf      #0
0x148e84  udf      #0
0x148e88  udf      #0
0x148e8c  udf      #0
0x148e90  udf      #0
0x148e94  udf      #0
0x148e98  udf      #0
0x148e9c  udf      #0
0x148ea0  udf      #0
0x148ea4  udf      #0
0x148ea8  udf      #0
0x148eac  udf      #0
0x148eb0  udf      #0
0x148eb4  udf      #0
0x148eb8  udf      #0
0x148ebc  udf      #0
0x148ec0  udf      #0
0x148ec4  udf      #0
0x148ec8  udf      #0
0x148ecc  udf      #0
0x148ed0  udf      #0
0x148ed4  udf      #0
0x148ed8  udf      #0
0x148edc  udf      #0
0x148ee0  udf      #0
0x148ee4  udf      #0
0x148ee8  udf      #0
0x148eec  udf      #0
0x148ef0  udf      #0
0x148ef4  udf      #0
0x148ef8  udf      #0
0x148efc  udf      #0
0x148f00  udf      #0
0x148f04  udf      #0
0x148f08  udf      #0
0x148f0c  udf      #0
0x148f10  udf      #0
0x148f14  udf      #0
0x148f18  udf      #0
0x148f1c  udf      #0
0x148f20  udf      #0
0x148f24  udf      #0
0x148f28  udf      #0
0x148f2c  udf      #0
0x148f30  udf      #0
0x148f34  udf      #0
0x148f38  udf      #0
0x148f3c  udf      #0
0x148f40  udf      #0
0x148f44  udf      #0
0x148f48  udf      #0
0x148f4c  udf      #0
0x148f50  udf      #0
0x148f54  udf      #0
0x148f58  udf      #0
0x148f5c  udf      #0
0x148f60  udf      #0
0x148f64  udf      #0
0x148f68  udf      #0
0x148f6c  udf      #0
0x148f70  udf      #0
0x148f74  udf      #0
0x148f78  udf      #0
0x148f7c  udf      #0
0x148f80  udf      #0
0x148f84  udf      #0
0x148f88  udf      #0
0x148f8c  udf      #0
0x148f90  udf      #0
0x148f94  udf      #0
0x148f98  udf      #0
0x148f9c  udf      #0
0x148fa0  udf      #0
0x148fa4  udf      #0
0x148fa8  udf      #0
0x148fac  udf      #0
0x148fb0  udf      #0
0x148fb4  udf      #0
0x148fb8  udf      #0
0x148fbc  udf      #0
0x148fc0  udf      #0
0x148fc4  udf      #0
0x148fc8  udf      #0
0x148fcc  udf      #0
0x148fd0  udf      #0
0x148fd4  udf      #0
0x148fd8  udf      #0
0x148fdc  udf      #0
0x148fe0  udf      #0
0x148fe4  udf      #0
0x148fe8  udf      #0
0x148fec  udf      #0
0x148ff0  udf      #0
0x148ff4  udf      #0
0x148ff8  udf      #0
0x148ffc  udf      #0
0x149000  udf      #0
0x149004  udf      #0
0x149008  udf      #0
0x14900c  udf      #0
0x149010  udf      #0
0x149014  udf      #0
0x149018  udf      #0
0x14901c  udf      #0
0x149020  udf      #0
0x149024  udf      #0
0x149028  udf      #0
0x14902c  udf      #0
0x149030  udf      #0
0x149034  udf      #0
0x149038  udf      #0
0x14903c  udf      #0
0x149040  udf      #0
0x149044  udf      #0
0x149048  udf      #0
0x14904c  udf      #0
0x149050  udf      #0
0x149054  udf      #0
0x149058  udf      #0
0x14905c  udf      #0
0x149060  udf      #0
0x149064  udf      #0
0x149068  udf      #0
0x14906c  udf      #0
0x149070  udf      #0
0x149074  udf      #0
0x149078  udf      #0
0x14907c  udf      #0
0x149080  udf      #0
0x149084  udf      #0
0x149088  udf      #0
0x14908c  udf      #0
0x149090  udf      #0
0x149094  udf      #0
0x149098  udf      #0
0x14909c  udf      #0
0x1490a0  udf      #0
0x1490a4  udf      #0
0x1490a8  udf      #0
0x1490ac  udf      #0
0x1490b0  udf      #0
0x1490b4  udf      #0
0x1490b8  udf      #0
0x1490bc  udf      #0
0x1490c0  udf      #0
0x1490c4  udf      #0
0x1490c8  udf      #0
0x1490cc  udf      #0
0x1490d0  udf      #0
0x1490d4  udf      #0
0x1490d8  udf      #0
0x1490dc  udf      #0
0x1490e0  udf      #0
0x1490e4  udf      #0
0x1490e8  udf      #0
0x1490ec  udf      #0
0x1490f0  udf      #0
0x1490f4  udf      #0
0x1490f8  udf      #0
0x1490fc  udf      #0
0x149100  udf      #0
0x149104  udf      #0
0x149108  udf      #0
0x14910c  udf      #0
0x149110  udf      #0
0x149114  udf      #0
0x149118  udf      #0
0x14911c  udf      #0
0x149120  udf      #0
0x149124  udf      #0
0x149128  udf      #0
0x14912c  udf      #0
0x149130  udf      #0
0x149134  udf      #0
0x149138  udf      #0
0x14913c  udf      #0
0x149140  udf      #0
0x149144  udf      #0
0x149148  udf      #0
0x14914c  udf      #0
0x149150  udf      #0
0x149154  udf      #0
0x149158  udf      #0
0x14915c  udf      #0
0x149160  udf      #0
0x149164  udf      #0
0x149168  udf      #0
0x14916c  udf      #0
0x149170  udf      #0
0x149174  udf      #0
0x149178  udf      #0
0x14917c  udf      #0
0x149180  udf      #0
0x149184  udf      #0
0x149188  udf      #0
0x14918c  udf      #0
0x149190  udf      #0
0x149194  udf      #0
0x149198  udf      #0
0x14919c  udf      #0
0x1491a0  udf      #0
0x1491a4  udf      #0
0x1491a8  udf      #0
0x1491ac  udf      #0
0x1491b0  udf      #0
0x1491b4  udf      #0
0x1491b8  udf      #0
0x1491bc  udf      #0
0x1491c0  udf      #0
0x1491c4  udf      #0
0x1491c8  udf      #0
0x1491cc  udf      #0
0x1491d0  udf      #0
0x1491d4  udf      #0
0x1491d8  udf      #0
0x1491dc  udf      #0
0x1491e0  udf      #0
0x1491e4  udf      #0
0x1491e8  udf      #0
0x1491ec  udf      #0
0x1491f0  udf      #0
0x1491f4  udf      #0
0x1491f8  udf      #0
0x1491fc  udf      #0
0x149200  udf      #0
0x149204  udf      #0
0x149208  udf      #0
0x14920c  udf      #0
0x149210  udf      #0
0x149214  udf      #0
0x149218  udf      #0
0x14921c  udf      #0
0x149220  udf      #0
0x149224  udf      #0
0x149228  udf      #0
0x14922c  udf      #0
0x149230  udf      #0
0x149234  udf      #0
0x149238  udf      #0
0x14923c  udf      #0
0x149240  udf      #0
0x149244  udf      #0
0x149248  udf      #0
0x14924c  udf      #0
0x149250  udf      #0
0x149254  udf      #0
0x149258  udf      #0
0x14925c  udf      #0
0x149260  udf      #0
0x149264  udf      #0
0x149268  udf      #0
0x14926c  udf      #0
0x149270  udf      #0
0x149274  udf      #0
0x149278  udf      #0
0x14927c  udf      #0
0x149280  udf      #0
0x149284  udf      #0
0x149288  udf      #0
0x14928c  udf      #0
0x149290  udf      #0
0x149294  udf      #0
0x149298  udf      #0
0x14929c  udf      #0
0x1492a0  udf      #0
0x1492a4  udf      #0
0x1492a8  udf      #0
0x1492ac  udf      #0
0x1492b0  udf      #0
0x1492b4  udf      #0
0x1492b8  udf      #0
0x1492bc  udf      #0
0x1492c0  udf      #0
0x1492c4  udf      #0
0x1492c8  udf      #0
0x1492cc  udf      #0
0x1492d0  udf      #0
0x1492d4  udf      #0
0x1492d8  udf      #0
0x1492dc  udf      #0
0x1492e0  udf      #0
0x1492e4  udf      #0
0x1492e8  udf      #0
0x1492ec  udf      #0
0x1492f0  udf      #0
0x1492f4  udf      #0
0x1492f8  udf      #0
0x1492fc  udf      #0
0x149300  udf      #0
0x149304  udf      #0
0x149308  udf      #0
0x14930c  udf      #0
0x149310  udf      #0
0x149314  udf      #0
0x149318  udf      #0
0x14931c  udf      #0
0x149320  udf      #0
0x149324  udf      #0
0x149328  udf      #0
0x14932c  udf      #0
0x149330  udf      #0
0x149334  udf      #0
0x149338  udf      #0
0x14933c  udf      #0
0x149340  udf      #0
0x149344  udf      #0
0x149348  udf      #0
0x14934c  udf      #0
0x149350  udf      #0
0x149354  udf      #0
0x149358  udf      #0
0x14935c  udf      #0
0x149360  udf      #0
0x149364  udf      #0
0x149368  udf      #0
0x14936c  udf      #0
0x149370  udf      #0
0x149374  udf      #0
0x149378  udf      #0
0x14937c  udf      #0
0x149380  udf      #0
0x149384  udf      #0
0x149388  udf      #0
0x14938c  udf      #0
0x149390  udf      #0
0x149394  udf      #0
0x149398  udf      #0
0x14939c  udf      #0
0x1493a0  udf      #0
0x1493a4  udf      #0
0x1493a8  udf      #0
0x1493ac  udf      #0
0x1493b0  udf      #0
0x1493b4  udf      #0
0x1493b8  udf      #0
0x1493bc  udf      #0
0x1493c0  udf      #0
0x1493c4  udf      #0
0x1493c8  udf      #0
0x1493cc  udf      #0
0x1493d0  udf      #0
0x1493d4  udf      #0
0x1493d8  udf      #0
0x1493dc  udf      #0
0x1493e0  udf      #0
0x1493e4  udf      #0
0x1493e8  udf      #0
0x1493ec  udf      #0
0x1493f0  udf      #0
0x1493f4  udf      #0
0x1493f8  udf      #0
0x1493fc  udf      #0
0x149400  udf      #0
0x149404  udf      #0
0x149408  udf      #0
0x14940c  udf      #0
0x149410  udf      #0
0x149414  udf      #0
0x149418  udf      #0
0x14941c  udf      #0
0x149420  udf      #0
0x149424  udf      #0
0x149428  udf      #0
0x14942c  udf      #0
0x149430  udf      #0
0x149434  udf      #0
0x149438  udf      #0
0x14943c  udf      #0
0x149440  udf      #0
0x149444  udf      #0
0x149448  udf      #0
0x14944c  udf      #0
0x149450  udf      #0
0x149454  udf      #0
0x149458  udf      #0
0x14945c  udf      #0
0x149460  udf      #0
0x149464  udf      #0
0x149468  udf      #0
0x14946c  udf      #0
0x149470  udf      #0
0x149474  udf      #0
0x149478  udf      #0
0x14947c  udf      #0
0x149480  udf      #0
0x149484  udf      #0
0x149488  udf      #0
0x14948c  udf      #0
0x149490  udf      #0
0x149494  udf      #0
0x149498  udf      #0
0x14949c  udf      #0
0x1494a0  udf      #0
0x1494a4  udf      #0
0x1494a8  udf      #0
0x1494ac  udf      #0
0x1494b0  udf      #0
0x1494b4  udf      #0
0x1494b8  udf      #0
0x1494bc  udf      #0
0x1494c0  udf      #0
0x1494c4  udf      #0
0x1494c8  udf      #0
0x1494cc  udf      #0
0x1494d0  udf      #0
0x1494d4  udf      #0
0x1494d8  udf      #0
0x1494dc  udf      #0
0x1494e0  udf      #0
0x1494e4  udf      #0
0x1494e8  udf      #0
0x1494ec  udf      #0
0x1494f0  udf      #0
0x1494f4  udf      #0
0x1494f8  udf      #0
0x1494fc  udf      #0
0x149500  udf      #0
0x149504  udf      #0
0x149508  udf      #0
0x14950c  udf      #0
0x149510  udf      #0
0x149514  udf      #0
0x149518  udf      #0
0x14951c  udf      #0
0x149520  udf      #0
0x149524  udf      #0
0x149528  udf      #0
0x14952c  udf      #0
0x149530  udf      #0
0x149534  udf      #0
0x149538  udf      #0
0x14953c  udf      #0
0x149540  udf      #0
0x149544  udf      #0
0x149548  udf      #0
0x14954c  udf      #0
0x149550  udf      #0
0x149554  udf      #0
0x149558  udf      #0
0x14955c  udf      #0
0x149560  udf      #0
0x149564  udf      #0
0x149568  udf      #0
0x14956c  udf      #0
0x149570  udf      #0
0x149574  udf      #0
0x149578  udf      #0
0x14957c  udf      #0
0x149580  udf      #0
0x149584  udf      #0
0x149588  udf      #0
0x14958c  udf      #0
0x149590  udf      #0
0x149594  udf      #0
0x149598  udf      #0
0x14959c  udf      #0
0x1495a0  udf      #0
0x1495a4  udf      #0
0x1495a8  udf      #0
0x1495ac  udf      #0
0x1495b0  udf      #0
0x1495b4  udf      #0
0x1495b8  udf      #0
0x1495bc  udf      #0
0x1495c0  udf      #0
0x1495c4  udf      #0
0x1495c8  udf      #0
0x1495cc  udf      #0
0x1495d0  udf      #0
0x1495d4  udf      #0
0x1495d8  udf      #0
0x1495dc  udf      #0
0x1495e0  udf      #0
0x1495e4  udf      #0
0x1495e8  udf      #0
0x1495ec  udf      #0
0x1495f0  udf      #0
0x1495f4  udf      #0
0x1495f8  udf      #0
0x1495fc  udf      #0
0x149600  udf      #0
0x149604  udf      #0
0x149608  udf      #0
0x14960c  udf      #0
0x149610  udf      #0
0x149614  udf      #0
0x149618  udf      #0
0x14961c  udf      #0
0x149620  udf      #0
0x149624  udf      #0
0x149628  udf      #0
0x14962c  udf      #0
