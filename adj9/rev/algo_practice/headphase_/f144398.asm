00144398  sub      sp, sp, #0x1b0
0014439c  stp      x29, x30, [sp, #0x150]
001443a0  stp      x28, x27, [sp, #0x160]
001443a4  stp      x26, x25, [sp, #0x170]
001443a8  stp      x24, x23, [sp, #0x180]
001443ac  stp      x22, x21, [sp, #0x190]
001443b0  stp      x20, x19, [sp, #0x1a0]
001443b4  add      x29, sp, #0x150
001443b8  str      x6, [sp, #0xa0]
001443bc  mov      x16, x1
001443c0  stp      x4, x5, [sp, #0x20]
001443c4  mov      x1, #0x507b
001443c8  stp      x2, x3, [sp, #0x10]
001443cc  mov      x2, #0xc335
001443d0  mov      x3, #0x865
001443d4  mov      x4, #0x8d87
001443d8  mov      x5, #0xc2a2
001443dc  mov      x6, #0x1859
001443e0  mov      x19, #0xe386
001443e4  mov      x30, #0xd05b
001443e8  mov      x17, #0xb7cc
001443ec  mov      x15, #0x8e81
001443f0  str      x0, [sp, #8]
001443f4  movk     x1, #0x2c50, lsl #16
001443f8  stur     wzr, [x29, #-0x34]
001443fc  movk     x2, #0x1484, lsl #16
00144400  str      wzr, [sp, #0x94]
00144404  movk     x3, #0x5362, lsl #16
00144408  stur     wzr, [x29, #-0x4c]
0014440c  mrs      x8, tpidr_el0
00144410  movk     x4, #0xa2f3, lsl #16
00144414  movk     x5, #0x1048, lsl #16
00144418  movk     x6, #0x2b53, lsl #16
0014441c  movk     x19, #0xeab8, lsl #16
00144420  movk     x30, #0xef20, lsl #16
00144424  movk     x17, #0xff64, lsl #16
00144428  movk     x15, #0xe154, lsl #16
0014442c  str      x8, [sp]
00144430  movk     x1, #0x48ac, lsl #32
00144434  movk     x2, #0x16b3, lsl #32
00144438  movk     x3, #0x98ea, lsl #32
0014443c  movk     x4, #0x8648, lsl #32
00144440  movk     x5, #0x7104, lsl #32
00144444  movk     x6, #0x6ffc, lsl #32
00144448  movk     x19, #0xc1ec, lsl #32
0014444c  movk     x30, #0x96cc, lsl #32
00144450  movk     x17, #0xf23e, lsl #32
00144454  movk     x15, #0x3b5e, lsl #32
00144458  mov      w11, wzr
0014445c  ldr      x8, [x8, #0x28]
00144460  movk     x1, #0xc90b, lsl #48
00144464  movk     x2, #0xb3cc, lsl #48
00144468  movk     x3, #0xabfd, lsl #48
0014446c  movk     x4, #0xa5e3, lsl #48
00144470  movk     x5, #0x9ffe, lsl #48
00144474  movk     x6, #0x930b, lsl #48
00144478  movk     x19, #0x808f, lsl #48
0014447c  movk     x30, #0x8753, lsl #48
00144480  movk     x17, #0x8f3d, lsl #48
00144484  movk     x15, #0x7cc5, lsl #48
00144488  stur     x8, [x29, #-0x10]
0014448c  stur     wzr, [x29, #-0x18]
00144490  stur     xzr, [x29, #-0x20]
00144494  str      x16, [sp, #0x98]
00144498  mov      x14, x15
0014449c  mov      x15, #0xc2a2
001444a0  movk     x15, #0x1048, lsl #16
001444a4  cmp      x14, x19
001444a8  movk     x15, #0x7104, lsl #32
001444ac  movk     x15, #0x9ffe, lsl #48
001444b0  b.eq     #0x144498
001444b4  mov      x24, x16
001444b8  mov      x21, x13
001444bc  mov      w28, w11
001444c0  mov      x25, x10
001444c4  mov      x27, x9
001444c8  mov      x20, x8
001444cc  cmp      x14, x30
001444d0  b.eq     #0x145578
001444d4  mov      x23, x12
001444d8  cmp      x14, x17
001444dc  b.eq     #0x144e40
001444e0  cmp      x14, x6
001444e4  b.eq     #0x144c64
001444e8  mov      x8, #0x8a0
001444ec  movk     x8, #0xbd15, lsl #16
001444f0  movk     x8, #0xb02c, lsl #32
001444f4  movk     x8, #0x93e7, lsl #48
001444f8  cmp      x14, x8
001444fc  b.eq     #0x1455c0
00144500  cmp      x14, x5
00144504  b.eq     #0x144bf4
00144508  mov      x15, #0x754
0014450c  mov      x7, #0x1471
00144510  movk     x15, #0xa078, lsl #16
00144514  movk     x7, #0x4a0, lsl #16
00144518  movk     x15, #0x1f94, lsl #32
0014451c  mov      x8, x20
00144520  mov      x9, x27
00144524  mov      x10, x25
00144528  mov      w11, w28
0014452c  mov      x12, x23
00144530  mov      x13, x21
00144534  mov      x16, x24
00144538  movk     x15, #0x3282, lsl #48
0014453c  movk     x7, #0x5fd, lsl #32
00144540  movk     x7, #0xa11a, lsl #48
00144544  cmp      x14, x7
00144548  b.eq     #0x144498
0014454c  cmp      x14, x4
00144550  b.eq     #0x1453d0
00144554  mov      x15, #0x8d87
00144558  mov      x8, x20
0014455c  movk     x15, #0xa2f3, lsl #16
00144560  mov      x9, x27
00144564  movk     x15, #0x8648, lsl #32
00144568  mov      x10, x25
0014456c  mov      w11, w28
00144570  mov      x12, x23
00144574  mov      x13, x21
00144578  mov      x16, x24
0014457c  movk     x15, #0xa5e3, lsl #48
00144580  cmp      x14, x3
00144584  b.eq     #0x144498
00144588  mov      x8, #0xafb5
0014458c  movk     x8, #0xa12b, lsl #16
00144590  movk     x8, #0xce93, lsl #32
00144594  movk     x8, #0xb225, lsl #48
00144598  cmp      x14, x8
0014459c  b.eq     #0x145070
001445a0  cmp      x14, x2
001445a4  b.eq     #0x144c24
001445a8  mov      x8, #0x1381
001445ac  movk     x8, #0xa58a, lsl #16
001445b0  movk     x8, #0xb763, lsl #32
001445b4  movk     x8, #0xbbcd, lsl #48
001445b8  cmp      x14, x8
001445bc  b.eq     #0x144d08
001445c0  mov      x15, #0x28cc
001445c4  mov      x7, #0xfe0a
001445c8  movk     x15, #0xc3e2, lsl #16
001445cc  movk     x7, #0x69fd, lsl #16
001445d0  movk     x15, #0x7819, lsl #32
001445d4  mov      x8, x20
001445d8  mov      x9, x27
001445dc  mov      x10, x25
001445e0  mov      w11, w28
001445e4  mov      x12, x23
001445e8  mov      x13, x21
001445ec  mov      x16, x24
001445f0  movk     x15, #0x6b85, lsl #48
001445f4  movk     x7, #0x5f3a, lsl #32
001445f8  movk     x7, #0xbdc7, lsl #48
001445fc  cmp      x14, x7
00144600  b.eq     #0x144498
00144604  mov      x8, #0xdf4a
00144608  movk     x8, #0xbdc8, lsl #16
0014460c  movk     x8, #0xceb, lsl #32
00144610  movk     x8, #0xc8d5, lsl #48
00144614  cmp      x14, x8
00144618  b.eq     #0x14502c
0014461c  cmp      x14, x1
00144620  b.eq     #0x145254
00144624  mov      x8, #0x113f
00144628  movk     x8, #0xceaf, lsl #16
0014462c  movk     x8, #0x4fe6, lsl #32
00144630  movk     x8, #0xe9ff, lsl #48
00144634  cmp      x14, x8
00144638  b.eq     #0x1450e0
0014463c  mov      x15, #0x8d87
00144640  mov      x7, #0x25ce
00144644  movk     x15, #0xa2f3, lsl #16
00144648  movk     x7, #0x8c3e, lsl #16
0014464c  movk     x15, #0x8648, lsl #32
00144650  mov      x8, x20
00144654  mov      x9, x27
00144658  mov      x10, x25
0014465c  mov      w11, w28
00144660  mov      x12, x23
00144664  mov      x13, x21
00144668  mov      x16, x24
0014466c  movk     x15, #0xa5e3, lsl #48
00144670  movk     x7, #0xdec2, lsl #32
00144674  movk     x7, #0xf201, lsl #48
00144678  cmp      x14, x7
0014467c  b.eq     #0x144498
00144680  mov      x15, #0x3581
00144684  mov      x7, #0x2f9c
00144688  movk     x15, #0xbcba, lsl #16
0014468c  movk     x7, #0xc396, lsl #16
00144690  movk     x15, #0x133, lsl #32
00144694  mov      x8, x20
00144698  mov      x9, x27
0014469c  mov      x10, x25
001446a0  mov      w11, w28
001446a4  mov      x12, x23
001446a8  mov      x13, x21
001446ac  mov      x16, x24
001446b0  movk     x15, #0x761f, lsl #48
001446b4  movk     x7, #0x5e8f, lsl #32
001446b8  movk     x7, #0xf2cd, lsl #48
001446bc  cmp      x14, x7
001446c0  b.eq     #0x144498
001446c4  mov      x8, #0x9a1f
001446c8  movk     x8, #0xd6a5, lsl #16
001446cc  movk     x8, #0xc885, lsl #32
001446d0  movk     x8, #0xf611, lsl #48
001446d4  cmp      x14, x8
001446d8  b.eq     #0x144f2c
001446dc  mov      x8, #0x7811
001446e0  movk     x8, #0x740, lsl #16
001446e4  movk     x8, #0x67ad, lsl #32
001446e8  movk     x8, #0xf79c, lsl #48
001446ec  cmp      x14, x8
001446f0  b.eq     #0x145494
001446f4  mov      x15, #0x5dae
001446f8  mov      x7, #0xa74a
001446fc  movk     x15, #0xbd6e, lsl #16
00144700  movk     x7, #0x5ea3, lsl #16
00144704  movk     x15, #0x6aaa, lsl #32
00144708  mov      x8, x20
0014470c  mov      x9, x27
00144710  mov      x10, x25
00144714  mov      w11, w28
00144718  mov      x12, x23
0014471c  mov      x13, x21
00144720  mov      x16, x22
00144724  movk     x15, #0x28f0, lsl #48
00144728  movk     x7, #0xa04f, lsl #32
0014472c  movk     x7, #0xfa1e, lsl #48
00144730  cmp      x14, x7
00144734  b.eq     #0x144498
00144738  mov      x15, #0x865
0014473c  mov      x7, #0xcdf8
00144740  movk     x15, #0x5362, lsl #16
00144744  movk     x7, #0xd72b, lsl #16
00144748  movk     x15, #0x98ea, lsl #32
0014474c  mov      x8, x20
00144750  mov      x9, x27
00144754  mov      x10, x25
00144758  mov      w11, w28
0014475c  mov      x12, x23
00144760  mov      x13, x21
00144764  mov      x16, x24
00144768  movk     x15, #0xabfd, lsl #48
0014476c  movk     x7, #0x55aa, lsl #32
00144770  movk     x7, #0xfe6b, lsl #48
00144774  cmp      x14, x7
00144778  b.eq     #0x144498
0014477c  mov      x8, #0x8779
00144780  movk     x8, #0xf1b8, lsl #16
00144784  movk     x8, #0x3378, lsl #32
00144788  movk     x8, #0xeb0, lsl #48
0014478c  cmp      x14, x8
00144790  b.eq     #0x144ee4
00144794  mov      x15, #0x1859
00144798  mov      x7, #0xea12
0014479c  movk     x15, #0x2b53, lsl #16
001447a0  movk     x7, #0x2ac8, lsl #16
001447a4  movk     x15, #0x6ffc, lsl #32
001447a8  mov      x8, x20
001447ac  mov      x9, x27
001447b0  mov      x10, x25
001447b4  mov      w11, w28
001447b8  mov      x12, x0
001447bc  mov      x13, x21
001447c0  mov      x16, x24
001447c4  movk     x15, #0x930b, lsl #48
001447c8  movk     x7, #0x1d60, lsl #32
001447cc  movk     x7, #0x1023, lsl #48
001447d0  cmp      x14, x7
001447d4  b.eq     #0x144498
001447d8  mov      x15, #0x754
001447dc  mov      x7, #0xcd53
001447e0  movk     x15, #0xa078, lsl #16
001447e4  movk     x7, #0xade6, lsl #16
001447e8  movk     x15, #0x1f94, lsl #32
001447ec  mov      x8, x20
001447f0  mov      x9, x27
001447f4  mov      x10, x25
001447f8  mov      w11, w28
001447fc  mov      x12, x23
00144800  mov      x13, x21
00144804  mov      x16, x24
00144808  movk     x15, #0x3282, lsl #48
0014480c  movk     x7, #0xefff, lsl #32
00144810  movk     x7, #0x13d4, lsl #48
00144814  cmp      x14, x7
00144818  b.eq     #0x144498
0014481c  mov      x15, #0xc2a2
00144820  mov      x7, #0xb3d0
00144824  movk     x15, #0x1048, lsl #16
00144828  movk     x7, #0x566, lsl #16
0014482c  movk     x15, #0x7104, lsl #32
00144830  mov      x8, x20
00144834  mov      x9, x27
00144838  mov      x10, x25
0014483c  mov      w11, w28
00144840  mov      x12, x23
00144844  mov      x13, x21
00144848  mov      x16, x24
0014484c  movk     x15, #0x9ffe, lsl #48
00144850  movk     x7, #0xa50d, lsl #32
00144854  movk     x7, #0x204a, lsl #48
00144858  cmp      x14, x7
0014485c  b.eq     #0x144498
00144860  mov      x8, #0x7801
00144864  movk     x8, #0xa06d, lsl #16
00144868  movk     x8, #0xab5f, lsl #32
0014486c  movk     x8, #0x22db, lsl #48
00144870  cmp      x14, x8
00144874  b.eq     #0x14529c
00144878  mov      x8, #0xb031
0014487c  movk     x8, #0x9cc1, lsl #16
00144880  movk     x8, #0xffeb, lsl #32
00144884  movk     x8, #0x2516, lsl #48
00144888  cmp      x14, x8
0014488c  b.eq     #0x144ccc
00144890  mov      x8, #0x92
00144894  movk     x8, #0x16d6, lsl #16
00144898  movk     x8, #0x9d06, lsl #32
0014489c  movk     x8, #0x2680, lsl #48
001448a0  cmp      x14, x8
001448a4  b.eq     #0x144f8c
001448a8  mov      x8, #0x5dae
001448ac  movk     x8, #0xbd6e, lsl #16
001448b0  movk     x8, #0x6aaa, lsl #32
001448b4  movk     x8, #0x28f0, lsl #48
001448b8  cmp      x14, x8
001448bc  b.eq     #0x145448
001448c0  mov      x8, #0x754
001448c4  movk     x8, #0xa078, lsl #16
001448c8  movk     x8, #0x1f94, lsl #32
001448cc  movk     x8, #0x3282, lsl #48
001448d0  cmp      x14, x8
001448d4  b.eq     #0x145394
001448d8  mov      x15, #0x5cb8
001448dc  mov      x7, #0x1dac
001448e0  ldp      x9, x10, [x29, #-0x30]
001448e4  movk     x15, #0x2795, lsl #16
001448e8  movk     x7, #0x9f5e, lsl #16
001448ec  movk     x15, #0x15f4, lsl #32
001448f0  ldur     x8, [x29, #-0x40]
001448f4  ldur     w11, [x29, #-0x34]
001448f8  mov      x12, x23
001448fc  mov      x13, x21
00144900  mov      x16, x24
00144904  movk     x15, #0x77a4, lsl #48
00144908  movk     x7, #0xb762, lsl #32
0014490c  movk     x7, #0x3b4a, lsl #48
00144910  cmp      x14, x7
00144914  b.eq     #0x144498
00144918  mov      x15, #0x865
0014491c  mov      x7, #0x4c0d
00144920  movk     x15, #0x5362, lsl #16
00144924  movk     x7, #0x52dd, lsl #16
00144928  movk     x15, #0x98ea, lsl #32
0014492c  mov      x8, x20
00144930  mov      x9, x27
00144934  mov      x10, x25
00144938  mov      w11, w28
0014493c  mov      x12, x23
00144940  mov      x13, x21
00144944  mov      x16, x24
00144948  movk     x15, #0xabfd, lsl #48
0014494c  movk     x7, #0x7dcf, lsl #32
00144950  movk     x7, #0x48fe, lsl #48
00144954  cmp      x14, x7
00144958  b.eq     #0x144498
0014495c  mov      x8, #0xd282
00144960  movk     x8, #0x957d, lsl #16
00144964  movk     x8, #0xadd, lsl #32
00144968  movk     x8, #0x549f, lsl #48
0014496c  cmp      x14, x8
00144970  b.eq     #0x14520c
00144974  mov      x8, #0x6436
00144978  movk     x8, #0x2869, lsl #16
0014497c  movk     x8, #0xc5df, lsl #32
00144980  movk     x8, #0x56de, lsl #48
00144984  cmp      x14, x8
00144988  b.eq     #0x145348
0014498c  mov      x8, #0xd2d1
00144990  movk     x8, #0xf825, lsl #16
00144994  movk     x8, #0xee0c, lsl #32
00144998  movk     x8, #0x5c23, lsl #48
0014499c  cmp      x14, x8
001449a0  b.eq     #0x144d54
001449a4  mov      x8, #0x9bd
001449a8  movk     x8, #0xb5f6, lsl #16
001449ac  movk     x8, #0xce8f, lsl #32
001449b0  movk     x8, #0x62d5, lsl #48
001449b4  cmp      x14, x8
001449b8  b.eq     #0x144e90
001449bc  mov      x8, #0xee15
001449c0  movk     x8, #0x1fe1, lsl #16
001449c4  movk     x8, #0x5376, lsl #32
001449c8  movk     x8, #0x6aa9, lsl #48
001449cc  cmp      x14, x8
001449d0  b.eq     #0x145214
001449d4  mov      x8, #0x28cc
001449d8  mov      x26, x0
001449dc  movk     x8, #0xc3e2, lsl #16
001449e0  movk     x8, #0x7819, lsl #32
001449e4  movk     x8, #0x6b85, lsl #48
001449e8  cmp      x14, x8
001449ec  b.eq     #0x144fc4
001449f0  mov      x8, #0x3581
001449f4  movk     x8, #0xbcba, lsl #16
001449f8  movk     x8, #0x133, lsl #32
001449fc  movk     x8, #0x761f, lsl #48
00144a00  cmp      x14, x8
00144a04  b.eq     #0x1450fc
00144a08  mov      x17, #0x7515
00144a0c  mov      x15, #0x3581
00144a10  movk     x17, #0xb217, lsl #16
00144a14  mov      x1, #0x507b
00144a18  movk     x17, #0xdfc8, lsl #32
00144a1c  mov      x2, #0xc335
00144a20  movk     x17, #0x768a, lsl #48
00144a24  mov      x3, #0x865
00144a28  cmp      x14, x17
00144a2c  mov      x4, #0x8d87
00144a30  mov      x5, #0xc2a2
00144a34  mov      x6, #0x1859
00144a38  mov      x30, #0xd05b
00144a3c  mov      x17, #0xb7cc
00144a40  mov      x19, #0xe386
00144a44  movk     x15, #0xbcba, lsl #16
00144a48  movk     x1, #0x2c50, lsl #16
00144a4c  movk     x2, #0x1484, lsl #16
00144a50  movk     x3, #0x5362, lsl #16
00144a54  movk     x4, #0xa2f3, lsl #16
00144a58  movk     x5, #0x1048, lsl #16
00144a5c  movk     x6, #0x2b53, lsl #16
00144a60  movk     x30, #0xef20, lsl #16
00144a64  movk     x17, #0xff64, lsl #16
00144a68  movk     x19, #0xeab8, lsl #16
00144a6c  movk     x15, #0x133, lsl #32
00144a70  movk     x1, #0x48ac, lsl #32
00144a74  movk     x2, #0x16b3, lsl #32
00144a78  movk     x3, #0x98ea, lsl #32
00144a7c  movk     x4, #0x8648, lsl #32
00144a80  movk     x5, #0x7104, lsl #32
00144a84  movk     x6, #0x6ffc, lsl #32
00144a88  movk     x30, #0x96cc, lsl #32
00144a8c  movk     x17, #0xf23e, lsl #32
00144a90  movk     x19, #0xc1ec, lsl #32
00144a94  mov      x8, x20
00144a98  mov      x9, x27
00144a9c  mov      x10, x25
00144aa0  mov      w11, w28
00144aa4  mov      x12, x23
00144aa8  mov      x13, x21
00144aac  mov      x16, x24
00144ab0  movk     x15, #0x761f, lsl #48
00144ab4  movk     x1, #0xc90b, lsl #48
00144ab8  movk     x2, #0xb3cc, lsl #48
00144abc  movk     x3, #0xabfd, lsl #48
00144ac0  movk     x4, #0xa5e3, lsl #48
00144ac4  movk     x5, #0x9ffe, lsl #48
00144ac8  movk     x6, #0x930b, lsl #48
00144acc  movk     x30, #0x8753, lsl #48
00144ad0  movk     x17, #0x8f3d, lsl #48
00144ad4  movk     x19, #0x808f, lsl #48
00144ad8  mov      x0, x26
00144adc  b.eq     #0x144498
00144ae0  mov      x8, #0x5cb8
00144ae4  movk     x8, #0x2795, lsl #16
00144ae8  movk     x8, #0x15f4, lsl #32
00144aec  movk     x8, #0x77a4, lsl #48
00144af0  cmp      x14, x8
00144af4  b.eq     #0x1452e4
00144af8  mov      x17, #0x8e81
00144afc  mov      x15, #0x5dae
00144b00  movk     x17, #0xe154, lsl #16
00144b04  movk     x15, #0xbd6e, lsl #16
00144b08  movk     x17, #0x3b5e, lsl #32
00144b0c  movk     x15, #0x6aaa, lsl #32
00144b10  movk     x17, #0x7cc5, lsl #48
00144b14  mov      x8, x20
00144b18  cmp      x14, x17
00144b1c  mov      x17, #0xb7cc
00144b20  movk     x17, #0xff64, lsl #16
00144b24  mov      x9, x27
00144b28  movk     x17, #0xf23e, lsl #32
00144b2c  mov      x10, x25
00144b30  mov      w11, w28
00144b34  mov      x12, x23
00144b38  mov      x13, x21
00144b3c  mov      x16, x24
00144b40  movk     x15, #0x28f0, lsl #48
00144b44  movk     x17, #0x8f3d, lsl #48
00144b48  b.eq     #0x144498
00144b4c  mov      x8, #0x6dbb
00144b50  movk     x8, #0xc058, lsl #16
00144b54  movk     x8, #0xf56d, lsl #32
00144b58  movk     x8, #0x7e88, lsl #48
00144b5c  cmp      x14, x8
00144b60  b.eq     #0x1451ec
00144b64  mov      x15, #0x507b
00144b68  mov      x7, #0x7408
00144b6c  movk     x15, #0x2c50, lsl #16
00144b70  movk     x7, #0x4e14, lsl #16
00144b74  movk     x15, #0x48ac, lsl #32
00144b78  mov      x8, x20
00144b7c  mov      x9, x27
00144b80  mov      x10, x25
00144b84  mov      w11, w28
00144b88  mov      x12, x23
00144b8c  ldur     x13, [x29, #-0x70]
00144b90  mov      x16, x24
00144b94  movk     x15, #0xc90b, lsl #48
00144b98  movk     x7, #0x43cd, lsl #32
00144b9c  movk     x7, #0x7f74, lsl #48
00144ba0  cmp      x14, x7
00144ba4  b.eq     #0x144498
00144ba8  mov      x17, #0x1968
00144bac  mov      x8, x20
00144bb0  movk     x17, #0x5932, lsl #16
00144bb4  mov      x9, x27
00144bb8  movk     x17, #0x8339, lsl #32
00144bbc  mov      x10, x25
00144bc0  movk     x17, #0xb13, lsl #48
00144bc4  mov      w11, w28
00144bc8  cmp      x14, x17
00144bcc  mov      x17, #0xb7cc
00144bd0  movk     x17, #0xff64, lsl #16
00144bd4  mov      x12, x23
00144bd8  movk     x17, #0xf23e, lsl #32
00144bdc  mov      x13, x21
00144be0  mov      x16, x24
00144be4  mov      x15, x14
00144be8  movk     x17, #0x8f3d, lsl #48
00144bec  b.ne     #0x144498
00144bf0  b        #0x145600
00144bf4  ldp      x8, x9, [sp, #0x30]
00144bf8  mov      x15, #0x5cb8
00144bfc  mov      x12, x23
00144c00  movk     x15, #0x2795, lsl #16
00144c04  mov      x13, x21
00144c08  movk     x15, #0x15f4, lsl #32
00144c0c  mov      x16, x24
00144c10  add      x10, x8, #1
00144c14  ldur     x8, [x29, #-0x80]
00144c18  ldrb     w11, [x9, #1]!
00144c1c  movk     x15, #0x77a4, lsl #48
00144c20  b        #0x144498
00144c24  ldr      x11, [sp, #0xa8]
00144c28  mov      x10, #0x7515
00144c2c  movk     x10, #0xb217, lsl #16
00144c30  mov      x8, x20
00144c34  movk     x10, #0xdfc8, lsl #32
00144c38  mov      x9, x27
00144c3c  cmp      x11, #0
00144c40  str      x11, [sp, #0x70]
00144c44  ldur     x11, [x29, #-0xa0]
00144c48  movk     x10, #0x768a, lsl #48
00144c4c  csel     x15, x10, x17, eq
00144c50  mov      x10, x25
00144c54  str      x11, [sp, #0x58]
00144c58  ldur     x11, [x29, #-0x98]
00144c5c  str      x11, [sp, #0x50]
00144c60  b        #0x145434
00144c64  ldrb     w10, [x23]
00144c68  mov      x14, #0x1dac
00144c6c  ldr      w12, [sp, #0x6c]
00144c70  mov      x15, #0x92
00144c74  movk     x14, #0x9f5e, lsl #16
00144c78  movk     x15, #0x16d6, lsl #16
00144c7c  cmp      w10, #0
00144c80  movk     x14, #0xb762, lsl #32
00144c84  cset     w13, eq
00144c88  movk     x15, #0x9d06, lsl #32
00144c8c  movk     x14, #0x3b4a, lsl #48
00144c90  movk     x15, #0x2680, lsl #48
00144c94  mov      x8, x20
00144c98  mov      x9, x27
00144c9c  str      w13, [sp, #0x4c]
00144ca0  orr      w13, w12, w13
00144ca4  tst      w13, #1
00144ca8  stur     w10, [x29, #-0x34]
00144cac  mov      x10, x25
00144cb0  mov      w11, w28
00144cb4  mov      x12, x23
00144cb8  mov      x13, x21
00144cbc  csel     x15, x15, x14, ne
00144cc0  stur     x23, [x29, #-0x30]
00144cc4  mov      x16, x24
00144cc8  b        #0x144498
00144ccc  ldur     w8, [x29, #-0x4c]
00144cd0  mov      x10, #0x1381
00144cd4  ldr      w9, [sp, #0x94]
00144cd8  mov      x11, #0xb3d0
00144cdc  movk     x10, #0xa58a, lsl #16
00144ce0  movk     x11, #0x566, lsl #16
00144ce4  movk     x10, #0xb763, lsl #32
00144ce8  movk     x11, #0xa50d, lsl #32
00144cec  cmp      w9, w8
00144cf0  movk     x10, #0xbbcd, lsl #48
00144cf4  movk     x11, #0x204a, lsl #48
00144cf8  mov      x8, x20
00144cfc  mov      x9, x27
00144d00  csel     x15, x11, x10, eq
00144d04  b        #0x145430
00144d08  ldur     w12, [x29, #-0x8c]
00144d0c  ldur     w11, [x29, #-0x4c]
00144d10  sub      w8, w12, #0x5b
00144d14  orr      w9, w12, #0x20
00144d18  sub      w10, w11, #0x5b
00144d1c  cmn      w8, #0x1a
00144d20  orr      w8, w11, #0x20
00144d24  csel     w9, w12, w9, lo
00144d28  cmn      w10, #0x1a
00144d2c  csel     w10, w11, w8, lo
00144d30  mov      x8, x20
00144d34  cmp      w9, w10
00144d38  mov      x10, #0xcdf8
00144d3c  movk     x10, #0xd72b, lsl #16
00144d40  mov      x9, x27
00144d44  movk     x10, #0x55aa, lsl #32
00144d48  movk     x10, #0xfe6b, lsl #48
00144d4c  csel     x15, x19, x10, eq
00144d50  b        #0x145430
00144d54  ldr      x8, [sp, #0x98]
00144d58  mov      x19, x0
00144d5c  ldr      x9, [sp, #0x78]
00144d60  sub      x8, x9, x8
00144d64  add      x0, x8, #1
00144d68  str      x8, [sp, #0x88]
00144d6c  bl       #0x148b10
00144d70  mov      x11, #0xdf4a
00144d74  mov      x12, #0x9a1f
00144d78  mov      x17, #0xb7cc
00144d7c  mov      x30, #0xd05b
00144d80  mov      x6, #0x1859
00144d84  mov      x5, #0xc2a2
00144d88  mov      x4, #0x8d87
00144d8c  mov      x3, #0x865
00144d90  mov      x2, #0xc335
00144d94  mov      x1, #0x507b
00144d98  stur     x0, [x29, #-0x68]
00144d9c  cmp      x0, #0
00144da0  mov      x0, x19
00144da4  mov      x19, #0xe386
00144da8  movk     x11, #0xbdc8, lsl #16
00144dac  movk     x12, #0xd6a5, lsl #16
00144db0  movk     x17, #0xff64, lsl #16
00144db4  movk     x30, #0xef20, lsl #16
00144db8  movk     x6, #0x2b53, lsl #16
00144dbc  movk     x5, #0x1048, lsl #16
00144dc0  movk     x4, #0xa2f3, lsl #16
00144dc4  movk     x3, #0x5362, lsl #16
00144dc8  movk     x2, #0x1484, lsl #16
00144dcc  movk     x1, #0x2c50, lsl #16
00144dd0  movk     x19, #0xeab8, lsl #16
00144dd4  movk     x11, #0xceb, lsl #32
00144dd8  movk     x12, #0xc885, lsl #32
00144ddc  movk     x17, #0xf23e, lsl #32
00144de0  movk     x30, #0x96cc, lsl #32
00144de4  movk     x6, #0x6ffc, lsl #32
00144de8  movk     x5, #0x7104, lsl #32
00144dec  movk     x4, #0x8648, lsl #32
00144df0  movk     x3, #0x98ea, lsl #32
00144df4  movk     x2, #0x16b3, lsl #32
00144df8  movk     x1, #0x48ac, lsl #32
00144dfc  movk     x19, #0xc1ec, lsl #32
00144e00  movk     x11, #0xc8d5, lsl #48
00144e04  movk     x12, #0xf611, lsl #48
00144e08  movk     x17, #0x8f3d, lsl #48
00144e0c  movk     x30, #0x8753, lsl #48
00144e10  movk     x6, #0x930b, lsl #48
00144e14  movk     x5, #0x9ffe, lsl #48
00144e18  movk     x4, #0xa5e3, lsl #48
00144e1c  movk     x3, #0xabfd, lsl #48
00144e20  movk     x2, #0xb3cc, lsl #48
00144e24  movk     x1, #0xc90b, lsl #48
00144e28  mov      x8, x20
00144e2c  mov      x9, x27
00144e30  movk     x19, #0x808f, lsl #48
00144e34  mov      x10, x25
00144e38  csel     x15, x11, x12, eq
00144e3c  b        #0x145434
00144e40  ldp      x10, x7, [sp, #0x50]
00144e44  mov      x15, #0xc335
00144e48  mov      x9, x27
00144e4c  ldr      x8, [sp, #0x70]
00144e50  movk     x15, #0x1484, lsl #16
00144e54  movk     x15, #0x16b3, lsl #32
00144e58  mov      w11, w28
00144e5c  ldrb     w14, [x10], #1
00144e60  sub      x8, x8, #1
00144e64  stur     x10, [x29, #-0x98]
00144e68  mov      x10, x25
00144e6c  mov      x12, x23
00144e70  mov      x13, x21
00144e74  mov      x16, x24
00144e78  str      x8, [sp, #0xa8]
00144e7c  mov      x8, x20
00144e80  movk     x15, #0xb3cc, lsl #48
00144e84  strb     w14, [x7], #1
00144e88  stur     x7, [x29, #-0xa0]
00144e8c  b        #0x144498
00144e90  ldur     x8, [x29, #-0x78]
00144e94  mov      x10, #0x8a0
00144e98  ldur     x14, [x29, #-0x88]
00144e9c  mov      x11, #0xd282
00144ea0  movk     x10, #0xbd15, lsl #16
00144ea4  movk     x11, #0x957d, lsl #16
00144ea8  movk     x10, #0xb02c, lsl #32
00144eac  movk     x11, #0xadd, lsl #32
00144eb0  cmp      x14, x8
00144eb4  movk     x10, #0x93e7, lsl #48
00144eb8  movk     x11, #0x549f, lsl #48
00144ebc  mov      x8, x20
00144ec0  mov      x9, x27
00144ec4  csel     x15, x11, x10, eq
00144ec8  mov      x10, x25
00144ecc  mov      w11, w28
00144ed0  mov      x12, x23
00144ed4  mov      x13, x21
00144ed8  stur     x14, [x29, #-0x60]
00144edc  mov      x16, x24
00144ee0  b        #0x144498
00144ee4  ldur     x11, [x29, #-0x48]
00144ee8  mov      x15, #0x1968
00144eec  ldr      x14, [sp, #0xa0]
00144ef0  mov      w7, #5
00144ef4  movk     x15, #0x5932, lsl #16
00144ef8  stur     wzr, [x29, #-0x50]
00144efc  movk     x15, #0x8339, lsl #32
00144f00  mov      x8, x20
00144f04  mov      x9, x27
00144f08  mov      x10, x25
00144f0c  stur     x11, [x29, #-0x58]
00144f10  mov      w11, w28
00144f14  mov      x12, x23
00144f18  mov      x13, x21
00144f1c  mov      x16, x24
00144f20  movk     x15, #0xb13, lsl #48
00144f24  str      w7, [x14]
00144f28  b        #0x144498
00144f2c  ldr      x14, [sp, #0x98]
00144f30  mov      x7, x0
00144f34  ldur     x0, [x29, #-0x68]
00144f38  mov      x15, #0xc335
00144f3c  mov      x19, #0xe386
00144f40  movk     x15, #0x1484, lsl #16
00144f44  movk     x19, #0xeab8, lsl #16
00144f48  movk     x15, #0x16b3, lsl #32
00144f4c  stp      x0, x14, [x29, #-0xa0]
00144f50  ldr      x14, [sp, #0x88]
00144f54  movk     x19, #0xc1ec, lsl #32
00144f58  mov      x8, x20
00144f5c  mov      x9, x27
00144f60  mov      x10, x25
00144f64  mov      w11, w28
00144f68  mov      x12, x23
00144f6c  mov      x13, x21
00144f70  str      x14, [sp, #0xa8]
00144f74  mov      x16, x24
00144f78  movk     x15, #0xb3cc, lsl #48
00144f7c  strb     wzr, [x0, x14]
00144f80  mov      x0, x7
00144f84  movk     x19, #0x808f, lsl #48
00144f88  b        #0x144498
00144f8c  ldr      w8, [sp, #0x4c]
00144f90  mov      x10, #0x1471
00144f94  mov      x11, #0x6dbb
00144f98  movk     x10, #0x4a0, lsl #16
00144f9c  movk     x11, #0xc058, lsl #16
00144fa0  movk     x10, #0x5fd, lsl #32
00144fa4  movk     x11, #0xf56d, lsl #32
00144fa8  tst      w8, #1
00144fac  movk     x10, #0xa11a, lsl #48
00144fb0  movk     x11, #0x7e88, lsl #48
00144fb4  mov      x8, x20
00144fb8  mov      x9, x27
00144fbc  csel     x15, x11, x10, ne
00144fc0  b        #0x145430
00144fc4  nop      
00144fc8  adr      x8, #0x155e5c
00144fcc  nop      
00144fd0  adr      x2, #0x155228
00144fd4  stlrb    wzr, [x8]
00144fd8  ldp      x0, x1, [sp, #0x20]
00144fdc  bl       #0x145650
00144fe0  stur     x0, [x29, #-0x48]
00144fe4  sub      x2, x29, #0x20
00144fe8  ldur     x0, [x29, #-0x68]
00144fec  ldr      x1, [sp, #8]
00144ff0  bl       #0x13ade4
00144ff4  mov      x11, #0x7811
00144ff8  mov      x12, #0x8779
00144ffc  movk     x11, #0x740, lsl #16
00145000  movk     x12, #0xf1b8, lsl #16
00145004  movk     x11, #0x67ad, lsl #32
00145008  movk     x12, #0x3378, lsl #32
0014500c  tst      w0, #1
00145010  movk     x11, #0xf79c, lsl #48
00145014  movk     x12, #0xeb0, lsl #48
00145018  mov      x8, x20
0014501c  mov      x9, x27
00145020  mov      x10, x25
00145024  csel     x15, x11, x12, ne
00145028  b        #0x145144
0014502c  mov      x15, #0x1968
00145030  ldr      x14, [sp, #0xa0]
00145034  mov      w7, #2
00145038  movk     x15, #0x5932, lsl #16
0014503c  movk     x15, #0x8339, lsl #32
00145040  stur     xzr, [x29, #-0x58]
00145044  stur     wzr, [x29, #-0x50]
00145048  mov      x8, x20
0014504c  mov      x9, x27
00145050  mov      x10, x25
00145054  mov      w11, w28
00145058  mov      x12, x23
0014505c  mov      x13, x21
00145060  mov      x16, x24
00145064  movk     x15, #0xb13, lsl #48
00145068  str      w7, [x14]
0014506c  b        #0x144498
00145070  nop      
00145074  adr      x7, #0x155228
00145078  mov      w15, #0x46
0014507c  mov      x8, x20
00145080  mov      x9, x27
00145084  mov      x10, x25
00145088  ldrb     w12, [x7]
0014508c  mov      w11, w28
00145090  ldrb     w13, [x7, #1]
00145094  mov      x16, x24
00145098  eor      w14, w12, w15
0014509c  mov      x12, x23
001450a0  eor      w17, w13, w15
001450a4  mov      x15, #0x28cc
001450a8  movk     x15, #0xc3e2, lsl #16
001450ac  mov      x13, x21
001450b0  strb     w14, [x7]
001450b4  adrp     x14, #0x155000
001450b8  strb     w17, [x7, #1]
001450bc  mov      x17, #0xb7cc
001450c0  mov      w7, #1
001450c4  movk     x17, #0xff64, lsl #16
001450c8  movk     x15, #0x7819, lsl #32
001450cc  movk     x17, #0xf23e, lsl #32
001450d0  movk     x15, #0x6b85, lsl #48
001450d4  movk     x17, #0x8f3d, lsl #48
001450d8  strb     w7, [x14, #0xe5d]
001450dc  b        #0x144498
001450e0  ldr      x9, [sp, #0x60]
001450e4  stur     xzr, [x29, #-0x88]
001450e8  ldr      x8, [x9, #0x18]
001450ec  stur     x8, [x29, #-0x78]
001450f0  add      x8, x9, #0x10
001450f4  str      x8, [sp, #0x80]
001450f8  b        #0x1453a0
001450fc  mov      w0, wzr
00145100  mov      w1, #1
00145104  nop      
00145108  adr      x2, #0x155e5c
0014510c  bl       #0x1483e0
00145110  mov      x11, #0x2f9c
00145114  mov      x12, #0x7801
00145118  movk     x11, #0xc396, lsl #16
0014511c  movk     x12, #0xa06d, lsl #16
00145120  movk     x11, #0x5e8f, lsl #32
00145124  movk     x12, #0xab5f, lsl #32
00145128  cmp      w0, #0
0014512c  movk     x11, #0xf2cd, lsl #48
00145130  movk     x12, #0x22db, lsl #48
00145134  mov      x8, x20
00145138  mov      x9, x27
0014513c  mov      x10, x25
00145140  csel     x15, x12, x11, eq
00145144  mov      x1, #0x507b
00145148  mov      x2, #0xc335
0014514c  mov      x3, #0x865
00145150  mov      x4, #0x8d87
00145154  mov      x5, #0xc2a2
00145158  mov      x6, #0x1859
0014515c  mov      x30, #0xd05b
00145160  mov      x17, #0xb7cc
00145164  mov      x19, #0xe386
00145168  movk     x1, #0x2c50, lsl #16
0014516c  movk     x2, #0x1484, lsl #16
00145170  movk     x3, #0x5362, lsl #16
00145174  movk     x4, #0xa2f3, lsl #16
00145178  movk     x5, #0x1048, lsl #16
0014517c  movk     x6, #0x2b53, lsl #16
00145180  movk     x30, #0xef20, lsl #16
00145184  movk     x17, #0xff64, lsl #16
00145188  movk     x19, #0xeab8, lsl #16
0014518c  movk     x1, #0x48ac, lsl #32
00145190  movk     x2, #0x16b3, lsl #32
00145194  movk     x3, #0x98ea, lsl #32
00145198  movk     x4, #0x8648, lsl #32
0014519c  movk     x5, #0x7104, lsl #32
001451a0  movk     x6, #0x6ffc, lsl #32
001451a4  movk     x30, #0x96cc, lsl #32
001451a8  movk     x17, #0xf23e, lsl #32
001451ac  movk     x19, #0xc1ec, lsl #32
001451b0  mov      w11, w28
001451b4  mov      x12, x23
001451b8  mov      x13, x21
001451bc  mov      x16, x24
001451c0  movk     x1, #0xc90b, lsl #48
001451c4  movk     x2, #0xb3cc, lsl #48
001451c8  movk     x3, #0xabfd, lsl #48
001451cc  movk     x4, #0xa5e3, lsl #48
001451d0  movk     x5, #0x9ffe, lsl #48
001451d4  movk     x6, #0x930b, lsl #48
001451d8  movk     x30, #0x8753, lsl #48
001451dc  movk     x17, #0x8f3d, lsl #48
001451e0  movk     x19, #0x808f, lsl #48
001451e4  mov      x0, x26
001451e8  b        #0x144498
001451ec  ldur     x8, [x29, #-0x78]
001451f0  ldur     x9, [x29, #-0x60]
001451f4  cmp      x9, x8
001451f8  mov      x8, x20
001451fc  cset     w10, lo
00145200  mov      x9, x27
00145204  stur     w10, [x29, #-0x50]
00145208  b        #0x145224
0014520c  stur     wzr, [x29, #-0x50]
00145210  b        #0x14521c
00145214  mov      w8, #1
00145218  stur     w8, [x29, #-0x50]
0014521c  mov      x8, x20
00145220  mov      x9, x27
00145224  ldur     x11, [x29, #-0x48]
00145228  mov      x15, #0x1968
0014522c  movk     x15, #0x5932, lsl #16
00145230  mov      x10, x25
00145234  movk     x15, #0x8339, lsl #32
00145238  mov      x12, x23
0014523c  stur     x11, [x29, #-0x58]
00145240  mov      w11, w28
00145244  mov      x13, x21
00145248  mov      x16, x24
0014524c  movk     x15, #0xb13, lsl #48
00145250  b        #0x144498
00145254  mov      x8, x21
00145258  mov      x14, #0x7408
0014525c  movk     x14, #0x4e14, lsl #16
00145260  mov      x9, x27
00145264  movk     x14, #0x43cd, lsl #32
00145268  mov      x10, x25
0014526c  ldrb     w13, [x8], #1
00145270  movk     x14, #0x7f74, lsl #48
00145274  stur     x8, [x29, #-0x70]
00145278  mov      x8, x20
0014527c  mov      w11, w28
00145280  cmp      w13, #0
00145284  mov      x12, x23
00145288  mov      x13, x21
0014528c  csel     x15, x30, x14, eq
00145290  str      x21, [sp, #0x40]
00145294  mov      x16, x24
00145298  b        #0x144498
0014529c  adrp     x8, #0x155000
001452a0  mov      x13, #0xafb5
001452a4  mov      x14, #0xfe0a
001452a8  movk     x13, #0xa12b, lsl #16
001452ac  movk     x14, #0x69fd, lsl #16
001452b0  movk     x13, #0xce93, lsl #32
001452b4  ldrb     w12, [x8, #0xe5d]
001452b8  movk     x14, #0x5f3a, lsl #32
001452bc  movk     x13, #0xb225, lsl #48
001452c0  movk     x14, #0xbdc7, lsl #48
001452c4  mov      x8, x20
001452c8  mov      x9, x27
001452cc  cmp      w12, #0
001452d0  mov      x10, x25
001452d4  mov      w11, w28
001452d8  mov      x12, x23
001452dc  csel     x15, x14, x13, ne
001452e0  b        #0x14543c
001452e4  sub      x8, x20, #1
001452e8  mov      x9, #0x6436
001452ec  movk     x9, #0x2869, lsl #16
001452f0  cmp      w28, #0
001452f4  movk     x9, #0xc5df, lsl #32
001452f8  mov      x10, x25
001452fc  stur     x8, [x29, #-0x80]
00145300  ldrb     w8, [x25]
00145304  movk     x9, #0x56de, lsl #48
00145308  mov      w11, w28
0014530c  mov      x12, x23
00145310  mov      x13, x21
00145314  stur     w8, [x29, #-0x4c]
00145318  mov      x8, #0x25ce
0014531c  movk     x8, #0x8c3e, lsl #16
00145320  str      w28, [sp, #0x94]
00145324  movk     x8, #0xdec2, lsl #32
00145328  stp      x25, x27, [sp, #0x30]
0014532c  movk     x8, #0xf201, lsl #48
00145330  stur     w28, [x29, #-0x8c]
00145334  csel     x15, x8, x9, eq
00145338  mov      x8, x20
0014533c  mov      x9, x27
00145340  mov      x16, x24
00145344  b        #0x144498
00145348  ldur     x8, [x29, #-0x80]
0014534c  mov      x13, #0xb031
00145350  mov      x14, #0x4c0d
00145354  movk     x13, #0x9cc1, lsl #16
00145358  movk     x14, #0x52dd, lsl #16
0014535c  movk     x13, #0xffeb, lsl #32
00145360  cmp      x8, #0
00145364  ldur     w8, [x29, #-0x4c]
00145368  movk     x14, #0x7dcf, lsl #32
0014536c  movk     x13, #0x2516, lsl #48
00145370  movk     x14, #0x48fe, lsl #48
00145374  mov      x9, x27
00145378  ccmp     w8, #0, #4, ne
0014537c  mov      x8, x20
00145380  mov      x10, x25
00145384  mov      w11, w28
00145388  mov      x12, x23
0014538c  csel     x15, x13, x14, ne
00145390  b        #0x14543c
00145394  ldur     x8, [x29, #-0x60]
00145398  add      x8, x8, #1
0014539c  stur     x8, [x29, #-0x88]
001453a0  mov      x15, #0x9bd
001453a4  mov      x8, x20
001453a8  movk     x15, #0xb5f6, lsl #16
001453ac  mov      x9, x27
001453b0  movk     x15, #0xce8f, lsl #32
001453b4  mov      x10, x25
001453b8  mov      w11, w28
001453bc  mov      x12, x23
001453c0  mov      x13, x21
001453c4  mov      x16, x24
001453c8  movk     x15, #0x62d5, lsl #48
001453cc  b        #0x144498
001453d0  ldur     w12, [x29, #-0x8c]
001453d4  ldur     w11, [x29, #-0x4c]
001453d8  sub      w8, w12, #0x5b
001453dc  orr      w9, w12, #0x20
001453e0  sub      w10, w11, #0x5b
001453e4  cmn      w8, #0x1a
001453e8  csel     w9, w12, w9, lo
001453ec  cmn      w10, #0x1a
001453f0  ldur     x10, [x29, #-0x30]
001453f4  orr      w8, w11, #0x20
001453f8  csel     w8, w11, w8, lo
001453fc  cmp      w9, w8
00145400  mov      x9, #0xea12
00145404  add      x0, x10, #1
00145408  mov      x10, #0xcd53
0014540c  movk     x9, #0x2ac8, lsl #16
00145410  movk     x10, #0xade6, lsl #16
00145414  movk     x9, #0x1d60, lsl #32
00145418  movk     x10, #0xefff, lsl #32
0014541c  movk     x9, #0x1023, lsl #48
00145420  movk     x10, #0x13d4, lsl #48
00145424  mov      x8, x20
00145428  csel     x15, x10, x9, eq
0014542c  mov      x9, x27
00145430  mov      x10, x25
00145434  mov      w11, w28
00145438  mov      x12, x23
0014543c  mov      x13, x21
00145440  mov      x16, x24
00145444  b        #0x144498
00145448  mov      x22, x24
0014544c  mov      x13, #0xa74a
00145450  mov      x14, #0xd2d1
00145454  movk     x13, #0x5ea3, lsl #16
00145458  movk     x14, #0xf825, lsl #16
0014545c  movk     x13, #0xa04f, lsl #32
00145460  ldrb     w12, [x22], #1
00145464  movk     x14, #0xee0c, lsl #32
00145468  movk     x13, #0xfa1e, lsl #48
0014546c  movk     x14, #0x5c23, lsl #48
00145470  mov      x8, x20
00145474  cmp      w12, #0
00145478  mov      x9, x27
0014547c  mov      x10, x25
00145480  str      x24, [sp, #0x78]
00145484  mov      w11, w28
00145488  mov      x12, x23
0014548c  csel     x15, x14, x13, eq
00145490  b        #0x14543c
00145494  ldp      x2, x3, [sp, #0x10]
00145498  mov      x26, x0
0014549c  ldur     x0, [x29, #-0x20]
001454a0  ldur     w1, [x29, #-0x18]
001454a4  bl       #0x145d84
001454a8  mov      x11, #0x113f
001454ac  mov      x12, #0xee15
001454b0  mov      x17, #0xb7cc
001454b4  mov      x30, #0xd05b
001454b8  mov      x6, #0x1859
001454bc  mov      x5, #0xc2a2
001454c0  mov      x4, #0x8d87
001454c4  mov      x3, #0x865
001454c8  mov      x2, #0xc335
001454cc  mov      x19, #0xe386
001454d0  mov      x1, #0x507b
001454d4  movk     x11, #0xceaf, lsl #16
001454d8  movk     x12, #0x1fe1, lsl #16
001454dc  movk     x17, #0xff64, lsl #16
001454e0  movk     x30, #0xef20, lsl #16
001454e4  movk     x6, #0x2b53, lsl #16
001454e8  movk     x5, #0x1048, lsl #16
001454ec  movk     x4, #0xa2f3, lsl #16
001454f0  movk     x3, #0x5362, lsl #16
001454f4  movk     x2, #0x1484, lsl #16
001454f8  movk     x19, #0xeab8, lsl #16
001454fc  movk     x1, #0x2c50, lsl #16
00145500  movk     x11, #0x4fe6, lsl #32
00145504  movk     x12, #0x5376, lsl #32
00145508  movk     x17, #0xf23e, lsl #32
0014550c  movk     x30, #0x96cc, lsl #32
00145510  movk     x6, #0x6ffc, lsl #32
00145514  movk     x5, #0x7104, lsl #32
00145518  movk     x4, #0x8648, lsl #32
0014551c  movk     x3, #0x98ea, lsl #32
00145520  movk     x2, #0x16b3, lsl #32
00145524  movk     x19, #0xc1ec, lsl #32
00145528  movk     x1, #0x48ac, lsl #32
0014552c  cmp      x0, #0
00145530  movk     x11, #0xe9ff, lsl #48
00145534  movk     x12, #0x6aa9, lsl #48
00145538  movk     x17, #0x8f3d, lsl #48
0014553c  movk     x30, #0x8753, lsl #48
00145540  movk     x6, #0x930b, lsl #48
00145544  movk     x5, #0x9ffe, lsl #48
00145548  movk     x4, #0xa5e3, lsl #48
0014554c  movk     x3, #0xabfd, lsl #48
00145550  movk     x2, #0xb3cc, lsl #48
00145554  movk     x19, #0x808f, lsl #48
00145558  movk     x1, #0xc90b, lsl #48
0014555c  mov      x8, x20
00145560  mov      x9, x27
00145564  str      x0, [sp, #0x60]
00145568  mov      x0, x26
0014556c  mov      x10, x25
00145570  csel     x15, x12, x11, eq
00145574  b        #0x145434
00145578  ldur     x8, [x29, #-0x28]
0014557c  mov      x15, #0x1859
00145580  ldr      x9, [sp, #0x40]
00145584  movk     x15, #0x2b53, lsl #16
00145588  ldur     x12, [x29, #-0x48]
0014558c  movk     x15, #0x6ffc, lsl #32
00145590  mov      w11, w28
00145594  mov      x13, x21
00145598  subs     x8, x9, x8
0014559c  mov      x9, x27
001455a0  cset     w10, eq
001455a4  mov      x16, x24
001455a8  movk     x15, #0x930b, lsl #48
001455ac  stur     x8, [x29, #-0x40]
001455b0  mov      x8, x20
001455b4  str      w10, [sp, #0x6c]
001455b8  mov      x10, x25
001455bc  b        #0x144498
001455c0  ldr      x8, [sp, #0x80]
001455c4  mov      x15, #0x507b
001455c8  ldur     x9, [x29, #-0x60]
001455cc  movk     x15, #0x2c50, lsl #16
001455d0  movk     x15, #0x48ac, lsl #32
001455d4  mov      x10, x25
001455d8  ldr      x8, [x8]
001455dc  mov      w11, w28
001455e0  mov      x12, x23
001455e4  mov      x16, x24
001455e8  ldr      x13, [x8, x9, lsl #3]
001455ec  mov      x8, x20
001455f0  mov      x9, x27
001455f4  movk     x15, #0xc90b, lsl #48
001455f8  stur     x13, [x29, #-0x28]
001455fc  b        #0x144498
00145600  ldur     x0, [x29, #-0x68]
00145604  bl       #0x148a00
00145608  ldur     x0, [x29, #-0x58]
0014560c  bl       #0x148a00
00145610  ldr      x8, [sp]
00145614  ldr      x8, [x8, #0x28]
00145618  ldur     x9, [x29, #-0x10]
0014561c  cmp      x8, x9
00145620  b.ne     #0x14564c
00145624  ldur     w8, [x29, #-0x50]
00145628  ldp      x20, x19, [sp, #0x1a0]
0014562c  ldp      x22, x21, [sp, #0x190]
00145630  and      w0, w8, #1
00145634  ldp      x24, x23, [sp, #0x180]
00145638  ldp      x26, x25, [sp, #0x170]
0014563c  ldp      x28, x27, [sp, #0x160]
00145640  ldp      x29, x30, [sp, #0x150]
00145644  add      sp, sp, #0x1b0
00145648  ret      
0014564c  bl       #0x148a10
00145650  sub      sp, sp, #0x100
00145654  stp      x29, x30, [sp, #0xa0]
00145658  stp      x28, x27, [sp, #0xb0]
0014565c  stp      x26, x25, [sp, #0xc0]
00145660  stp      x24, x23, [sp, #0xd0]
00145664  stp      x22, x21, [sp, #0xe0]
00145668  stp      x20, x19, [sp, #0xf0]
0014566c  add      x29, sp, #0xa0
00145670  str      x2, [sp]
00145674  mov      x23, #0xe4da
00145678  stur     x1, [x29, #-0x48]
0014567c  mov      x12, #0xb0b0
00145680  stp      xzr, x0, [sp, #0x48]
00145684  mov      x13, #0x2214
00145688  mov      x15, #0xe11a
0014568c  mov      x17, #0x692
00145690  mov      x0, #0xafca
00145694  mov      x20, #0x8f9b
00145698  mov      x1, #0xdfbb
0014569c  mov      x2, #0xc6bd
001456a0  mov      x27, #0x540b
001456a4  mov      x28, #0x259
001456a8  mov      x26, #0x4905
001456ac  mov      x4, #0x1c0f
001456b0  mov      x5, #0x30e
001456b4  mov      x6, #0x64c6
001456b8  mov      x7, #0x933c
001456bc  mov      x30, #0x208d
001456c0  mov      x16, #0xe6b2
001456c4  mov      x11, #0x692
001456c8  movk     x23, #0x60f6, lsl #16
001456cc  movk     x12, #0x4891, lsl #16
001456d0  movk     x13, #0x6e6c, lsl #16
001456d4  movk     x15, #0xe707, lsl #16
001456d8  movk     x17, #0x8807, lsl #16
001456dc  movk     x0, #0x7c1a, lsl #16
001456e0  movk     x20, #0xc267, lsl #16
001456e4  movk     x1, #0xfd40, lsl #16
001456e8  movk     x2, #0xda71, lsl #16
001456ec  movk     x27, #0x5e6a, lsl #16
001456f0  movk     x28, #0x6e2a, lsl #16
001456f4  movk     x26, #0x4d4c, lsl #16
001456f8  movk     x4, #0x6b47, lsl #16
001456fc  movk     x5, #0x1b5, lsl #16
00145700  movk     x6, #0xb4df, lsl #16
00145704  movk     x7, #0x4138, lsl #16
00145708  movk     x30, #0x44b3, lsl #16
0014570c  movk     x16, #0xa01a, lsl #16
00145710  movk     x11, #0x8807, lsl #16
00145714  movk     x23, #0xb0ba, lsl #32
00145718  movk     x12, #0xd7d8, lsl #32
0014571c  movk     x13, #0x2705, lsl #32
00145720  movk     x15, #0x5296, lsl #32
00145724  movk     x17, #0xfbe3, lsl #32
00145728  movk     x0, #0x1e39, lsl #32
0014572c  movk     x20, #0xf353, lsl #32
00145730  movk     x1, #0xeac0, lsl #32
00145734  movk     x2, #0x6422, lsl #32
00145738  movk     x27, #0x5fdc, lsl #32
0014573c  movk     x28, #0xc6cb, lsl #32
00145740  movk     x26, #0xa445, lsl #32
00145744  movk     x4, #0x4b03, lsl #32
00145748  movk     x5, #0x9ee9, lsl #32
0014574c  movk     x6, #0xca87, lsl #32
00145750  movk     x7, #0xbb88, lsl #32
00145754  movk     x30, #0xb99f, lsl #32
00145758  movk     x16, #0x11ba, lsl #32
0014575c  movk     x11, #0xfbe3, lsl #32
00145760  mov      x14, xzr
00145764  movk     x23, #0x8940, lsl #48
00145768  movk     x12, #0x3df5, lsl #48
0014576c  movk     x13, #0x2e9a, lsl #48
00145770  movk     x15, #0x1df3, lsl #48
00145774  movk     x17, #0xa1b3, lsl #48
00145778  movk     x0, #0x6f3, lsl #48
0014577c  movk     x20, #0x853c, lsl #48
00145780  movk     x1, #0x1ca0, lsl #48
00145784  movk     x2, #0x3b0d, lsl #48
00145788  movk     x27, #0x9974, lsl #48
0014578c  movk     x28, #0x176e, lsl #48
00145790  movk     x26, #0x9d91, lsl #48
00145794  movk     x4, #0xc1bd, lsl #48
00145798  movk     x5, #0xcf73, lsl #48
0014579c  movk     x6, #0x162c, lsl #48
001457a0  movk     x7, #0x5c22, lsl #48
001457a4  movk     x30, #0x3ef2, lsl #48
001457a8  movk     x16, #0x26d0, lsl #48
001457ac  movk     x11, #0xa1b3, lsl #48
001457b0  mov      x9, x11
001457b4  mov      x11, #0xf23e
001457b8  movk     x11, #0xeb9c, lsl #16
001457bc  cmp      x9, x20
001457c0  movk     x11, #0x667e, lsl #32
001457c4  movk     x11, #0x7c8, lsl #48
001457c8  b.eq     #0x1457b0
001457cc  mov      x19, x10
001457d0  mov      x25, x8
001457d4  cmp      x9, x23
001457d8  b.eq     #0x145944
001457dc  cmp      x9, x27
001457e0  b.eq     #0x145964
001457e4  cmp      x9, x26
001457e8  b.eq     #0x145a74
001457ec  mov      x11, #0xe11a
001457f0  mov      x8, x25
001457f4  movk     x11, #0xe707, lsl #16
001457f8  mov      x10, x19
001457fc  movk     x11, #0x5296, lsl #32
00145800  cmp      x9, x17
00145804  movk     x11, #0x1df3, lsl #48
00145808  b.eq     #0x1457b0
0014580c  mov      x11, #0xb0b0
00145810  mov      x8, x25
00145814  movk     x11, #0x4891, lsl #16
00145818  mov      x10, x21
0014581c  movk     x11, #0xd7d8, lsl #32
00145820  cmp      x9, x4
00145824  movk     x11, #0x3df5, lsl #48
00145828  b.eq     #0x1457b0
0014582c  mov      x11, #0xe4da
00145830  mov      x8, x22
00145834  movk     x11, #0x60f6, lsl #16
00145838  mov      x10, x19
0014583c  movk     x11, #0xb0ba, lsl #32
00145840  cmp      x9, x5
00145844  movk     x11, #0x8940, lsl #48
00145848  b.eq     #0x1457b0
0014584c  cmp      x9, x0
00145850  b.eq     #0x145a94
00145854  cmp      x9, x6
00145858  b.eq     #0x145abc
0014585c  cmp      x9, x28
00145860  b.eq     #0x145adc
00145864  mov      x8, x24
00145868  mov      x10, x19
0014586c  cmp      x9, x1
00145870  b.eq     #0x1457b0
00145874  cmp      x9, x15
00145878  b.eq     #0x145ae8
0014587c  cmp      x9, x16
00145880  b.eq     #0x145b04
00145884  cmp      x9, x13
00145888  b.eq     #0x145b30
0014588c  mov      x8, #0x4fa1
00145890  movk     x8, #0x3fc2, lsl #16
00145894  movk     x8, #0x4b99, lsl #32
00145898  movk     x8, #0x365c, lsl #48
0014589c  cmp      x9, x8
001458a0  b.eq     #0x145b58
001458a4  cmp      x9, x2
001458a8  b.eq     #0x145b8c
001458ac  cmp      x9, x12
001458b0  b.eq     #0x145bc4
001458b4  cmp      x9, x30
001458b8  b.eq     #0x145bf4
001458bc  cmp      x9, x7
001458c0  b.eq     #0x145d14
001458c4  mov      x11, #0xf23e
001458c8  mov      x3, #0x4bb4
001458cc  movk     x11, #0xeb9c, lsl #16
001458d0  movk     x3, #0x877, lsl #16
001458d4  movk     x11, #0x667e, lsl #32
001458d8  mov      x8, x25
001458dc  mov      x10, x19
001458e0  movk     x11, #0x7c8, lsl #48
001458e4  movk     x3, #0x5974, lsl #32
001458e8  movk     x3, #0x5eff, lsl #48
001458ec  cmp      x9, x3
001458f0  b.eq     #0x1457b0
001458f4  mov      x8, #0xd62d
001458f8  movk     x8, #0xa717, lsl #16
001458fc  movk     x8, #0xd684, lsl #32
00145900  movk     x8, #0x75ea, lsl #48
00145904  cmp      x9, x8
00145908  b.eq     #0x145d3c
0014590c  mov      x16, #0xf23e
00145910  mov      x8, x25
00145914  movk     x16, #0xeb9c, lsl #16
00145918  mov      x10, x19
0014591c  movk     x16, #0x667e, lsl #32
00145920  mov      x11, x9
00145924  movk     x16, #0x7c8, lsl #48
00145928  cmp      x9, x16
0014592c  mov      x16, #0xe6b2
00145930  movk     x16, #0xa01a, lsl #16
00145934  movk     x16, #0x11ba, lsl #32
00145938  movk     x16, #0x26d0, lsl #48
0014593c  b.ne     #0x1457b0
00145940  b        #0x145d60
00145944  mov      x24, x25
00145948  str      x25, [sp, #0x18]
0014594c  mov      x10, x19
00145950  ldrb     w8, [x24], #1
00145954  cmp      w8, #0
00145958  mov      x8, x25
0014595c  csel     x11, x2, x1, eq
00145960  b        #0x1457b0
00145964  ldur     x8, [x29, #-8]
00145968  mov      w1, #1
0014596c  mov      x22, x14
00145970  add      x0, x8, #1
00145974  bl       #0x148b90
00145978  mov      x28, #0x259
0014597c  mov      x16, #0xe6b2
00145980  mov      x30, #0x208d
00145984  mov      x7, #0x933c
00145988  mov      x6, #0x64c6
0014598c  mov      x5, #0x30e
00145990  mov      x4, #0x1c0f
00145994  movk     x28, #0x6e2a, lsl #16
00145998  mov      x2, #0xc6bd
0014599c  mov      x1, #0xdfbb
001459a0  mov      x17, #0x692
001459a4  mov      x15, #0xe11a
001459a8  mov      x14, x22
001459ac  mov      x13, #0x2214
001459b0  mov      x12, #0xb0b0
001459b4  mov      x22, x0
001459b8  mov      x0, #0xafca
001459bc  movk     x16, #0xa01a, lsl #16
001459c0  movk     x30, #0x44b3, lsl #16
001459c4  movk     x7, #0x4138, lsl #16
001459c8  movk     x6, #0xb4df, lsl #16
001459cc  movk     x5, #0x1b5, lsl #16
001459d0  movk     x4, #0x6b47, lsl #16
001459d4  movk     x28, #0xc6cb, lsl #32
001459d8  movk     x2, #0xda71, lsl #16
001459dc  movk     x1, #0xfd40, lsl #16
001459e0  movk     x17, #0x8807, lsl #16
001459e4  movk     x15, #0xe707, lsl #16
001459e8  movk     x13, #0x6e6c, lsl #16
001459ec  movk     x12, #0x4891, lsl #16
001459f0  movk     x0, #0x7c1a, lsl #16
001459f4  movk     x16, #0x11ba, lsl #32
001459f8  movk     x30, #0xb99f, lsl #32
001459fc  movk     x7, #0xbb88, lsl #32
00145a00  movk     x6, #0xca87, lsl #32
00145a04  movk     x5, #0x9ee9, lsl #32
00145a08  movk     x4, #0x4b03, lsl #32
00145a0c  movk     x28, #0x176e, lsl #48
00145a10  movk     x2, #0x6422, lsl #32
00145a14  movk     x1, #0xeac0, lsl #32
00145a18  movk     x17, #0xfbe3, lsl #32
00145a1c  movk     x15, #0x5296, lsl #32
00145a20  movk     x13, #0x2705, lsl #32
00145a24  movk     x12, #0xd7d8, lsl #32
00145a28  movk     x0, #0x1e39, lsl #32
00145a2c  cmp      x22, #0
00145a30  movk     x16, #0x26d0, lsl #48
00145a34  movk     x30, #0x3ef2, lsl #48
00145a38  movk     x7, #0x5c22, lsl #48
00145a3c  movk     x6, #0x162c, lsl #48
00145a40  movk     x5, #0xcf73, lsl #48
00145a44  movk     x4, #0xc1bd, lsl #48
00145a48  movk     x2, #0x3b0d, lsl #48
00145a4c  movk     x1, #0x1ca0, lsl #48
00145a50  movk     x17, #0xa1b3, lsl #48
00145a54  movk     x15, #0x1df3, lsl #48
00145a58  movk     x13, #0x2e9a, lsl #48
00145a5c  movk     x12, #0x3df5, lsl #48
00145a60  movk     x0, #0x6f3, lsl #48
00145a64  mov      x8, x25
00145a68  csel     x11, x20, x28, eq
00145a6c  mov      x10, x19
00145a70  b        #0x1457b0
00145a74  ldr      x8, [sp, #0x20]
00145a78  add      x8, x8, #1
00145a7c  stur     x8, [x29, #-0x38]
00145a80  ldr      x8, [sp, #0x28]
00145a84  add      x8, x8, #1
00145a88  stur     x8, [x29, #-0x40]
00145a8c  mov      x8, x25
00145a90  b        #0x145b74
00145a94  ldur     x3, [x29, #-0x18]
00145a98  mov      x10, x19
00145a9c  ldur     x19, [x29, #-0x30]
00145aa0  mov      x8, x25
00145aa4  ldrb     w9, [x3]
00145aa8  stp      x3, x19, [sp, #8]
00145aac  cmp      w9, #0
00145ab0  strb     w9, [x19]
00145ab4  csel     x11, x7, x6, eq
00145ab8  b        #0x1457b0
00145abc  ldr      x8, [sp, #8]
00145ac0  add      x8, x8, #1
00145ac4  stur     x8, [x29, #-0x18]
00145ac8  ldr      x8, [sp, #0x10]
00145acc  add      x8, x8, #1
00145ad0  stur     x8, [x29, #-0x30]
00145ad4  mov      x8, x25
00145ad8  b        #0x145bac
00145adc  stur     xzr, [x29, #-0x20]
00145ae0  stur     x22, [x29, #-0x10]
00145ae4  b        #0x145d20
00145ae8  ldur     x8, [x29, #-0x48]
00145aec  str      x14, [sp, #0x38]
00145af0  cmp      x14, x8
00145af4  ldr      x8, [sp, #0x48]
00145af8  csel     x11, x27, x30, eq
00145afc  stur     x8, [x29, #-8]
00145b00  b        #0x145be8
00145b04  ldur     x9, [x29, #-0x28]
00145b08  mov      x11, #0xb0b0
00145b0c  ldr      x8, [sp, #0x50]
00145b10  movk     x11, #0x4891, lsl #16
00145b14  movk     x11, #0xd7d8, lsl #32
00145b18  mov      x10, x22
00145b1c  ldr      x8, [x8, x9, lsl #3]
00145b20  movk     x11, #0x3df5, lsl #48
00145b24  str      x8, [sp, #0x40]
00145b28  mov      x8, x25
00145b2c  b        #0x1457b0
00145b30  ldur     x8, [x29, #-0x48]
00145b34  ldur     x9, [x29, #-0x20]
00145b38  cmp      x9, x8
00145b3c  mov      x8, #0x4bb4
00145b40  movk     x8, #0x877, lsl #16
00145b44  stur     x9, [x29, #-0x28]
00145b48  movk     x8, #0x5974, lsl #32
00145b4c  movk     x8, #0x5eff, lsl #48
00145b50  csel     x11, x8, x16, eq
00145b54  b        #0x145be8
00145b58  ldur     x8, [x29, #-0x10]
00145b5c  ldr      x9, [sp, #0x30]
00145b60  ldr      x10, [sp, #0x40]
00145b64  sub      x9, x9, x8
00145b68  mov      x8, x25
00145b6c  add      x9, x22, x9
00145b70  stp      x9, x10, [x29, #-0x40]
00145b74  mov      x11, #0xd62d
00145b78  mov      x10, x19
00145b7c  movk     x11, #0xa717, lsl #16
00145b80  movk     x11, #0xd684, lsl #32
00145b84  movk     x11, #0x75ea, lsl #48
00145b88  b        #0x1457b0
00145b8c  ldur     x8, [x29, #-0x10]
00145b90  ldr      x9, [sp, #0x18]
00145b94  sub      x9, x9, x8
00145b98  ldr      x8, [sp]
00145b9c  add      x9, x22, x9
00145ba0  stur     x8, [x29, #-0x18]
00145ba4  mov      x8, x25
00145ba8  stur     x9, [x29, #-0x30]
00145bac  mov      x11, #0xafca
00145bb0  mov      x10, x19
00145bb4  movk     x11, #0x7c1a, lsl #16
00145bb8  movk     x11, #0x1e39, lsl #32
00145bbc  movk     x11, #0x6f3, lsl #48
00145bc0  b        #0x1457b0
00145bc4  mov      x21, x19
00145bc8  str      x19, [sp, #0x30]
00145bcc  ldrb     w8, [x21], #1
00145bd0  cmp      w8, #0
00145bd4  mov      x8, #0x4fa1
00145bd8  movk     x8, #0x3fc2, lsl #16
00145bdc  movk     x8, #0x4b99, lsl #32
00145be0  movk     x8, #0x365c, lsl #48
00145be4  csel     x11, x8, x4, eq
00145be8  mov      x8, x25
00145bec  mov      x10, x19
00145bf0  b        #0x1457b0
00145bf4  ldr      x26, [sp, #0x38]
00145bf8  ldr      x8, [sp, #0x50]
00145bfc  ldr      x0, [x8, x26, lsl #3]
00145c00  bl       #0x148ce0
00145c04  ldur     x8, [x29, #-8]
00145c08  mov      x16, #0xe6b2
00145c0c  mov      x30, #0x208d
00145c10  mov      x7, #0x933c
00145c14  mov      x6, #0x64c6
00145c18  mov      x5, #0x30e
00145c1c  add      x9, x8, x0
00145c20  mov      x4, #0x1c0f
00145c24  mov      x2, #0xc6bd
00145c28  mov      x1, #0xdfbb
00145c2c  mov      x17, #0x692
00145c30  mov      x15, #0xe11a
00145c34  mov      x13, #0x2214
00145c38  mov      x12, #0xb0b0
00145c3c  add      x14, x26, #1
00145c40  mov      x26, #0x4905
00145c44  mov      x0, #0xafca
00145c48  add      x9, x9, #1
00145c4c  mov      x11, #0xe11a
00145c50  movk     x16, #0xa01a, lsl #16
00145c54  movk     x30, #0x44b3, lsl #16
00145c58  movk     x7, #0x4138, lsl #16
00145c5c  movk     x6, #0xb4df, lsl #16
00145c60  movk     x5, #0x1b5, lsl #16
00145c64  movk     x4, #0x6b47, lsl #16
00145c68  movk     x2, #0xda71, lsl #16
00145c6c  movk     x1, #0xfd40, lsl #16
00145c70  movk     x17, #0x8807, lsl #16
00145c74  movk     x15, #0xe707, lsl #16
00145c78  movk     x13, #0x6e6c, lsl #16
00145c7c  movk     x12, #0x4891, lsl #16
00145c80  movk     x26, #0x4d4c, lsl #16
00145c84  movk     x0, #0x7c1a, lsl #16
00145c88  movk     x11, #0xe707, lsl #16
00145c8c  movk     x16, #0x11ba, lsl #32
00145c90  movk     x30, #0xb99f, lsl #32
00145c94  movk     x7, #0xbb88, lsl #32
00145c98  movk     x6, #0xca87, lsl #32
00145c9c  movk     x5, #0x9ee9, lsl #32
00145ca0  movk     x4, #0x4b03, lsl #32
00145ca4  movk     x2, #0x6422, lsl #32
00145ca8  movk     x1, #0xeac0, lsl #32
00145cac  movk     x17, #0xfbe3, lsl #32
00145cb0  movk     x15, #0x5296, lsl #32
00145cb4  movk     x13, #0x2705, lsl #32
00145cb8  movk     x12, #0xd7d8, lsl #32
00145cbc  movk     x26, #0xa445, lsl #32
00145cc0  movk     x0, #0x1e39, lsl #32
00145cc4  movk     x11, #0x5296, lsl #32
00145cc8  movk     x16, #0x26d0, lsl #48
00145ccc  movk     x30, #0x3ef2, lsl #48
00145cd0  movk     x7, #0x5c22, lsl #48
00145cd4  movk     x6, #0x162c, lsl #48
00145cd8  movk     x5, #0xcf73, lsl #48
00145cdc  movk     x4, #0xc1bd, lsl #48
00145ce0  movk     x2, #0x3b0d, lsl #48
00145ce4  movk     x1, #0x1ca0, lsl #48
00145ce8  movk     x17, #0xa1b3, lsl #48
00145cec  movk     x15, #0x1df3, lsl #48
00145cf0  movk     x13, #0x2e9a, lsl #48
00145cf4  movk     x12, #0x3df5, lsl #48
00145cf8  movk     x26, #0x9d91, lsl #48
00145cfc  movk     x0, #0x6f3, lsl #48
00145d00  mov      x8, x25
00145d04  str      x9, [sp, #0x48]
00145d08  mov      x10, x19
00145d0c  movk     x11, #0x1df3, lsl #48
00145d10  b        #0x1457b0
00145d14  ldur     x8, [x29, #-0x28]
00145d18  add      x8, x8, #1
00145d1c  stur     x8, [x29, #-0x20]
00145d20  mov      x11, #0x2214
00145d24  mov      x8, x25
00145d28  movk     x11, #0x6e6c, lsl #16
00145d2c  mov      x10, x19
00145d30  movk     x11, #0x2705, lsl #32
00145d34  movk     x11, #0x2e9a, lsl #48
00145d38  b        #0x1457b0
00145d3c  ldp      x3, x10, [x29, #-0x40]
00145d40  mov      x8, x25
00145d44  ldrb     w9, [x10]
00145d48  stp      x10, x3, [sp, #0x20]
00145d4c  mov      x10, x19
00145d50  cmp      w9, #0
00145d54  strb     w9, [x3]
00145d58  csel     x11, x5, x26, eq
00145d5c  b        #0x1457b0
00145d60  mov      x0, x22
00145d64  ldp      x20, x19, [sp, #0xf0]
00145d68  ldp      x22, x21, [sp, #0xe0]
00145d6c  ldp      x24, x23, [sp, #0xd0]
00145d70  ldp      x26, x25, [sp, #0xc0]
00145d74  ldp      x28, x27, [sp, #0xb0]
00145d78  ldp      x29, x30, [sp, #0xa0]
00145d7c  add      sp, sp, #0x100
00145d80  ret      
00145d84  sub      sp, sp, #0x130
00145d88  stp      x29, x30, [sp, #0xd0]
00145d8c  stp      x28, x27, [sp, #0xe0]
00145d90  stp      x26, x25, [sp, #0xf0]
00145d94  stp      x24, x23, [sp, #0x100]
00145d98  stp      x22, x21, [sp, #0x110]
00145d9c  stp      x20, x19, [sp, #0x120]
00145da0  add      x29, sp, #0xd0
00145da4  sub      x8, x3, #1
00145da8  mov      x11, #0xdfb
00145dac  mov      x12, #0xde08
00145db0  mov      x13, #0x7df3
00145db4  mov      x14, #0x892a
00145db8  mov      x15, #0x55a2
00145dbc  stp      x8, x3, [sp]
00145dc0  and      x8, x1, #0xffffffff
00145dc4  mov      x16, #0x657a
00145dc8  mov      x17, #0xc0f4
00145dcc  mov      x7, #0x2cec
00145dd0  mov      x30, #0xf039
00145dd4  stp      x8, x0, [sp, #0x60]
00145dd8  mov      x9, #0x892a
00145ddc  movk     x11, #0x2958, lsl #16
00145de0  movk     x12, #0xc909, lsl #16
00145de4  movk     x13, #0xc080, lsl #16
00145de8  movk     x14, #0xf589, lsl #16
00145dec  movk     x15, #0xf7da, lsl #16
00145df0  movk     x16, #0xfdaf, lsl #16
00145df4  movk     x17, #0x5f9, lsl #16
00145df8  movk     x7, #0x1b16, lsl #16
00145dfc  movk     x30, #0x4336, lsl #16
00145e00  movk     x9, #0xf589, lsl #16
00145e04  movk     x11, #0x9f87, lsl #32
00145e08  movk     x12, #0x3343, lsl #32
00145e0c  movk     x13, #0x5a98, lsl #32
00145e10  movk     x14, #0xee2f, lsl #32
00145e14  movk     x15, #0xd1ac, lsl #32
00145e18  movk     x16, #0x9ffd, lsl #32
00145e1c  movk     x17, #0x5b42, lsl #32
00145e20  movk     x7, #0x9030, lsl #32
00145e24  movk     x30, #0xfc62, lsl #32
00145e28  movk     x9, #0xee2f, lsl #32
00145e2c  movk     x11, #0xd5b5, lsl #48
00145e30  movk     x12, #0xa7a4, lsl #48
00145e34  movk     x13, #0x1704, lsl #48
00145e38  movk     x14, #0x24c0, lsl #48
00145e3c  movk     x15, #0x87a9, lsl #48
00145e40  movk     x16, #0xb4b1, lsl #48
00145e44  movk     x17, #0xc20e, lsl #48
00145e48  movk     x7, #0xb6c1, lsl #48
00145e4c  movk     x30, #0xd078, lsl #48
00145e50  movk     x9, #0x24c0, lsl #48
00145e54  stp      x2, xzr, [sp, #0x40]
00145e58  mov      x8, x9
00145e5c  mov      x9, #0xde08
00145e60  mov      x22, x0
00145e64  mov      x24, x1
00145e68  ldp      x1, x0, [x29, #-0x18]
00145e6c  movk     x9, #0xc909, lsl #16
00145e70  mov      x21, x6
00145e74  movk     x9, #0x3343, lsl #32
00145e78  mov      x28, x5
00145e7c  mov      x25, x4
00145e80  mov      x23, x2
00145e84  mov      x2, x26
00145e88  mov      x4, x20
00145e8c  mov      x5, x27
00145e90  ldur     x6, [x29, #-0x20]
00145e94  movk     x9, #0xa7a4, lsl #48
00145e98  cmp      x8, x15
00145e9c  b.eq     #0x145e58
00145ea0  mov      x19, x3
00145ea4  cmp      x8, x12
00145ea8  b.eq     #0x146064
00145eac  cmp      x8, x16
00145eb0  b.eq     #0x1460ac
00145eb4  cmp      x8, x7
00145eb8  b.eq     #0x146194
00145ebc  mov      x9, #0xdfb
00145ec0  cmp      x8, x17
00145ec4  movk     x9, #0x2958, lsl #16
00145ec8  mov      x1, x24
00145ecc  movk     x9, #0x9f87, lsl #32
00145ed0  mov      x2, x23
00145ed4  ccmp     x8, x30, #4, ne
00145ed8  mov      x0, x22
00145edc  mov      x4, x25
00145ee0  mov      x3, x19
00145ee4  mov      x5, x28
00145ee8  mov      x6, x21
00145eec  movk     x9, #0xd5b5, lsl #48
00145ef0  b.eq     #0x145e58
00145ef4  mov      x9, #0x6c7b
00145ef8  mov      x1, x24
00145efc  movk     x9, #0xdbb6, lsl #16
00145f00  mov      x2, x23
00145f04  movk     x9, #0x615, lsl #32
00145f08  mov      x0, x22
00145f0c  mov      x4, x25
00145f10  ldur     x3, [x29, #-0x28]
00145f14  mov      x5, x28
00145f18  mov      x6, x21
00145f1c  movk     x9, #0x1904, lsl #48
00145f20  cmp      x8, x11
00145f24  b.eq     #0x145e58
00145f28  mov      x9, #0x23f8
00145f2c  movk     x9, #0x4d22, lsl #16
00145f30  movk     x9, #0x706a, lsl #32
00145f34  movk     x9, #0xe104, lsl #48
00145f38  cmp      x8, x9
00145f3c  b.eq     #0x1461c4
00145f40  cmp      x8, x13
00145f44  b.eq     #0x1462a8
00145f48  mov      x9, #0x7df3
00145f4c  mov      x1, x24
00145f50  movk     x9, #0xc080, lsl #16
00145f54  mov      x2, x23
00145f58  movk     x9, #0x5a98, lsl #32
00145f5c  mov      x0, x22
00145f60  mov      x4, x25
00145f64  mov      x3, x19
00145f68  mov      x5, x28
00145f6c  mov      x6, x21
00145f70  movk     x9, #0x1704, lsl #48
00145f74  cmp      x8, x14
00145f78  b.eq     #0x145e58
00145f7c  mov      x9, #0x7fe0
00145f80  movk     x9, #0xb22d, lsl #16
00145f84  movk     x9, #0x6acd, lsl #32
00145f88  movk     x9, #0x2fb9, lsl #48
00145f8c  cmp      x8, x9
00145f90  b.eq     #0x146308
00145f94  mov      x9, #0xde08
00145f98  mov      x10, #0xc59
00145f9c  ldp      x0, x1, [x29, #-0x40]
00145fa0  movk     x9, #0xc909, lsl #16
00145fa4  movk     x10, #0x6b1, lsl #16
00145fa8  movk     x9, #0x3343, lsl #32
00145fac  mov      x2, x26
00145fb0  ldur     x4, [x29, #-0x48]
00145fb4  mov      x3, x19
00145fb8  mov      x5, x27
00145fbc  ldur     x6, [x29, #-0x30]
00145fc0  movk     x9, #0xa7a4, lsl #48
00145fc4  movk     x10, #0xace6, lsl #32
00145fc8  movk     x10, #0x316a, lsl #48
00145fcc  cmp      x8, x10
00145fd0  b.eq     #0x145e58
00145fd4  mov      x9, #0x2a77
00145fd8  movk     x9, #0xf078, lsl #16
00145fdc  movk     x9, #0x8200, lsl #32
00145fe0  movk     x9, #0x3d54, lsl #48
00145fe4  cmp      x8, x9
00145fe8  b.eq     #0x146364
00145fec  mov      x9, #0xde08
00145ff0  mov      x10, #0x2807
00145ff4  ldp      x1, x0, [x29, #-0x18]
00145ff8  movk     x9, #0xc909, lsl #16
00145ffc  movk     x10, #0xc9ce, lsl #16
