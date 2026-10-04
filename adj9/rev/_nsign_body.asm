0db1cc: sub      sp, sp, #0x130
0db1d0: str      d12, [sp, #0xa0]
0db1d4: stp      d11, d10, [sp, #0xb0]
0db1d8: stp      d9, d8, [sp, #0xc0]
0db1dc: stp      x29, x30, [sp, #0xd0]
0db1e0: stp      x28, x27, [sp, #0xe0]
0db1e4: stp      x26, x25, [sp, #0xf0]
0db1e8: stp      x24, x23, [sp, #0x100]
0db1ec: stp      x22, x21, [sp, #0x110]
0db1f0: stp      x20, x19, [sp, #0x120]
0db1f4: add      x29, sp, #0xd0
0db1f8: mrs      x8, tpidr_el0
0db1fc: mov      w22, w5
0db200: str      x8, [sp, #8]
0db204: mov      x19, x0
0db208: ldr      x8, [x8, #0x28]
0db20c: stur     x8, [x29, #-0x40]
0db210: stp      x3, x2, [x29, #-0x50]
0db214: stur     x4, [x29, #-0x58]
0db218: stp      wzr, w5, [x29, #-0x60]
0db21c: bl       #0xe2be0
0db220: sub      x8, x29, #0x48
0db224: sub      x9, x29, #0x50
0db228: sub      x10, x29, #0x58
0db22c: sub      x11, x29, #0x5c
0db230: sub      x2, x29, #0x60
0db234: mov      w0, w22
0db238: mov      x1, x19
0db23c: stp      x19, x8, [sp, #0x48]
0db240: stp      x9, x10, [sp, #0x58]
0db244: str      x11, [sp, #0x68]
0db248: str      x19, [sp, #0x18]
0db24c: bl       #0x95fc4
0db250: ldur     w8, [x29, #-0x60]
0db254: mov      x9, #0x259
0db258: mov      x24, #0x8f9b
0db25c: movk     x9, #0x6e2a, lsl #16
0db260: movk     x24, #0xc267, lsl #16
0db264: mov      x27, #0x540b
0db268: mov      x19, #0x55a2
0db26c: mov      x21, #0xe4da
0db270: mov      x23, #0x4905
0db274: mov      x22, #0x657a
0db278: mov      x12, #0x540b
0db27c: movk     x9, #0xc6cb, lsl #32
0db280: movk     x24, #0xf353, lsl #32
0db284: movk     x27, #0x5e6a, lsl #16
0db288: movk     x19, #0xf7da, lsl #16
0db28c: movk     x21, #0x60f6, lsl #16
0db290: movk     x23, #0x4d4c, lsl #16
0db294: movk     x22, #0xfdaf, lsl #16
0db298: movk     x12, #0x5e6a, lsl #16
0db29c: movk     x9, #0x176e, lsl #48
0db2a0: movk     x24, #0x853c, lsl #48
0db2a4: movk     x27, #0x5fdc, lsl #32
0db2a8: movk     x19, #0xd1ac, lsl #32
0db2ac: movk     x21, #0xb0ba, lsl #32
0db2b0: cmp      w8, #0
0db2b4: movi     v10.8b, #0x33
0db2b8: movk     x23, #0xa445, lsl #32
0db2bc: movk     x22, #0x9ffd, lsl #32
0db2c0: movi     v11.8b, #0x3a
0db2c4: movi     v12.8b, #0xd4
0db2c8: movk     x12, #0x5fdc, lsl #32
0db2cc: movk     x27, #0x9974, lsl #48
0db2d0: movk     x19, #0x87a9, lsl #48
0db2d4: movk     x21, #0x8940, lsl #48
0db2d8: csel     x20, x24, x9, eq
0db2dc: movk     x23, #0x9d91, lsl #48
0db2e0: movk     x22, #0xb4b1, lsl #48
0db2e4: movk     x12, #0x9974, lsl #48
0db2e8: mov      x11, x12
0db2ec: mov      x12, #0x208d
0db2f0: movk     x12, #0x44b3, lsl #16
0db2f4: cmp      x11, x24
0db2f8: movk     x12, #0xb99f, lsl #32
0db2fc: movk     x12, #0x3ef2, lsl #48
0db300: b.eq     #0xdb2e8
0db304: mov      x12, #0xde08
0db308: mov      x28, x10
0db30c: movk     x12, #0xc909, lsl #16
0db310: mov      x25, x9
0db314: movk     x12, #0x3343, lsl #32
0db318: mov      w26, w8
0db31c: movk     x12, #0xa7a4, lsl #48
0db320: cmp      x11, x19
0db324: b.eq     #0xdb2e8
0db328: cmp      x11, x21
0db32c: b.eq     #0xdb81c
0db330: mov      w8, w26
0db334: mov      x9, x25
0db338: mov      x10, x28
0db33c: mov      x12, x20
0db340: cmp      x11, x27
0db344: b.eq     #0xdb2e8
0db348: mov      x12, #0x30e
0db34c: mov      w8, w26
0db350: movk     x12, #0x1b5, lsl #16
0db354: mov      x9, x25
0db358: movk     x12, #0x9ee9, lsl #32
0db35c: mov      x10, x28
0db360: movk     x12, #0xcf73, lsl #48
0db364: cmp      x11, x23
0db368: b.eq     #0xdb2e8
0db36c: mov      x12, #0x2807
0db370: mov      w8, w26
0db374: movk     x12, #0xc9ce, lsl #16
0db378: mov      x9, x25
0db37c: movk     x12, #0x58a8, lsl #32
0db380: mov      x10, x28
0db384: movk     x12, #0x4339, lsl #48
0db388: cmp      x11, x22
0db38c: b.eq     #0xdb2e8
0db390: mov      x8, #0x2cec
0db394: movk     x8, #0x1b16, lsl #16
0db398: movk     x8, #0x9030, lsl #32
0db39c: movk     x8, #0xb6c1, lsl #48
0db3a0: cmp      x11, x8
0db3a4: b.eq     #0xdbda4
0db3a8: mov      x12, #0xc59
0db3ac: mov      x13, #0xb5fd
0db3b0: movk     x12, #0x6b1, lsl #16
0db3b4: movk     x13, #0x5ecd, lsl #16
0db3b8: movk     x12, #0xace6, lsl #32
0db3bc: mov      w8, w26
0db3c0: mov      x9, x25
0db3c4: mov      x10, x28
0db3c8: movk     x12, #0x316a, lsl #48
0db3cc: movk     x13, #0x10d4, lsl #32
0db3d0: movk     x13, #0xc150, lsl #48
0db3d4: cmp      x11, x13
0db3d8: b.eq     #0xdb2e8
0db3dc: mov      x8, #0x1c0f
0db3e0: movk     x8, #0x6b47, lsl #16
0db3e4: movk     x8, #0x4b03, lsl #32
0db3e8: movk     x8, #0xc1bd, lsl #48
0db3ec: cmp      x11, x8
0db3f0: b.eq     #0xdbb9c
0db3f4: mov      x12, #0x2807
0db3f8: mov      x13, #0xc0f4
0db3fc: movk     x12, #0xc9ce, lsl #16
0db400: movk     x13, #0x5f9, lsl #16
0db404: movk     x12, #0x58a8, lsl #32
0db408: mov      w8, w26
0db40c: mov      x9, x25
0db410: mov      x10, x28
0db414: movk     x12, #0x4339, lsl #48
0db418: movk     x13, #0x5b42, lsl #32
0db41c: movk     x13, #0xc20e, lsl #48
0db420: cmp      x11, x13
0db424: b.eq     #0xdb2e8
0db428: mov      x12, #0xdfbb
0db42c: mov      x13, #0x4654
0db430: movk     x12, #0xfd40, lsl #16
0db434: movk     x13, #0x6d04, lsl #16
0db438: movk     x12, #0xeac0, lsl #32
0db43c: mov      w8, w26
0db440: mov      x9, x25
0db444: mov      x10, x28
0db448: movk     x12, #0x1ca0, lsl #48
0db44c: movk     x13, #0xc0d1, lsl #32
0db450: movk     x13, #0xcf0c, lsl #48
0db454: cmp      x11, x13
0db458: b.eq     #0xdb2e8
0db45c: mov      x8, #0x30e
0db460: movk     x8, #0x1b5, lsl #16
0db464: movk     x8, #0x9ee9, lsl #32
0db468: movk     x8, #0xcf73, lsl #48
0db46c: cmp      x11, x8
0db470: b.eq     #0xdbd68
0db474: mov      x8, #0xf039
0db478: movk     x8, #0x4336, lsl #16
0db47c: movk     x8, #0xfc62, lsl #32
0db480: movk     x8, #0xd078, lsl #48
0db484: cmp      x11, x8
0db488: b.eq     #0xdb930
0db48c: mov      x12, #0xb0b0
0db490: mov      x13, #0xdfb
0db494: movk     x12, #0x4891, lsl #16
0db498: movk     x13, #0x2958, lsl #16
0db49c: movk     x12, #0xd7d8, lsl #32
0db4a0: mov      w8, w26
0db4a4: mov      x9, x25
0db4a8: mov      x10, x28
0db4ac: movk     x12, #0x3df5, lsl #48
0db4b0: movk     x13, #0x9f87, lsl #32
0db4b4: movk     x13, #0xd5b5, lsl #48
0db4b8: cmp      x11, x13
0db4bc: b.eq     #0xdb2e8
0db4c0: mov      x8, #0x23f8
0db4c4: movk     x8, #0x4d22, lsl #16
0db4c8: movk     x8, #0x706a, lsl #32
0db4cc: movk     x8, #0xe104, lsl #48
0db4d0: cmp      x11, x8
0db4d4: b.eq     #0xdba58
0db4d8: mov      x8, #0x14ed
0db4dc: movk     x8, #0xed0, lsl #16
0db4e0: movk     x8, #0x391e, lsl #32
0db4e4: movk     x8, #0xfac5, lsl #48
0db4e8: cmp      x11, x8
0db4ec: b.eq     #0xdb8d8
0db4f0: mov      x8, #0xafca
0db4f4: movk     x8, #0x7c1a, lsl #16
0db4f8: movk     x8, #0x1e39, lsl #32
0db4fc: movk     x8, #0x6f3, lsl #48
0db500: cmp      x11, x8
0db504: b.eq     #0xdb904
0db508: mov      x12, #0x892a
0db50c: mov      x13, #0xf23e
0db510: movk     x12, #0xf589, lsl #16
0db514: movk     x13, #0xeb9c, lsl #16
0db518: movk     x12, #0xee2f, lsl #32
0db51c: mov      w8, w26
0db520: mov      x9, x25
0db524: mov      x10, x28
0db528: movk     x12, #0x24c0, lsl #48
0db52c: movk     x13, #0x667e, lsl #32
0db530: movk     x13, #0x7c8, lsl #48
0db534: cmp      x11, x13
0db538: b.eq     #0xdb2e8
0db53c: mov      x8, #0x64c6
0db540: movk     x8, #0xb4df, lsl #16
0db544: movk     x8, #0xca87, lsl #32
0db548: movk     x8, #0x162c, lsl #48
0db54c: cmp      x11, x8
0db550: b.eq     #0xdbd0c
0db554: mov      x13, #0x7df3
0db558: mov      w8, w26
0db55c: movk     x13, #0xc080, lsl #16
0db560: mov      x9, x25
0db564: mov      x10, x28
0db568: movk     x13, #0x5a98, lsl #32
0db56c: movk     x13, #0x1704, lsl #48
0db570: cmp      x11, x13
0db574: b.eq     #0xdb2e8
0db578: mov      x8, #0x259
0db57c: movk     x8, #0x6e2a, lsl #16
0db580: movk     x8, #0xc6cb, lsl #32
0db584: movk     x8, #0x176e, lsl #48
0db588: cmp      x11, x8
0db58c: b.eq     #0xdbbbc
0db590: mov      x8, #0x6c7b
0db594: movk     x8, #0xdbb6, lsl #16
0db598: movk     x8, #0x615, lsl #32
0db59c: movk     x8, #0x1904, lsl #48
0db5a0: cmp      x11, x8
0db5a4: b.eq     #0xdb7f4
0db5a8: mov      x8, #0xdfbb
0db5ac: movk     x8, #0xfd40, lsl #16
0db5b0: movk     x8, #0xeac0, lsl #32
0db5b4: movk     x8, #0x1ca0, lsl #48
0db5b8: cmp      x11, x8
0db5bc: b.eq     #0xdb964
0db5c0: mov      x8, #0x892a
0db5c4: movk     x8, #0xf589, lsl #16
0db5c8: movk     x8, #0xee2f, lsl #32
0db5cc: movk     x8, #0x24c0, lsl #48
0db5d0: cmp      x11, x8
0db5d4: b.eq     #0xdbcc8
0db5d8: mov      x8, #0xe6b2
0db5dc: movk     x8, #0xa01a, lsl #16
0db5e0: movk     x8, #0x11ba, lsl #32
0db5e4: movk     x8, #0x26d0, lsl #48
0db5e8: cmp      x11, x8
0db5ec: b.eq     #0xdbc14
0db5f0: mov      x8, #0x2214
0db5f4: movk     x8, #0x6e6c, lsl #16
0db5f8: movk     x8, #0x2705, lsl #32
0db5fc: movk     x8, #0x2e9a, lsl #48
0db600: cmp      x11, x8
0db604: b.eq     #0xdbc88
0db608: mov      x8, #0x7fe0
0db60c: movk     x8, #0xb22d, lsl #16
0db610: movk     x8, #0x6acd, lsl #32
0db614: movk     x8, #0x2fb9, lsl #48
0db618: cmp      x11, x8
0db61c: b.eq     #0xdb858
0db620: mov      x8, #0xc59
0db624: movk     x8, #0x6b1, lsl #16
0db628: movk     x8, #0xace6, lsl #32
0db62c: movk     x8, #0x316a, lsl #48
0db630: cmp      x11, x8
0db634: b.eq     #0xdbb00
0db638: mov      x8, #0x4fa1
0db63c: movk     x8, #0x3fc2, lsl #16
0db640: movk     x8, #0x4b99, lsl #32
0db644: movk     x8, #0x365c, lsl #48
0db648: cmp      x11, x8
0db64c: b.eq     #0xdbbe0
0db650: mov      x12, #0x64c6
0db654: mov      x13, #0xc6bd
0db658: movk     x12, #0xb4df, lsl #16
0db65c: movk     x13, #0xda71, lsl #16
0db660: movk     x12, #0xca87, lsl #32
0db664: ldr      w8, [sp, #0x3c]
0db668: mov      x9, x25
0db66c: mov      x10, x28
0db670: movk     x12, #0x162c, lsl #48
0db674: movk     x13, #0x6422, lsl #32
0db678: movk     x13, #0x3b0d, lsl #48
0db67c: cmp      x11, x13
0db680: b.eq     #0xdb2e8
0db684: mov      x8, #0x2a77
0db688: movk     x8, #0xf078, lsl #16
0db68c: movk     x8, #0x8200, lsl #32
0db690: movk     x8, #0x3d54, lsl #48
0db694: cmp      x11, x8
0db698: b.eq     #0xdb894
0db69c: mov      x8, #0xb0b0
0db6a0: movk     x8, #0x4891, lsl #16
0db6a4: movk     x8, #0xd7d8, lsl #32
0db6a8: movk     x8, #0x3df5, lsl #48
0db6ac: cmp      x11, x8
0db6b0: b.eq     #0xdbb3c
0db6b4: mov      x8, #0x208d
0db6b8: movk     x8, #0x44b3, lsl #16
0db6bc: movk     x8, #0xb99f, lsl #32
0db6c0: movk     x8, #0x3ef2, lsl #48
0db6c4: cmp      x11, x8
0db6c8: b.eq     #0xdb9c0
0db6cc: mov      x8, #0x2807
0db6d0: movk     x8, #0xc9ce, lsl #16
0db6d4: movk     x8, #0x58a8, lsl #32
0db6d8: movk     x8, #0x4339, lsl #48
0db6dc: cmp      x11, x8
0db6e0: b.eq     #0xdba18
0db6e4: mov      x12, #0x7fe0
0db6e8: mov      x13, #0x5e5d
0db6ec: movk     x12, #0xb22d, lsl #16
0db6f0: movk     x13, #0xe6ee, lsl #16
0db6f4: movk     x12, #0x6acd, lsl #32
0db6f8: mov      w8, w26
0db6fc: mov      x9, x25
0db700: mov      x10, x28
0db704: movk     x12, #0x2fb9, lsl #48
0db708: movk     x13, #0xcd9a, lsl #32
0db70c: movk     x13, #0x450f, lsl #48
0db710: cmp      x11, x13
0db714: b.eq     #0xdb2e8
0db718: mov      x12, #0x2a77
0db71c: mov      x13, #0x933c
0db720: movk     x12, #0xf078, lsl #16
0db724: movk     x13, #0x4138, lsl #16
0db728: movk     x12, #0x8200, lsl #32
0db72c: mov      w8, w26
0db730: mov      x9, x25
0db734: mov      x10, x28
0db738: movk     x12, #0x3d54, lsl #48
0db73c: movk     x13, #0xbb88, lsl #32
0db740: movk     x13, #0x5c22, lsl #48
0db744: cmp      x11, x13
0db748: b.eq     #0xdb2e8
0db74c: mov      x12, #0x2214
0db750: mov      x13, #0x4bb4
0db754: movk     x12, #0x6e6c, lsl #16
0db758: movk     x13, #0x877, lsl #16
0db75c: movk     x12, #0x2705, lsl #32
0db760: mov      w8, w26
0db764: mov      x9, x25
0db768: mov      x10, x28
0db76c: movk     x12, #0x2e9a, lsl #48
0db770: movk     x13, #0x5974, lsl #32
0db774: movk     x13, #0x5eff, lsl #48
0db778: cmp      x11, x13
0db77c: b.eq     #0xdb2e8
0db780: mov      x12, #0x30e
0db784: mov      x13, #0xd62d
0db788: ldp      x10, x9, [sp, #0x28]
0db78c: movk     x12, #0x1b5, lsl #16
0db790: movk     x13, #0xa717, lsl #16
0db794: movk     x12, #0x9ee9, lsl #32
0db798: mov      w8, w26
0db79c: movk     x12, #0xcf73, lsl #48
0db7a0: movk     x13, #0xd684, lsl #32
0db7a4: movk     x13, #0x75ea, lsl #48
0db7a8: cmp      x11, x13
0db7ac: b.eq     #0xdb2e8
0db7b0: mov      x8, #0xe526
0db7b4: movk     x8, #0xc774, lsl #16
0db7b8: movk     x8, #0xaacf, lsl #32
0db7bc: movk     x8, #0x7d8f, lsl #48
0db7c0: cmp      x11, x8
0db7c4: b.eq     #0xdb9e0
0db7c8: mov      x13, #0xde08
0db7cc: mov      w8, w26
0db7d0: movk     x13, #0xc909, lsl #16
0db7d4: mov      x9, x25
0db7d8: mov      x10, x28
0db7dc: mov      x12, x11
0db7e0: movk     x13, #0x3343, lsl #32
0db7e4: movk     x13, #0xa7a4, lsl #48
0db7e8: cmp      x11, x13
0db7ec: b.ne     #0xdb2e8
0db7f0: b        #0xdbdf8
0db7f4: adrp     x8, #0x155000
0db7f8: mov      x9, #0x4654
0db7fc: movk     x9, #0x6d04, lsl #16
0db800: movk     x9, #0xc0d1, lsl #32
0db804: ldrb     w8, [x8, #0xd92]
0db808: movk     x9, #0xcf0c, lsl #48
0db80c: cmp      w8, #0
0db810: mov      w8, w26
0db814: csel     x12, x9, x21, ne
0db818: b        #0xdbd98
0db81c: adrp     x11, #0x154000
0db820: mov      x12, #0xdfbb
0db824: mov      w13, #1
0db828: movk     x12, #0xfd40, lsl #16
0db82c: movk     x12, #0xeac0, lsl #32
0db830: mov      w8, w26
0db834: ldr      d0, [x11, #0x880]
0db838: mov      x9, x25
0db83c: mov      x10, x28
0db840: movk     x12, #0x1ca0, lsl #48
0db844: eor      v0.8b, v0.8b, v10.8b
0db848: str      d0, [x11, #0x880]
0db84c: adrp     x11, #0x155000
0db850: strb     w13, [x11, #0xd92]
0db854: b        #0xdb2e8
0db858: fmov     d0, d8
0db85c: nop      
0db860: adr      x8, #0x155d8c
0db864: nop      
0db868: adr      x0, #0x154890
0db86c: stlrb    wzr, [x8]
0db870: bl       #0x13d874
0db874: mov      x12, #0x2a77
0db878: mov      w8, w26
0db87c: movk     x12, #0xf078, lsl #16
0db880: mov      x9, x25
0db884: movk     x12, #0x8200, lsl #32
0db888: mov      x10, x28
0db88c: movk     x12, #0x3d54, lsl #48
0db890: b        #0xdb2e8
0db894: add      x0, sp, #0x48
0db898: bl       #0xda97c
0db89c: movi     d0, #0000000000000000
0db8a0: str      x0, [sp, #0x10]
0db8a4: sub      x0, x29, #0x60
0db8a8: stur     wzr, [x29, #-0x60]
0db8ac: bl       #0x13de90
0db8b0: ldur     w8, [x29, #-0x60]
0db8b4: fmov     d9, d0
0db8b8: ldr      w9, [sp, #0x24]
0db8bc: cmp      w8, #0
0db8c0: cset     w8, ne
0db8c4: orr      w8, w8, w9
0db8c8: tst      w8, #1
0db8cc: mov      w8, w26
0db8d0: csel     x12, x19, x22, ne
0db8d4: b        #0xdbd98
0db8d8: adrp     x8, #0x155000
0db8dc: mov      x9, #0x2cec
0db8e0: mov      x10, #0x5e5d
0db8e4: movk     x9, #0x1b16, lsl #16
0db8e8: movk     x10, #0xe6ee, lsl #16
0db8ec: movk     x9, #0x9030, lsl #32
0db8f0: ldrb     w8, [x8, #0xd93]
0db8f4: movk     x10, #0xcd9a, lsl #32
0db8f8: movk     x9, #0xb6c1, lsl #48
0db8fc: movk     x10, #0x450f, lsl #48
0db900: b        #0xdb958
0db904: add      x9, x25, #1
0db908: add      x8, x28, #1
0db90c: mov      x12, #0xd62d
0db910: mov      x10, x28
0db914: movk     x12, #0xa717, lsl #16
0db918: movk     x12, #0xd684, lsl #32
0db91c: stp      x8, x9, [sp, #0x28]
0db920: mov      w8, w26
0db924: mov      x9, x25
0db928: movk     x12, #0x75ea, lsl #48
0db92c: b        #0xdb2e8
0db930: adrp     x8, #0x155000
0db934: mov      x9, #0xe6b2
0db938: mov      x10, #0xdfb
0db93c: movk     x9, #0xa01a, lsl #16
0db940: movk     x10, #0x2958, lsl #16
0db944: movk     x9, #0x11ba, lsl #32
0db948: ldrb     w8, [x8, #0xd91]
0db94c: movk     x10, #0x9f87, lsl #32
0db950: movk     x9, #0x26d0, lsl #48
0db954: movk     x10, #0xd5b5, lsl #48
0db958: cmp      w8, #0
0db95c: mov      w8, w26
0db960: b        #0xdb9b8
0db964: nop      
0db968: adr      x8, #0x155d88
0db96c: stlrb    wzr, [x8]
0db970: ldrb     w8, [x25]
0db974: ldrb     w9, [x28]
0db978: cmp      w8, #0
0db97c: cset     w10, eq
0db980: cmp      w8, w9
0db984: cset     w9, ne
0db988: csinc    w8, w10, wzr, eq
0db98c: mov      x10, #0xc6bd
0db990: cmp      w8, #0
0db994: movk     x10, #0xda71, lsl #16
0db998: mov      w8, w26
0db99c: str      w9, [sp, #0x3c]
0db9a0: mov      x9, #0xafca
0db9a4: movk     x9, #0x7c1a, lsl #16
0db9a8: movk     x10, #0x6422, lsl #32
0db9ac: movk     x9, #0x1e39, lsl #32
0db9b0: movk     x10, #0x3b0d, lsl #48
0db9b4: movk     x9, #0x6f3, lsl #48
0db9b8: csel     x12, x10, x9, ne
0db9bc: b        #0xdbd98
0db9c0: mov      x12, #0x2214
0db9c4: mov      w8, w26
0db9c8: movk     x12, #0x6e6c, lsl #16
0db9cc: mov      x9, x25
0db9d0: movk     x12, #0x2705, lsl #32
0db9d4: mov      x10, x28
0db9d8: movk     x12, #0x2e9a, lsl #48
0db9dc: b        #0xdb2e8
0db9e0: adrp     x8, #0x155000
0db9e4: mov      x9, #0xb5fd
0db9e8: mov      x10, #0x23f8
0db9ec: movk     x9, #0x5ecd, lsl #16
0db9f0: movk     x10, #0x4d22, lsl #16
0db9f4: movk     x9, #0x10d4, lsl #32
0db9f8: ldrb     w8, [x8, #0xd94]
0db9fc: movk     x10, #0x706a, lsl #32
0dba00: movk     x9, #0xc150, lsl #48
0dba04: movk     x10, #0xe104, lsl #48
0dba08: cmp      w8, #0
0dba0c: mov      w8, w26
0dba10: csel     x12, x9, x10, ne
0dba14: b        #0xdbd98
0dba18: mov      w0, wzr
0dba1c: mov      w1, #1
0dba20: nop      
0dba24: adr      x2, #0x155d90
0dba28: bl       #0x1483e0
0dba2c: mov      x9, #0xc0f4
0dba30: mov      x10, #0xe526
0dba34: movk     x9, #0x5f9, lsl #16
0dba38: movk     x10, #0xc774, lsl #16
0dba3c: movk     x9, #0x5b42, lsl #32
0dba40: movk     x10, #0xaacf, lsl #32
0dba44: mov      w8, w26
0dba48: movk     x9, #0xc20e, lsl #48
0dba4c: movk     x10, #0x7d8f, lsl #48
0dba50: cmp      w0, #0
0dba54: b        #0xdbb94
0dba58: nop      
0dba5c: adr      x13, #0x1548c0
0dba60: mov      w12, #0x3a
0dba64: movi     v1.16b, #0x3a
0dba68: ldrb     w8, [x13, #0x18]
0dba6c: ldrb     w9, [x13, #0x19]
0dba70: ldrb     w10, [x13, #0x1a]
0dba74: eor      w8, w8, w12
0dba78: ldrb     w11, [x13, #0x1b]
0dba7c: eor      w9, w9, w12
0dba80: ldr      q0, [x13]
0dba84: strb     w8, [x13, #0x18]
0dba88: eor      w8, w10, w12
0dba8c: eor      w10, w11, w12
0dba90: strb     w9, [x13, #0x19]
0dba94: ldrb     w9, [x13, #0x1c]
0dba98: mov      w11, #1
0dba9c: strb     w8, [x13, #0x1a]
0dbaa0: ldrb     w8, [x13, #0x1d]
0dbaa4: strb     w10, [x13, #0x1b]
0dbaa8: ldrb     w10, [x13, #0x1e]
0dbaac: eor      v0.16b, v0.16b, v1.16b
0dbab0: eor      w9, w9, w12
0dbab4: str      q0, [x13]
0dbab8: ldr      d0, [x13, #0x10]
0dbabc: eor      w8, w8, w12
0dbac0: eor      w10, w10, w12
0dbac4: strb     w9, [x13, #0x1c]
0dbac8: mov      x12, #0xc59
0dbacc: eor      v0.8b, v0.8b, v11.8b
0dbad0: movk     x12, #0x6b1, lsl #16
0dbad4: strb     w8, [x13, #0x1d]
0dbad8: movk     x12, #0xace6, lsl #32
0dbadc: strb     w10, [x13, #0x1e]
0dbae0: mov      w8, w26
0dbae4: str      d0, [x13, #0x10]
0dbae8: adrp     x13, #0x155000
0dbaec: mov      x9, x25
0dbaf0: mov      x10, x28
0dbaf4: movk     x12, #0x316a, lsl #48
0dbaf8: strb     w11, [x13, #0xd94]
0dbafc: b        #0xdb2e8
0dbb00: fmov     d0, d9
0dbb04: nop      
0dbb08: adr      x8, #0x155d90
0dbb0c: nop      
0dbb10: adr      x0, #0x1548c0
0dbb14: stlrb    wzr, [x8]
0dbb18: bl       #0x13d874
0dbb1c: mov      x12, #0xde08
0dbb20: mov      w8, w26
0dbb24: movk     x12, #0xc909, lsl #16
0dbb28: mov      x9, x25
0dbb2c: movk     x12, #0x3343, lsl #32
0dbb30: mov      x10, x28
0dbb34: movk     x12, #0xa7a4, lsl #48
0dbb38: b        #0xdb2e8
0dbb3c: nop      
0dbb40: adr      x8, #0x155d84
0dbb44: sub      x0, x29, #0x60
0dbb48: add      x4, sp, #0x40
0dbb4c: nop      
0dbb50: adr      x3, #0x154870
0dbb54: stlrb    wzr, [x8]
0dbb58: ldur     x2, [x29, #-0x50]
0dbb5c: str      xzr, [sp, #0x40]
0dbb60: ldr      x1, [sp, #0x18]
0dbb64: bl       #0xbb548
0dbb68: ldur     w8, [x29, #-0x60]
0dbb6c: mov      x9, #0x1c0f
0dbb70: mov      x10, #0x4fa1
0dbb74: movk     x9, #0x6b47, lsl #16
0dbb78: movk     x10, #0x3fc2, lsl #16
0dbb7c: movk     x9, #0x4b03, lsl #32
0dbb80: movk     x10, #0x4b99, lsl #32
0dbb84: cmp      w8, #0
0dbb88: mov      w8, w26
0dbb8c: movk     x9, #0xc1bd, lsl #48
0dbb90: movk     x10, #0x365c, lsl #48
0dbb94: csel     x12, x10, x9, eq
0dbb98: b        #0xdbd98
0dbb9c: mov      x12, #0x64c6
0dbba0: mov      w8, #1
0dbba4: movk     x12, #0xb4df, lsl #16
0dbba8: mov      x9, x25
0dbbac: movk     x12, #0xca87, lsl #32
0dbbb0: mov      x10, x28
0dbbb4: movk     x12, #0x162c, lsl #48
0dbbb8: b        #0xdb2e8
0dbbbc: mov      x12, #0x208d
0dbbc0: mov      w8, w26
0dbbc4: movk     x12, #0x44b3, lsl #16
0dbbc8: mov      x9, x25
0dbbcc: movk     x12, #0xb99f, lsl #32
0dbbd0: mov      x10, x28
0dbbd4: movk     x12, #0x3ef2, lsl #48
0dbbd8: stur     wzr, [x29, #-0x60]
0dbbdc: b        #0xdb2e8
0dbbe0: ldr      x8, [sp, #0x40]
0dbbe4: nop      
0dbbe8: adr      x11, #0x154880
0dbbec: mov      x12, #0xd62d
0dbbf0: movk     x12, #0xa717, lsl #16
0dbbf4: mov      x9, x25
0dbbf8: movk     x12, #0xd684, lsl #32
0dbbfc: str      x8, [sp, #0x30]
0dbc00: mov      w8, w26
0dbc04: mov      x10, x28
0dbc08: str      x11, [sp, #0x28]
0dbc0c: movk     x12, #0x75ea, lsl #48
0dbc10: b        #0xdb2e8
0dbc14: nop      
0dbc18: adr      x13, #0x154870
0dbc1c: mov      w12, #0xd4
0dbc20: ldrb     w8, [x13, #8]
0dbc24: ldrb     w9, [x13, #9]
0dbc28: ldrb     w10, [x13, #0xa]
0dbc2c: eor      w8, w8, w12
0dbc30: ldrb     w11, [x13, #0xb]
0dbc34: ldr      d0, [x13]
0dbc38: eor      w9, w9, w12
0dbc3c: strb     w8, [x13, #8]
0dbc40: eor      w8, w10, w12
0dbc44: eor      w10, w11, w12
0dbc48: eor      v0.8b, v0.8b, v12.8b
0dbc4c: strb     w9, [x13, #9]
0dbc50: mov      x12, #0xb0b0
0dbc54: strb     w8, [x13, #0xa]
0dbc58: mov      w11, #1
0dbc5c: strb     w10, [x13, #0xb]
0dbc60: movk     x12, #0x4891, lsl #16
0dbc64: str      d0, [x13]
0dbc68: adrp     x13, #0x155000
0dbc6c: movk     x12, #0xd7d8, lsl #32
0dbc70: mov      w8, w26
0dbc74: mov      x9, x25
0dbc78: mov      x10, x28
0dbc7c: movk     x12, #0x3df5, lsl #48
0dbc80: strb     w11, [x13, #0xd91]
0dbc84: b        #0xdb2e8
0dbc88: mov      w0, wzr
0dbc8c: mov      w1, #1
0dbc90: nop      
0dbc94: adr      x2, #0x155d84
0dbc98: bl       #0x1483e0
0dbc9c: mov      x9, #0xf039
0dbca0: mov      x10, #0x4bb4
0dbca4: movk     x9, #0x4336, lsl #16
0dbca8: movk     x10, #0x877, lsl #16
0dbcac: movk     x9, #0xfc62, lsl #32
0dbcb0: movk     x10, #0x5974, lsl #32
0dbcb4: mov      w8, w26
0dbcb8: movk     x9, #0xd078, lsl #48
0dbcbc: movk     x10, #0x5eff, lsl #48
0dbcc0: cmp      w0, #0
0dbcc4: b        #0xdbd04
0dbcc8: mov      w0, wzr
0dbccc: mov      w1, #1
0dbcd0: nop      
0dbcd4: adr      x2, #0x155d8c
0dbcd8: bl       #0x1483e0
0dbcdc: mov      x9, #0x14ed
0dbce0: mov      x10, #0x7df3
0dbce4: movk     x9, #0xed0, lsl #16
0dbce8: movk     x10, #0xc080, lsl #16
0dbcec: movk     x9, #0x391e, lsl #32
0dbcf0: movk     x10, #0x5a98, lsl #32
0dbcf4: mov      w8, w26
0dbcf8: cmp      w0, #0
0dbcfc: movk     x9, #0xfac5, lsl #48
0dbd00: movk     x10, #0x1704, lsl #48
0dbd04: csel     x12, x9, x10, eq
0dbd08: b        #0xdbd98
0dbd0c: movi     d0, #0000000000000000
0dbd10: sub      x0, x29, #0x60
0dbd14: bl       #0x13de90
0dbd18: ldur     w8, [x29, #-0x60]
0dbd1c: mov      x10, #0xf23e
0dbd20: mov      x11, #0x933c
0dbd24: movk     x10, #0xeb9c, lsl #16
0dbd28: movk     x11, #0x4138, lsl #16
0dbd2c: movk     x10, #0x667e, lsl #32
0dbd30: cmp      w8, #0
0dbd34: movk     x11, #0xbb88, lsl #32
0dbd38: cset     w8, ne
0dbd3c: movk     x10, #0x7c8, lsl #48
0dbd40: orr      w9, w8, w26
0dbd44: movk     x11, #0x5c22, lsl #48
0dbd48: tst      w9, #1
0dbd4c: fmov     d8, d0
0dbd50: mov      w8, w26
0dbd54: mov      x9, x25
0dbd58: csel     x12, x11, x10, ne
0dbd5c: mov      x10, x28
0dbd60: str      w26, [sp, #0x24]
0dbd64: b        #0xdb2e8
0dbd68: mov      w0, wzr
0dbd6c: mov      w1, #1
0dbd70: nop      
0dbd74: adr      x2, #0x155d88
0dbd78: bl       #0x1483e0
0dbd7c: mov      x9, #0x6c7b
0dbd80: cmp      w0, #0
0dbd84: movk     x9, #0xdbb6, lsl #16
0dbd88: mov      w8, w26
0dbd8c: movk     x9, #0x615, lsl #32
0dbd90: movk     x9, #0x1904, lsl #48
0dbd94: csel     x12, x9, x23, eq
0dbd98: mov      x9, x25
0dbd9c: mov      x10, x28
0dbda0: b        #0xdb2e8
0dbda4: nop      
0dbda8: adr      x13, #0x154890
0dbdac: movi     v2.16b, #0xe
0dbdb0: mov      x12, #0x7fe0
0dbdb4: movk     x12, #0xb22d, lsl #16
0dbdb8: mov      w8, w26
0dbdbc: ldp      q0, q1, [x13]
0dbdc0: movk     x12, #0x6acd, lsl #32
0dbdc4: mov      x9, x25
0dbdc8: mov      x10, x28
0dbdcc: movk     x12, #0x2fb9, lsl #48
0dbdd0: eor      v0.16b, v0.16b, v2.16b
0dbdd4: ldrb     w11, [x13, #0x20]
0dbdd8: eor      v1.16b, v1.16b, v2.16b
0dbddc: stp      q0, q1, [x13]
0dbde0: eor      w11, w11, #0xe
0dbde4: strb     w11, [x13, #0x20]
0dbde8: mov      w11, #1
0dbdec: adrp     x13, #0x155000
0dbdf0: strb     w11, [x13, #0xd93]
0dbdf4: b        #0xdb2e8
0dbdf8: ldr      x8, [sp, #8]
0dbdfc: ldr      x8, [x8, #0x28]
0dbe00: ldur     x9, [x29, #-0x40]
0dbe04: cmp      x8, x9
0dbe08: b.ne     #0xdbe3c
0dbe0c: ldp      x20, x19, [sp, #0x120]
0dbe10: ldp      x22, x21, [sp, #0x110]
0dbe14: ldp      x24, x23, [sp, #0x100]
0dbe18: ldp      x26, x25, [sp, #0xf0]
0dbe1c: ldp      x28, x27, [sp, #0xe0]
0dbe20: ldp      x29, x30, [sp, #0xd0]
0dbe24: ldp      d9, d8, [sp, #0xc0]
0dbe28: ldp      d11, d10, [sp, #0xb0]
0dbe2c: ldr      x0, [sp, #0x10]
0dbe30: ldr      d12, [sp, #0xa0]
0dbe34: add      sp, sp, #0x130
0dbe38: ret      
0dbe3c: bl       #0x148a10