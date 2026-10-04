
extracted/arm64/lib/arm64-v8a/libsigner.so:	file format elf64-littleaarch64

Disassembly of section .text:

00000000000db1cc <Java_com_adjust_sdk_sig_NativeLibHelper_nSign>:
   db1cc: d104c3ff     	sub	sp, sp, #0x130
   db1d0: fd0053ec     	str	d12, [sp, #0xa0]
   db1d4: 6d0b2beb     	stp	d11, d10, [sp, #0xb0]
   db1d8: 6d0c23e9     	stp	d9, d8, [sp, #0xc0]
   db1dc: a90d7bfd     	stp	x29, x30, [sp, #0xd0]
   db1e0: a90e6ffc     	stp	x28, x27, [sp, #0xe0]
   db1e4: a90f67fa     	stp	x26, x25, [sp, #0xf0]
   db1e8: a9105ff8     	stp	x24, x23, [sp, #0x100]
   db1ec: a91157f6     	stp	x22, x21, [sp, #0x110]
   db1f0: a9124ff4     	stp	x20, x19, [sp, #0x120]
   db1f4: 910343fd     	add	x29, sp, #0xd0
   db1f8: d53bd048     	mrs	x8, TPIDR_EL0
   db1fc: 2a0503f6     	mov	w22, w5
   db200: f90007e8     	str	x8, [sp, #0x8]
   db204: aa0003f3     	mov	x19, x0
   db208: f9401508     	ldr	x8, [x8, #0x28]
   db20c: f81c03a8     	stur	x8, [x29, #-0x40]
   db210: a93b0ba3     	stp	x3, x2, [x29, #-0x50]
   db214: f81a83a4     	stur	x4, [x29, #-0x58]
   db218: 293417bf     	stp	wzr, w5, [x29, #-0x60]
   db21c: 94001e71     	bl	0xe2be0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x7a14>
   db220: d10123a8     	sub	x8, x29, #0x48
   db224: d10143a9     	sub	x9, x29, #0x50
   db228: d10163aa     	sub	x10, x29, #0x58
   db22c: d10173ab     	sub	x11, x29, #0x5c
   db230: d10183a2     	sub	x2, x29, #0x60
   db234: 2a1603e0     	mov	w0, w22
   db238: aa1303e1     	mov	x1, x19
   db23c: a904a3f3     	stp	x19, x8, [sp, #0x48]
   db240: a905abe9     	stp	x9, x10, [sp, #0x58]
   db244: f90037eb     	str	x11, [sp, #0x68]
   db248: f9000ff3     	str	x19, [sp, #0x18]
   db24c: 97feeb5e     	bl	0x95fc4 <.text+0x8d3e4>
   db250: b85a03a8     	ldur	w8, [x29, #-0x60]
   db254: d2804b29     	mov	x9, #0x259
   db258: d291f378     	mov	x24, #0x8f9b
   db25c: f2adc549     	movk	x9, #0x6e2a, lsl #16
   db260: f2b84cf8     	movk	x24, #0xc267, lsl #16
   db264: d28a817b     	mov	x27, #0x540b
   db268: d28ab453     	mov	x19, #0x55a2
   db26c: d29c9b55     	mov	x21, #0xe4da
   db270: d28920b7     	mov	x23, #0x4905
   db274: d28caf56     	mov	x22, #0x657a
   db278: d28a816c     	mov	x12, #0x540b
   db27c: f2d8d969     	movk	x9, #0xc6cb, lsl #32
   db280: f2de6a78     	movk	x24, #0xf353, lsl #32
   db284: f2abcd5b     	movk	x27, #0x5e6a, lsl #16
   db288: f2befb53     	movk	x19, #0xf7da, lsl #16
   db28c: f2ac1ed5     	movk	x21, #0x60f6, lsl #16
   db290: f2a9a997     	movk	x23, #0x4d4c, lsl #16
   db294: f2bfb5f6     	movk	x22, #0xfdaf, lsl #16
   db298: f2abcd4c     	movk	x12, #0x5e6a, lsl #16
   db29c: f2e2edc9     	movk	x9, #0x176e, lsl #48
   db2a0: f2f0a798     	movk	x24, #0x853c, lsl #48
   db2a4: f2cbfb9b     	movk	x27, #0x5fdc, lsl #32
   db2a8: f2da3593     	movk	x19, #0xd1ac, lsl #32
   db2ac: f2d61755     	movk	x21, #0xb0ba, lsl #32
   db2b0: 7100011f     	cmp	w8, #0x0
   db2b4: 0f01e66a     	movi	v10.8b, #0x33
   db2b8: f2d488b7     	movk	x23, #0xa445, lsl #32
   db2bc: f2d3ffb6     	movk	x22, #0x9ffd, lsl #32
   db2c0: 0f01e74b     	movi	v11.8b, #0x3a
   db2c4: 0f06e68c     	movi	v12.8b, #0xd4
   db2c8: f2cbfb8c     	movk	x12, #0x5fdc, lsl #32
   db2cc: f2f32e9b     	movk	x27, #0x9974, lsl #48
   db2d0: f2f0f533     	movk	x19, #0x87a9, lsl #48
   db2d4: f2f12815     	movk	x21, #0x8940, lsl #48
   db2d8: 9a890314     	csel	x20, x24, x9, eq
   db2dc: f2f3b237     	movk	x23, #0x9d91, lsl #48
   db2e0: f2f69636     	movk	x22, #0xb4b1, lsl #48
   db2e4: f2f32e8c     	movk	x12, #0x9974, lsl #48
   db2e8: aa0c03eb     	mov	x11, x12
   db2ec: d28411ac     	mov	x12, #0x208d
   db2f0: f2a8966c     	movk	x12, #0x44b3, lsl #16
   db2f4: eb18017f     	cmp	x11, x24
   db2f8: f2d733ec     	movk	x12, #0xb99f, lsl #32
   db2fc: f2e7de4c     	movk	x12, #0x3ef2, lsl #48
   db300: 54ffff40     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db304: d29bc10c     	mov	x12, #0xde08
   db308: aa0a03fc     	mov	x28, x10
   db30c: f2b9212c     	movk	x12, #0xc909, lsl #16
   db310: aa0903f9     	mov	x25, x9
   db314: f2c6686c     	movk	x12, #0x3343, lsl #32
   db318: 2a0803fa     	mov	w26, w8
   db31c: f2f4f48c     	movk	x12, #0xa7a4, lsl #48
   db320: eb13017f     	cmp	x11, x19
   db324: 54fffe20     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db328: eb15017f     	cmp	x11, x21
   db32c: 54002780     	b.eq	0xdb81c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x650>
   db330: 2a1a03e8     	mov	w8, w26
   db334: aa1903e9     	mov	x9, x25
   db338: aa1c03ea     	mov	x10, x28
   db33c: aa1403ec     	mov	x12, x20
   db340: eb1b017f     	cmp	x11, x27
   db344: 54fffd20     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db348: d28061cc     	mov	x12, #0x30e
   db34c: 2a1a03e8     	mov	w8, w26
   db350: f2a036ac     	movk	x12, #0x1b5, lsl #16
   db354: aa1903e9     	mov	x9, x25
   db358: f2d3dd2c     	movk	x12, #0x9ee9, lsl #32
   db35c: aa1c03ea     	mov	x10, x28
   db360: f2f9ee6c     	movk	x12, #0xcf73, lsl #48
   db364: eb17017f     	cmp	x11, x23
   db368: 54fffc00     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db36c: d28500ec     	mov	x12, #0x2807
   db370: 2a1a03e8     	mov	w8, w26
   db374: f2b939cc     	movk	x12, #0xc9ce, lsl #16
   db378: aa1903e9     	mov	x9, x25
   db37c: f2cb150c     	movk	x12, #0x58a8, lsl #32
   db380: aa1c03ea     	mov	x10, x28
   db384: f2e8672c     	movk	x12, #0x4339, lsl #48
   db388: eb16017f     	cmp	x11, x22
   db38c: 54fffae0     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db390: d2859d88     	mov	x8, #0x2cec
   db394: f2a362c8     	movk	x8, #0x1b16, lsl #16
   db398: f2d20608     	movk	x8, #0x9030, lsl #32
   db39c: f2f6d828     	movk	x8, #0xb6c1, lsl #48
   db3a0: eb08017f     	cmp	x11, x8
   db3a4: 54005000     	b.eq	0xdbda4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xbd8>
   db3a8: d2818b2c     	mov	x12, #0xc59
   db3ac: d296bfad     	mov	x13, #0xb5fd
   db3b0: f2a0d62c     	movk	x12, #0x6b1, lsl #16
   db3b4: f2abd9ad     	movk	x13, #0x5ecd, lsl #16
   db3b8: f2d59ccc     	movk	x12, #0xace6, lsl #32
   db3bc: 2a1a03e8     	mov	w8, w26
   db3c0: aa1903e9     	mov	x9, x25
   db3c4: aa1c03ea     	mov	x10, x28
   db3c8: f2e62d4c     	movk	x12, #0x316a, lsl #48
   db3cc: f2c21a8d     	movk	x13, #0x10d4, lsl #32
   db3d0: f2f82a0d     	movk	x13, #0xc150, lsl #48
   db3d4: eb0d017f     	cmp	x11, x13
   db3d8: 54fff880     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db3dc: d28381e8     	mov	x8, #0x1c0f
   db3e0: f2ad68e8     	movk	x8, #0x6b47, lsl #16
   db3e4: f2c96068     	movk	x8, #0x4b03, lsl #32
   db3e8: f2f837a8     	movk	x8, #0xc1bd, lsl #48
   db3ec: eb08017f     	cmp	x11, x8
   db3f0: 54003d60     	b.eq	0xdbb9c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x9d0>
   db3f4: d28500ec     	mov	x12, #0x2807
   db3f8: d2981e8d     	mov	x13, #0xc0f4
   db3fc: f2b939cc     	movk	x12, #0xc9ce, lsl #16
   db400: f2a0bf2d     	movk	x13, #0x5f9, lsl #16
   db404: f2cb150c     	movk	x12, #0x58a8, lsl #32
   db408: 2a1a03e8     	mov	w8, w26
   db40c: aa1903e9     	mov	x9, x25
   db410: aa1c03ea     	mov	x10, x28
   db414: f2e8672c     	movk	x12, #0x4339, lsl #48
   db418: f2cb684d     	movk	x13, #0x5b42, lsl #32
   db41c: f2f841cd     	movk	x13, #0xc20e, lsl #48
   db420: eb0d017f     	cmp	x11, x13
   db424: 54fff620     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db428: d29bf76c     	mov	x12, #0xdfbb
   db42c: d288ca8d     	mov	x13, #0x4654
   db430: f2bfa80c     	movk	x12, #0xfd40, lsl #16
   db434: f2ada08d     	movk	x13, #0x6d04, lsl #16
   db438: f2dd580c     	movk	x12, #0xeac0, lsl #32
   db43c: 2a1a03e8     	mov	w8, w26
   db440: aa1903e9     	mov	x9, x25
   db444: aa1c03ea     	mov	x10, x28
   db448: f2e3940c     	movk	x12, #0x1ca0, lsl #48
   db44c: f2d81a2d     	movk	x13, #0xc0d1, lsl #32
   db450: f2f9e18d     	movk	x13, #0xcf0c, lsl #48
   db454: eb0d017f     	cmp	x11, x13
   db458: 54fff480     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db45c: d28061c8     	mov	x8, #0x30e
   db460: f2a036a8     	movk	x8, #0x1b5, lsl #16
   db464: f2d3dd28     	movk	x8, #0x9ee9, lsl #32
   db468: f2f9ee68     	movk	x8, #0xcf73, lsl #48
   db46c: eb08017f     	cmp	x11, x8
   db470: 540047c0     	b.eq	0xdbd68 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xb9c>
   db474: d29e0728     	mov	x8, #0xf039
   db478: f2a866c8     	movk	x8, #0x4336, lsl #16
   db47c: f2df8c48     	movk	x8, #0xfc62, lsl #32
   db480: f2fa0f08     	movk	x8, #0xd078, lsl #48
   db484: eb08017f     	cmp	x11, x8
   db488: 54002540     	b.eq	0xdb930 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x764>
   db48c: d296160c     	mov	x12, #0xb0b0
   db490: d281bf6d     	mov	x13, #0xdfb
   db494: f2a9122c     	movk	x12, #0x4891, lsl #16
   db498: f2a52b0d     	movk	x13, #0x2958, lsl #16
   db49c: f2dafb0c     	movk	x12, #0xd7d8, lsl #32
   db4a0: 2a1a03e8     	mov	w8, w26
   db4a4: aa1903e9     	mov	x9, x25
   db4a8: aa1c03ea     	mov	x10, x28
   db4ac: f2e7beac     	movk	x12, #0x3df5, lsl #48
   db4b0: f2d3f0ed     	movk	x13, #0x9f87, lsl #32
   db4b4: f2fab6ad     	movk	x13, #0xd5b5, lsl #48
   db4b8: eb0d017f     	cmp	x11, x13
   db4bc: 54fff160     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db4c0: d2847f08     	mov	x8, #0x23f8
   db4c4: f2a9a448     	movk	x8, #0x4d22, lsl #16
   db4c8: f2ce0d48     	movk	x8, #0x706a, lsl #32
   db4cc: f2fc2088     	movk	x8, #0xe104, lsl #48
   db4d0: eb08017f     	cmp	x11, x8
   db4d4: 54002c20     	b.eq	0xdba58 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x88c>
   db4d8: d2829da8     	mov	x8, #0x14ed
   db4dc: f2a1da08     	movk	x8, #0xed0, lsl #16
   db4e0: f2c723c8     	movk	x8, #0x391e, lsl #32
   db4e4: f2ff58a8     	movk	x8, #0xfac5, lsl #48
   db4e8: eb08017f     	cmp	x11, x8
   db4ec: 54001f60     	b.eq	0xdb8d8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x70c>
   db4f0: d295f948     	mov	x8, #0xafca
   db4f4: f2af8348     	movk	x8, #0x7c1a, lsl #16
   db4f8: f2c3c728     	movk	x8, #0x1e39, lsl #32
   db4fc: f2e0de68     	movk	x8, #0x6f3, lsl #48
   db500: eb08017f     	cmp	x11, x8
   db504: 54002000     	b.eq	0xdb904 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x738>
   db508: d291254c     	mov	x12, #0x892a
   db50c: d29e47cd     	mov	x13, #0xf23e
   db510: f2beb12c     	movk	x12, #0xf589, lsl #16
   db514: f2bd738d     	movk	x13, #0xeb9c, lsl #16
   db518: f2ddc5ec     	movk	x12, #0xee2f, lsl #32
   db51c: 2a1a03e8     	mov	w8, w26
   db520: aa1903e9     	mov	x9, x25
   db524: aa1c03ea     	mov	x10, x28
   db528: f2e4980c     	movk	x12, #0x24c0, lsl #48
   db52c: f2cccfcd     	movk	x13, #0x667e, lsl #32
   db530: f2e0f90d     	movk	x13, #0x7c8, lsl #48
   db534: eb0d017f     	cmp	x11, x13
   db538: 54ffed80     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db53c: d28c98c8     	mov	x8, #0x64c6
   db540: f2b69be8     	movk	x8, #0xb4df, lsl #16
   db544: f2d950e8     	movk	x8, #0xca87, lsl #32
   db548: f2e2c588     	movk	x8, #0x162c, lsl #48
   db54c: eb08017f     	cmp	x11, x8
   db550: 54003de0     	b.eq	0xdbd0c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xb40>
   db554: d28fbe6d     	mov	x13, #0x7df3
   db558: 2a1a03e8     	mov	w8, w26
   db55c: f2b8100d     	movk	x13, #0xc080, lsl #16
   db560: aa1903e9     	mov	x9, x25
   db564: aa1c03ea     	mov	x10, x28
   db568: f2cb530d     	movk	x13, #0x5a98, lsl #32
   db56c: f2e2e08d     	movk	x13, #0x1704, lsl #48
   db570: eb0d017f     	cmp	x11, x13
   db574: 54ffeba0     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db578: d2804b28     	mov	x8, #0x259
   db57c: f2adc548     	movk	x8, #0x6e2a, lsl #16
   db580: f2d8d968     	movk	x8, #0xc6cb, lsl #32
   db584: f2e2edc8     	movk	x8, #0x176e, lsl #48
   db588: eb08017f     	cmp	x11, x8
   db58c: 54003180     	b.eq	0xdbbbc <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x9f0>
   db590: d28d8f68     	mov	x8, #0x6c7b
   db594: f2bb76c8     	movk	x8, #0xdbb6, lsl #16
   db598: f2c0c2a8     	movk	x8, #0x615, lsl #32
   db59c: f2e32088     	movk	x8, #0x1904, lsl #48
   db5a0: eb08017f     	cmp	x11, x8
   db5a4: 54001280     	b.eq	0xdb7f4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x628>
   db5a8: d29bf768     	mov	x8, #0xdfbb
   db5ac: f2bfa808     	movk	x8, #0xfd40, lsl #16
   db5b0: f2dd5808     	movk	x8, #0xeac0, lsl #32
   db5b4: f2e39408     	movk	x8, #0x1ca0, lsl #48
   db5b8: eb08017f     	cmp	x11, x8
   db5bc: 54001d40     	b.eq	0xdb964 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x798>
   db5c0: d2912548     	mov	x8, #0x892a
   db5c4: f2beb128     	movk	x8, #0xf589, lsl #16
   db5c8: f2ddc5e8     	movk	x8, #0xee2f, lsl #32
   db5cc: f2e49808     	movk	x8, #0x24c0, lsl #48
   db5d0: eb08017f     	cmp	x11, x8
   db5d4: 540037a0     	b.eq	0xdbcc8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xafc>
   db5d8: d29cd648     	mov	x8, #0xe6b2
   db5dc: f2b40348     	movk	x8, #0xa01a, lsl #16
   db5e0: f2c23748     	movk	x8, #0x11ba, lsl #32
   db5e4: f2e4da08     	movk	x8, #0x26d0, lsl #48
   db5e8: eb08017f     	cmp	x11, x8
   db5ec: 54003140     	b.eq	0xdbc14 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xa48>
   db5f0: d2844288     	mov	x8, #0x2214
   db5f4: f2adcd88     	movk	x8, #0x6e6c, lsl #16
   db5f8: f2c4e0a8     	movk	x8, #0x2705, lsl #32
   db5fc: f2e5d348     	movk	x8, #0x2e9a, lsl #48
   db600: eb08017f     	cmp	x11, x8
   db604: 54003420     	b.eq	0xdbc88 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xabc>
   db608: d28ffc08     	mov	x8, #0x7fe0
   db60c: f2b645a8     	movk	x8, #0xb22d, lsl #16
   db610: f2cd59a8     	movk	x8, #0x6acd, lsl #32
   db614: f2e5f728     	movk	x8, #0x2fb9, lsl #48
   db618: eb08017f     	cmp	x11, x8
   db61c: 540011e0     	b.eq	0xdb858 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x68c>
   db620: d2818b28     	mov	x8, #0xc59
   db624: f2a0d628     	movk	x8, #0x6b1, lsl #16
   db628: f2d59cc8     	movk	x8, #0xace6, lsl #32
   db62c: f2e62d48     	movk	x8, #0x316a, lsl #48
   db630: eb08017f     	cmp	x11, x8
   db634: 54002660     	b.eq	0xdbb00 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x934>
   db638: d289f428     	mov	x8, #0x4fa1
   db63c: f2a7f848     	movk	x8, #0x3fc2, lsl #16
   db640: f2c97328     	movk	x8, #0x4b99, lsl #32
   db644: f2e6cb88     	movk	x8, #0x365c, lsl #48
   db648: eb08017f     	cmp	x11, x8
   db64c: 54002ca0     	b.eq	0xdbbe0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xa14>
   db650: d28c98cc     	mov	x12, #0x64c6
   db654: d298d7ad     	mov	x13, #0xc6bd
   db658: f2b69bec     	movk	x12, #0xb4df, lsl #16
   db65c: f2bb4e2d     	movk	x13, #0xda71, lsl #16
   db660: f2d950ec     	movk	x12, #0xca87, lsl #32
   db664: b9403fe8     	ldr	w8, [sp, #0x3c]
   db668: aa1903e9     	mov	x9, x25
   db66c: aa1c03ea     	mov	x10, x28
   db670: f2e2c58c     	movk	x12, #0x162c, lsl #48
   db674: f2cc844d     	movk	x13, #0x6422, lsl #32
   db678: f2e761ad     	movk	x13, #0x3b0d, lsl #48
   db67c: eb0d017f     	cmp	x11, x13
   db680: 54ffe340     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db684: d2854ee8     	mov	x8, #0x2a77
   db688: f2be0f08     	movk	x8, #0xf078, lsl #16
   db68c: f2d04008     	movk	x8, #0x8200, lsl #32
   db690: f2e7aa88     	movk	x8, #0x3d54, lsl #48
   db694: eb08017f     	cmp	x11, x8
   db698: 54000fe0     	b.eq	0xdb894 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6c8>
   db69c: d2961608     	mov	x8, #0xb0b0
   db6a0: f2a91228     	movk	x8, #0x4891, lsl #16
   db6a4: f2dafb08     	movk	x8, #0xd7d8, lsl #32
   db6a8: f2e7bea8     	movk	x8, #0x3df5, lsl #48
   db6ac: eb08017f     	cmp	x11, x8
   db6b0: 54002460     	b.eq	0xdbb3c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x970>
   db6b4: d28411a8     	mov	x8, #0x208d
   db6b8: f2a89668     	movk	x8, #0x44b3, lsl #16
   db6bc: f2d733e8     	movk	x8, #0xb99f, lsl #32
   db6c0: f2e7de48     	movk	x8, #0x3ef2, lsl #48
   db6c4: eb08017f     	cmp	x11, x8
   db6c8: 540017c0     	b.eq	0xdb9c0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x7f4>
   db6cc: d28500e8     	mov	x8, #0x2807
   db6d0: f2b939c8     	movk	x8, #0xc9ce, lsl #16
   db6d4: f2cb1508     	movk	x8, #0x58a8, lsl #32
   db6d8: f2e86728     	movk	x8, #0x4339, lsl #48
   db6dc: eb08017f     	cmp	x11, x8
   db6e0: 540019c0     	b.eq	0xdba18 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x84c>
   db6e4: d28ffc0c     	mov	x12, #0x7fe0
   db6e8: d28bcbad     	mov	x13, #0x5e5d
   db6ec: f2b645ac     	movk	x12, #0xb22d, lsl #16
   db6f0: f2bcddcd     	movk	x13, #0xe6ee, lsl #16
   db6f4: f2cd59ac     	movk	x12, #0x6acd, lsl #32
   db6f8: 2a1a03e8     	mov	w8, w26
   db6fc: aa1903e9     	mov	x9, x25
   db700: aa1c03ea     	mov	x10, x28
   db704: f2e5f72c     	movk	x12, #0x2fb9, lsl #48
   db708: f2d9b34d     	movk	x13, #0xcd9a, lsl #32
   db70c: f2e8a1ed     	movk	x13, #0x450f, lsl #48
   db710: eb0d017f     	cmp	x11, x13
   db714: 54ffdea0     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db718: d2854eec     	mov	x12, #0x2a77
   db71c: d292678d     	mov	x13, #0x933c
   db720: f2be0f0c     	movk	x12, #0xf078, lsl #16
   db724: f2a8270d     	movk	x13, #0x4138, lsl #16
   db728: f2d0400c     	movk	x12, #0x8200, lsl #32
   db72c: 2a1a03e8     	mov	w8, w26
   db730: aa1903e9     	mov	x9, x25
   db734: aa1c03ea     	mov	x10, x28
   db738: f2e7aa8c     	movk	x12, #0x3d54, lsl #48
   db73c: f2d7710d     	movk	x13, #0xbb88, lsl #32
   db740: f2eb844d     	movk	x13, #0x5c22, lsl #48
   db744: eb0d017f     	cmp	x11, x13
   db748: 54ffdd00     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db74c: d284428c     	mov	x12, #0x2214
   db750: d289768d     	mov	x13, #0x4bb4
   db754: f2adcd8c     	movk	x12, #0x6e6c, lsl #16
   db758: f2a10eed     	movk	x13, #0x877, lsl #16
   db75c: f2c4e0ac     	movk	x12, #0x2705, lsl #32
   db760: 2a1a03e8     	mov	w8, w26
   db764: aa1903e9     	mov	x9, x25
   db768: aa1c03ea     	mov	x10, x28
   db76c: f2e5d34c     	movk	x12, #0x2e9a, lsl #48
   db770: f2cb2e8d     	movk	x13, #0x5974, lsl #32
   db774: f2ebdfed     	movk	x13, #0x5eff, lsl #48
   db778: eb0d017f     	cmp	x11, x13
   db77c: 54ffdb60     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db780: d28061cc     	mov	x12, #0x30e
   db784: d29ac5ad     	mov	x13, #0xd62d
   db788: a942a7ea     	ldp	x10, x9, [sp, #0x28]
   db78c: f2a036ac     	movk	x12, #0x1b5, lsl #16
   db790: f2b4e2ed     	movk	x13, #0xa717, lsl #16
   db794: f2d3dd2c     	movk	x12, #0x9ee9, lsl #32
   db798: 2a1a03e8     	mov	w8, w26
   db79c: f2f9ee6c     	movk	x12, #0xcf73, lsl #48
   db7a0: f2dad08d     	movk	x13, #0xd684, lsl #32
   db7a4: f2eebd4d     	movk	x13, #0x75ea, lsl #48
   db7a8: eb0d017f     	cmp	x11, x13
   db7ac: 54ffd9e0     	b.eq	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db7b0: d29ca4c8     	mov	x8, #0xe526
   db7b4: f2b8ee88     	movk	x8, #0xc774, lsl #16
   db7b8: f2d559e8     	movk	x8, #0xaacf, lsl #32
   db7bc: f2efb1e8     	movk	x8, #0x7d8f, lsl #48
   db7c0: eb08017f     	cmp	x11, x8
   db7c4: 540010e0     	b.eq	0xdb9e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x814>
   db7c8: d29bc10d     	mov	x13, #0xde08
   db7cc: 2a1a03e8     	mov	w8, w26
   db7d0: f2b9212d     	movk	x13, #0xc909, lsl #16
   db7d4: aa1903e9     	mov	x9, x25
   db7d8: aa1c03ea     	mov	x10, x28
   db7dc: aa0b03ec     	mov	x12, x11
   db7e0: f2c6686d     	movk	x13, #0x3343, lsl #32
   db7e4: f2f4f48d     	movk	x13, #0xa7a4, lsl #48
   db7e8: eb0d017f     	cmp	x11, x13
   db7ec: 54ffd7e1     	b.ne	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db7f0: 14000182     	b	0xdbdf8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xc2c>
   db7f4: d00003c8     	adrp	x8, 0x155000
   db7f8: d288ca89     	mov	x9, #0x4654
   db7fc: f2ada089     	movk	x9, #0x6d04, lsl #16
   db800: f2d81a29     	movk	x9, #0xc0d1, lsl #32
   db804: 39764908     	ldrb	w8, [x8, #0xd92]
   db808: f2f9e189     	movk	x9, #0xcf0c, lsl #48
   db80c: 7100011f     	cmp	w8, #0x0
   db810: 2a1a03e8     	mov	w8, w26
   db814: 9a95112c     	csel	x12, x9, x21, ne
   db818: 14000160     	b	0xdbd98 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xbcc>
   db81c: b00003cb     	adrp	x11, 0x154000
   db820: d29bf76c     	mov	x12, #0xdfbb
   db824: 5280002d     	mov	w13, #0x1
   db828: f2bfa80c     	movk	x12, #0xfd40, lsl #16
   db82c: f2dd580c     	movk	x12, #0xeac0, lsl #32
   db830: 2a1a03e8     	mov	w8, w26
   db834: fd444160     	ldr	d0, [x11, #0x880]
   db838: aa1903e9     	mov	x9, x25
   db83c: aa1c03ea     	mov	x10, x28
   db840: f2e3940c     	movk	x12, #0x1ca0, lsl #48
   db844: 2e2a1c00     	eor	v0.8b, v0.8b, v10.8b
   db848: fd044160     	str	d0, [x11, #0x880]
   db84c: d00003cb     	adrp	x11, 0x155000
   db850: 3936496d     	strb	w13, [x11, #0xd92]
   db854: 17fffea5     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db858: 1e604100     	fmov	d0, d8
   db85c: d503201f     	nop
   db860: 103d2968     	adr	x8, #0x7a52c
   db864: d503201f     	nop
   db868: 103c8140     	adr	x0, #0x79028
   db86c: 089ffd1f     	stlrb	wzr, [x8]
   db870: 94018801     	bl	0x13d874 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x626a8>
   db874: d2854eec     	mov	x12, #0x2a77
   db878: 2a1a03e8     	mov	w8, w26
   db87c: f2be0f0c     	movk	x12, #0xf078, lsl #16
   db880: aa1903e9     	mov	x9, x25
   db884: f2d0400c     	movk	x12, #0x8200, lsl #32
   db888: aa1c03ea     	mov	x10, x28
   db88c: f2e7aa8c     	movk	x12, #0x3d54, lsl #48
   db890: 17fffe96     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db894: 910123e0     	add	x0, sp, #0x48
   db898: 97fffc39     	bl	0xda97c <Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume+0x4cc>
   db89c: 2f00e400     	movi	d0, #0000000000000000
   db8a0: f9000be0     	str	x0, [sp, #0x10]
   db8a4: d10183a0     	sub	x0, x29, #0x60
   db8a8: b81a03bf     	stur	wzr, [x29, #-0x60]
   db8ac: 94018979     	bl	0x13de90 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x62cc4>
   db8b0: b85a03a8     	ldur	w8, [x29, #-0x60]
   db8b4: 1e604009     	fmov	d9, d0
   db8b8: b94027e9     	ldr	w9, [sp, #0x24]
   db8bc: 7100011f     	cmp	w8, #0x0
   db8c0: 1a9f07e8     	cset	w8, ne
   db8c4: 2a090108     	orr	w8, w8, w9
   db8c8: 7200011f     	tst	w8, #0x1
   db8cc: 2a1a03e8     	mov	w8, w26
   db8d0: 9a96126c     	csel	x12, x19, x22, ne
   db8d4: 14000131     	b	0xdbd98 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xbcc>
   db8d8: d00003c8     	adrp	x8, 0x155000
   db8dc: d2859d89     	mov	x9, #0x2cec
   db8e0: d28bcbaa     	mov	x10, #0x5e5d
   db8e4: f2a362c9     	movk	x9, #0x1b16, lsl #16
   db8e8: f2bcddca     	movk	x10, #0xe6ee, lsl #16
   db8ec: f2d20609     	movk	x9, #0x9030, lsl #32
   db8f0: 39764d08     	ldrb	w8, [x8, #0xd93]
   db8f4: f2d9b34a     	movk	x10, #0xcd9a, lsl #32
   db8f8: f2f6d829     	movk	x9, #0xb6c1, lsl #48
   db8fc: f2e8a1ea     	movk	x10, #0x450f, lsl #48
   db900: 14000016     	b	0xdb958 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x78c>
   db904: 91000729     	add	x9, x25, #0x1
   db908: 91000788     	add	x8, x28, #0x1
   db90c: d29ac5ac     	mov	x12, #0xd62d
   db910: aa1c03ea     	mov	x10, x28
   db914: f2b4e2ec     	movk	x12, #0xa717, lsl #16
   db918: f2dad08c     	movk	x12, #0xd684, lsl #32
   db91c: a902a7e8     	stp	x8, x9, [sp, #0x28]
   db920: 2a1a03e8     	mov	w8, w26
   db924: aa1903e9     	mov	x9, x25
   db928: f2eebd4c     	movk	x12, #0x75ea, lsl #48
   db92c: 17fffe6f     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db930: d00003c8     	adrp	x8, 0x155000
   db934: d29cd649     	mov	x9, #0xe6b2
   db938: d281bf6a     	mov	x10, #0xdfb
   db93c: f2b40349     	movk	x9, #0xa01a, lsl #16
   db940: f2a52b0a     	movk	x10, #0x2958, lsl #16
   db944: f2c23749     	movk	x9, #0x11ba, lsl #32
   db948: 39764508     	ldrb	w8, [x8, #0xd91]
   db94c: f2d3f0ea     	movk	x10, #0x9f87, lsl #32
   db950: f2e4da09     	movk	x9, #0x26d0, lsl #48
   db954: f2fab6aa     	movk	x10, #0xd5b5, lsl #48
   db958: 7100011f     	cmp	w8, #0x0
   db95c: 2a1a03e8     	mov	w8, w26
   db960: 14000016     	b	0xdb9b8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x7ec>
   db964: d503201f     	nop
   db968: 103d2108     	adr	x8, #0x7a420
   db96c: 089ffd1f     	stlrb	wzr, [x8]
   db970: 39400328     	ldrb	w8, [x25]
   db974: 39400389     	ldrb	w9, [x28]
   db978: 7100011f     	cmp	w8, #0x0
   db97c: 1a9f17ea     	cset	w10, eq
   db980: 6b09011f     	cmp	w8, w9
   db984: 1a9f07e9     	cset	w9, ne
   db988: 1a9f0548     	csinc	w8, w10, wzr, eq
   db98c: d298d7aa     	mov	x10, #0xc6bd
   db990: 7100011f     	cmp	w8, #0x0
   db994: f2bb4e2a     	movk	x10, #0xda71, lsl #16
   db998: 2a1a03e8     	mov	w8, w26
   db99c: b9003fe9     	str	w9, [sp, #0x3c]
   db9a0: d295f949     	mov	x9, #0xafca
   db9a4: f2af8349     	movk	x9, #0x7c1a, lsl #16
   db9a8: f2cc844a     	movk	x10, #0x6422, lsl #32
   db9ac: f2c3c729     	movk	x9, #0x1e39, lsl #32
   db9b0: f2e761aa     	movk	x10, #0x3b0d, lsl #48
   db9b4: f2e0de69     	movk	x9, #0x6f3, lsl #48
   db9b8: 9a89114c     	csel	x12, x10, x9, ne
   db9bc: 140000f7     	b	0xdbd98 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xbcc>
   db9c0: d284428c     	mov	x12, #0x2214
   db9c4: 2a1a03e8     	mov	w8, w26
   db9c8: f2adcd8c     	movk	x12, #0x6e6c, lsl #16
   db9cc: aa1903e9     	mov	x9, x25
   db9d0: f2c4e0ac     	movk	x12, #0x2705, lsl #32
   db9d4: aa1c03ea     	mov	x10, x28
   db9d8: f2e5d34c     	movk	x12, #0x2e9a, lsl #48
   db9dc: 17fffe43     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   db9e0: d00003c8     	adrp	x8, 0x155000
   db9e4: d296bfa9     	mov	x9, #0xb5fd
   db9e8: d2847f0a     	mov	x10, #0x23f8
   db9ec: f2abd9a9     	movk	x9, #0x5ecd, lsl #16
   db9f0: f2a9a44a     	movk	x10, #0x4d22, lsl #16
   db9f4: f2c21a89     	movk	x9, #0x10d4, lsl #32
   db9f8: 39765108     	ldrb	w8, [x8, #0xd94]
   db9fc: f2ce0d4a     	movk	x10, #0x706a, lsl #32
   dba00: f2f82a09     	movk	x9, #0xc150, lsl #48
   dba04: f2fc208a     	movk	x10, #0xe104, lsl #48
   dba08: 7100011f     	cmp	w8, #0x0
   dba0c: 2a1a03e8     	mov	w8, w26
   dba10: 9a8a112c     	csel	x12, x9, x10, ne
   dba14: 140000e1     	b	0xdbd98 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xbcc>
   dba18: 2a1f03e0     	mov	w0, wzr
   dba1c: 52800021     	mov	w1, #0x1
   dba20: d503201f     	nop
   dba24: 103d1b62     	adr	x2, #0x7a36c
   dba28: 9401b26e     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   dba2c: d2981e89     	mov	x9, #0xc0f4
   dba30: d29ca4ca     	mov	x10, #0xe526
   dba34: f2a0bf29     	movk	x9, #0x5f9, lsl #16
   dba38: f2b8ee8a     	movk	x10, #0xc774, lsl #16
   dba3c: f2cb6849     	movk	x9, #0x5b42, lsl #32
   dba40: f2d559ea     	movk	x10, #0xaacf, lsl #32
   dba44: 2a1a03e8     	mov	w8, w26
   dba48: f2f841c9     	movk	x9, #0xc20e, lsl #48
   dba4c: f2efb1ea     	movk	x10, #0x7d8f, lsl #48
   dba50: 7100001f     	cmp	w0, #0x0
   dba54: 14000050     	b	0xdbb94 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x9c8>
   dba58: d503201f     	nop
   dba5c: 103c732d     	adr	x13, #0x78e64
   dba60: 5280074c     	mov	w12, #0x3a
   dba64: 4f01e741     	movi	v1.16b, #0x3a
   dba68: 394061a8     	ldrb	w8, [x13, #0x18]
   dba6c: 394065a9     	ldrb	w9, [x13, #0x19]
   dba70: 394069aa     	ldrb	w10, [x13, #0x1a]
   dba74: 4a0c0108     	eor	w8, w8, w12
   dba78: 39406dab     	ldrb	w11, [x13, #0x1b]
   dba7c: 4a0c0129     	eor	w9, w9, w12
   dba80: 3dc001a0     	ldr	q0, [x13]
   dba84: 390061a8     	strb	w8, [x13, #0x18]
   dba88: 4a0c0148     	eor	w8, w10, w12
   dba8c: 4a0c016a     	eor	w10, w11, w12
   dba90: 390065a9     	strb	w9, [x13, #0x19]
   dba94: 394071a9     	ldrb	w9, [x13, #0x1c]
   dba98: 5280002b     	mov	w11, #0x1
   dba9c: 390069a8     	strb	w8, [x13, #0x1a]
   dbaa0: 394075a8     	ldrb	w8, [x13, #0x1d]
   dbaa4: 39006daa     	strb	w10, [x13, #0x1b]
   dbaa8: 394079aa     	ldrb	w10, [x13, #0x1e]
   dbaac: 6e211c00     	eor	v0.16b, v0.16b, v1.16b
   dbab0: 4a0c0129     	eor	w9, w9, w12
   dbab4: 3d8001a0     	str	q0, [x13]
   dbab8: fd4009a0     	ldr	d0, [x13, #0x10]
   dbabc: 4a0c0108     	eor	w8, w8, w12
   dbac0: 4a0c014a     	eor	w10, w10, w12
   dbac4: 390071a9     	strb	w9, [x13, #0x1c]
   dbac8: d2818b2c     	mov	x12, #0xc59
   dbacc: 2e2b1c00     	eor	v0.8b, v0.8b, v11.8b
   dbad0: f2a0d62c     	movk	x12, #0x6b1, lsl #16
   dbad4: 390075a8     	strb	w8, [x13, #0x1d]
   dbad8: f2d59ccc     	movk	x12, #0xace6, lsl #32
   dbadc: 390079aa     	strb	w10, [x13, #0x1e]
   dbae0: 2a1a03e8     	mov	w8, w26
   dbae4: fd0009a0     	str	d0, [x13, #0x10]
   dbae8: d00003cd     	adrp	x13, 0x155000
   dbaec: aa1903e9     	mov	x9, x25
   dbaf0: aa1c03ea     	mov	x10, x28
   dbaf4: f2e62d4c     	movk	x12, #0x316a, lsl #48
   dbaf8: 393651ab     	strb	w11, [x13, #0xd94]
   dbafc: 17fffdfb     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   dbb00: 1e604120     	fmov	d0, d9
   dbb04: d503201f     	nop
   dbb08: 103d1448     	adr	x8, #0x7a288
   dbb0c: d503201f     	nop
   dbb10: 103c6d80     	adr	x0, #0x78db0
   dbb14: 089ffd1f     	stlrb	wzr, [x8]
   dbb18: 94018757     	bl	0x13d874 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x626a8>
   dbb1c: d29bc10c     	mov	x12, #0xde08
   dbb20: 2a1a03e8     	mov	w8, w26
   dbb24: f2b9212c     	movk	x12, #0xc909, lsl #16
   dbb28: aa1903e9     	mov	x9, x25
   dbb2c: f2c6686c     	movk	x12, #0x3343, lsl #32
   dbb30: aa1c03ea     	mov	x10, x28
   dbb34: f2f4f48c     	movk	x12, #0xa7a4, lsl #48
   dbb38: 17fffdec     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   dbb3c: d503201f     	nop
   dbb40: 103d1228     	adr	x8, #0x7a244
   dbb44: d10183a0     	sub	x0, x29, #0x60
   dbb48: 910103e4     	add	x4, sp, #0x40
   dbb4c: d503201f     	nop
   dbb50: 103c6903     	adr	x3, #0x78d20
   dbb54: 089ffd1f     	stlrb	wzr, [x8]
   dbb58: f85b03a2     	ldur	x2, [x29, #-0x50]
   dbb5c: f90023ff     	str	xzr, [sp, #0x40]
   dbb60: f9400fe1     	ldr	x1, [sp, #0x18]
   dbb64: 97ff7e79     	bl	0xbb548 <.text+0xb2968>
   dbb68: b85a03a8     	ldur	w8, [x29, #-0x60]
   dbb6c: d28381e9     	mov	x9, #0x1c0f
   dbb70: d289f42a     	mov	x10, #0x4fa1
   dbb74: f2ad68e9     	movk	x9, #0x6b47, lsl #16
   dbb78: f2a7f84a     	movk	x10, #0x3fc2, lsl #16
   dbb7c: f2c96069     	movk	x9, #0x4b03, lsl #32
   dbb80: f2c9732a     	movk	x10, #0x4b99, lsl #32
   dbb84: 7100011f     	cmp	w8, #0x0
   dbb88: 2a1a03e8     	mov	w8, w26
   dbb8c: f2f837a9     	movk	x9, #0xc1bd, lsl #48
   dbb90: f2e6cb8a     	movk	x10, #0x365c, lsl #48
   dbb94: 9a89014c     	csel	x12, x10, x9, eq
   dbb98: 14000080     	b	0xdbd98 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xbcc>
   dbb9c: d28c98cc     	mov	x12, #0x64c6
   dbba0: 52800028     	mov	w8, #0x1
   dbba4: f2b69bec     	movk	x12, #0xb4df, lsl #16
   dbba8: aa1903e9     	mov	x9, x25
   dbbac: f2d950ec     	movk	x12, #0xca87, lsl #32
   dbbb0: aa1c03ea     	mov	x10, x28
   dbbb4: f2e2c58c     	movk	x12, #0x162c, lsl #48
   dbbb8: 17fffdcc     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   dbbbc: d28411ac     	mov	x12, #0x208d
   dbbc0: 2a1a03e8     	mov	w8, w26
   dbbc4: f2a8966c     	movk	x12, #0x44b3, lsl #16
   dbbc8: aa1903e9     	mov	x9, x25
   dbbcc: f2d733ec     	movk	x12, #0xb99f, lsl #32
   dbbd0: aa1c03ea     	mov	x10, x28
   dbbd4: f2e7de4c     	movk	x12, #0x3ef2, lsl #48
   dbbd8: b81a03bf     	stur	wzr, [x29, #-0x60]
   dbbdc: 17fffdc3     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   dbbe0: f94023e8     	ldr	x8, [sp, #0x40]
   dbbe4: d503201f     	nop
   dbbe8: 103c64cb     	adr	x11, #0x78c98
   dbbec: d29ac5ac     	mov	x12, #0xd62d
   dbbf0: f2b4e2ec     	movk	x12, #0xa717, lsl #16
   dbbf4: aa1903e9     	mov	x9, x25
   dbbf8: f2dad08c     	movk	x12, #0xd684, lsl #32
   dbbfc: f9001be8     	str	x8, [sp, #0x30]
   dbc00: 2a1a03e8     	mov	w8, w26
   dbc04: aa1c03ea     	mov	x10, x28
   dbc08: f90017eb     	str	x11, [sp, #0x28]
   dbc0c: f2eebd4c     	movk	x12, #0x75ea, lsl #48
   dbc10: 17fffdb6     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   dbc14: d503201f     	nop
   dbc18: 103c62cd     	adr	x13, #0x78c58
   dbc1c: 52801a8c     	mov	w12, #0xd4
   dbc20: 394021a8     	ldrb	w8, [x13, #0x8]
   dbc24: 394025a9     	ldrb	w9, [x13, #0x9]
   dbc28: 394029aa     	ldrb	w10, [x13, #0xa]
   dbc2c: 4a0c0108     	eor	w8, w8, w12
   dbc30: 39402dab     	ldrb	w11, [x13, #0xb]
   dbc34: fd4001a0     	ldr	d0, [x13]
   dbc38: 4a0c0129     	eor	w9, w9, w12
   dbc3c: 390021a8     	strb	w8, [x13, #0x8]
   dbc40: 4a0c0148     	eor	w8, w10, w12
   dbc44: 4a0c016a     	eor	w10, w11, w12
   dbc48: 2e2c1c00     	eor	v0.8b, v0.8b, v12.8b
   dbc4c: 390025a9     	strb	w9, [x13, #0x9]
   dbc50: d296160c     	mov	x12, #0xb0b0
   dbc54: 390029a8     	strb	w8, [x13, #0xa]
   dbc58: 5280002b     	mov	w11, #0x1
   dbc5c: 39002daa     	strb	w10, [x13, #0xb]
   dbc60: f2a9122c     	movk	x12, #0x4891, lsl #16
   dbc64: fd0001a0     	str	d0, [x13]
   dbc68: d00003cd     	adrp	x13, 0x155000
   dbc6c: f2dafb0c     	movk	x12, #0xd7d8, lsl #32
   dbc70: 2a1a03e8     	mov	w8, w26
   dbc74: aa1903e9     	mov	x9, x25
   dbc78: aa1c03ea     	mov	x10, x28
   dbc7c: f2e7beac     	movk	x12, #0x3df5, lsl #48
   dbc80: 393645ab     	strb	w11, [x13, #0xd91]
   dbc84: 17fffd99     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   dbc88: 2a1f03e0     	mov	w0, wzr
   dbc8c: 52800021     	mov	w1, #0x1
   dbc90: d503201f     	nop
   dbc94: 103d0782     	adr	x2, #0x7a0f0
   dbc98: 9401b1d2     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   dbc9c: d29e0729     	mov	x9, #0xf039
   dbca0: d289768a     	mov	x10, #0x4bb4
   dbca4: f2a866c9     	movk	x9, #0x4336, lsl #16
   dbca8: f2a10eea     	movk	x10, #0x877, lsl #16
   dbcac: f2df8c49     	movk	x9, #0xfc62, lsl #32
   dbcb0: f2cb2e8a     	movk	x10, #0x5974, lsl #32
   dbcb4: 2a1a03e8     	mov	w8, w26
   dbcb8: f2fa0f09     	movk	x9, #0xd078, lsl #48
   dbcbc: f2ebdfea     	movk	x10, #0x5eff, lsl #48
   dbcc0: 7100001f     	cmp	w0, #0x0
   dbcc4: 14000010     	b	0xdbd04 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xb38>
   dbcc8: 2a1f03e0     	mov	w0, wzr
   dbccc: 52800021     	mov	w1, #0x1
   dbcd0: d503201f     	nop
   dbcd4: 103d05c2     	adr	x2, #0x7a0b8
   dbcd8: 9401b1c2     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   dbcdc: d2829da9     	mov	x9, #0x14ed
   dbce0: d28fbe6a     	mov	x10, #0x7df3
   dbce4: f2a1da09     	movk	x9, #0xed0, lsl #16
   dbce8: f2b8100a     	movk	x10, #0xc080, lsl #16
   dbcec: f2c723c9     	movk	x9, #0x391e, lsl #32
   dbcf0: f2cb530a     	movk	x10, #0x5a98, lsl #32
   dbcf4: 2a1a03e8     	mov	w8, w26
   dbcf8: 7100001f     	cmp	w0, #0x0
   dbcfc: f2ff58a9     	movk	x9, #0xfac5, lsl #48
   dbd00: f2e2e08a     	movk	x10, #0x1704, lsl #48
   dbd04: 9a8a012c     	csel	x12, x9, x10, eq
   dbd08: 14000024     	b	0xdbd98 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xbcc>
   dbd0c: 2f00e400     	movi	d0, #0000000000000000
   dbd10: d10183a0     	sub	x0, x29, #0x60
   dbd14: 9401885f     	bl	0x13de90 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x62cc4>
   dbd18: b85a03a8     	ldur	w8, [x29, #-0x60]
   dbd1c: d29e47ca     	mov	x10, #0xf23e
   dbd20: d292678b     	mov	x11, #0x933c
   dbd24: f2bd738a     	movk	x10, #0xeb9c, lsl #16
   dbd28: f2a8270b     	movk	x11, #0x4138, lsl #16
   dbd2c: f2cccfca     	movk	x10, #0x667e, lsl #32
   dbd30: 7100011f     	cmp	w8, #0x0
   dbd34: f2d7710b     	movk	x11, #0xbb88, lsl #32
   dbd38: 1a9f07e8     	cset	w8, ne
   dbd3c: f2e0f90a     	movk	x10, #0x7c8, lsl #48
   dbd40: 2a1a0109     	orr	w9, w8, w26
   dbd44: f2eb844b     	movk	x11, #0x5c22, lsl #48
   dbd48: 7200013f     	tst	w9, #0x1
   dbd4c: 1e604008     	fmov	d8, d0
   dbd50: 2a1a03e8     	mov	w8, w26
   dbd54: aa1903e9     	mov	x9, x25
   dbd58: 9a8a116c     	csel	x12, x11, x10, ne
   dbd5c: aa1c03ea     	mov	x10, x28
   dbd60: b90027fa     	str	w26, [sp, #0x24]
   dbd64: 17fffd61     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   dbd68: 2a1f03e0     	mov	w0, wzr
   dbd6c: 52800021     	mov	w1, #0x1
   dbd70: d503201f     	nop
   dbd74: 103d00a2     	adr	x2, #0x7a014
   dbd78: 9401b19a     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   dbd7c: d28d8f69     	mov	x9, #0x6c7b
   dbd80: 7100001f     	cmp	w0, #0x0
   dbd84: f2bb76c9     	movk	x9, #0xdbb6, lsl #16
   dbd88: 2a1a03e8     	mov	w8, w26
   dbd8c: f2c0c2a9     	movk	x9, #0x615, lsl #32
   dbd90: f2e32089     	movk	x9, #0x1904, lsl #48
   dbd94: 9a97012c     	csel	x12, x9, x23, eq
   dbd98: aa1903e9     	mov	x9, x25
   dbd9c: aa1c03ea     	mov	x10, x28
   dbda0: 17fffd52     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   dbda4: d503201f     	nop
   dbda8: 103c574d     	adr	x13, #0x78ae8
   dbdac: 4f00e5c2     	movi	v2.16b, #0xe
   dbdb0: d28ffc0c     	mov	x12, #0x7fe0
   dbdb4: f2b645ac     	movk	x12, #0xb22d, lsl #16
   dbdb8: 2a1a03e8     	mov	w8, w26
   dbdbc: ad4005a0     	ldp	q0, q1, [x13]
   dbdc0: f2cd59ac     	movk	x12, #0x6acd, lsl #32
   dbdc4: aa1903e9     	mov	x9, x25
   dbdc8: aa1c03ea     	mov	x10, x28
   dbdcc: f2e5f72c     	movk	x12, #0x2fb9, lsl #48
   dbdd0: 6e221c00     	eor	v0.16b, v0.16b, v2.16b
   dbdd4: 394081ab     	ldrb	w11, [x13, #0x20]
   dbdd8: 6e221c21     	eor	v1.16b, v1.16b, v2.16b
   dbddc: ad0005a0     	stp	q0, q1, [x13]
   dbde0: 521f096b     	eor	w11, w11, #0xe
   dbde4: 390081ab     	strb	w11, [x13, #0x20]
   dbde8: 5280002b     	mov	w11, #0x1
   dbdec: d00003cd     	adrp	x13, 0x155000
   dbdf0: 39364dab     	strb	w11, [x13, #0xd93]
   dbdf4: 17fffd3d     	b	0xdb2e8 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x11c>
   dbdf8: f94007e8     	ldr	x8, [sp, #0x8]
   dbdfc: f9401508     	ldr	x8, [x8, #0x28]
   dbe00: f85c03a9     	ldur	x9, [x29, #-0x40]
   dbe04: eb09011f     	cmp	x8, x9
   dbe08: 540001a1     	b.ne	0xdbe3c <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0xc70>
   dbe0c: a9524ff4     	ldp	x20, x19, [sp, #0x120]
   dbe10: a95157f6     	ldp	x22, x21, [sp, #0x110]
   dbe14: a9505ff8     	ldp	x24, x23, [sp, #0x100]
   dbe18: a94f67fa     	ldp	x26, x25, [sp, #0xf0]
   dbe1c: a94e6ffc     	ldp	x28, x27, [sp, #0xe0]
   dbe20: a94d7bfd     	ldp	x29, x30, [sp, #0xd0]
   dbe24: 6d4c23e9     	ldp	d9, d8, [sp, #0xc0]
   dbe28: 6d4b2beb     	ldp	d11, d10, [sp, #0xb0]
   dbe2c: f9400be0     	ldr	x0, [sp, #0x10]
   dbe30: fd4053ec     	ldr	d12, [sp, #0xa0]
   dbe34: 9104c3ff     	add	sp, sp, #0x130
   dbe38: d65f03c0     	ret
   dbe3c: 9401b2f5     	bl	0x148a10 <__stack_chk_fail@plt>
