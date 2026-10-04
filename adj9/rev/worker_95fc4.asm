
extracted/arm64/lib/arm64-v8a/libsigner.so:	file format elf64-littleaarch64

Disassembly of section .text:

0000000000008be0 <.text>:
   95fc4: d10203ff     	sub	sp, sp, #0x80
   95fc8: a9027bfd     	stp	x29, x30, [sp, #0x20]
   95fcc: a9036ffc     	stp	x28, x27, [sp, #0x30]
   95fd0: a90467fa     	stp	x26, x25, [sp, #0x40]
   95fd4: a9055ff8     	stp	x24, x23, [sp, #0x50]
   95fd8: a90657f6     	stp	x22, x21, [sp, #0x60]
   95fdc: a9074ff4     	stp	x20, x19, [sp, #0x70]
   95fe0: 910083fd     	add	x29, sp, #0x20
   95fe4: d294e95c     	mov	x28, #0xa74a
   95fe8: d28bb5db     	mov	x27, #0x5dae
   95fec: f2abd47c     	movk	x28, #0x5ea3, lsl #16
   95ff0: f2b7addb     	movk	x27, #0xbd6e, lsl #16
   95ff4: d296f999     	mov	x25, #0xb7cc
   95ff8: d29be955     	mov	x21, #0xdf4a
   95ffc: d295f6ba     	mov	x26, #0xafb5
   96000: d29866b7     	mov	x23, #0xc335
   96004: d285f393     	mov	x19, #0x2f9c
   96008: d29343f6     	mov	x22, #0x9a1f
   9600c: d29a5a38     	mov	x24, #0xd2d1
   96010: d291d029     	mov	x9, #0x8e81
   96014: f2d409fc     	movk	x28, #0xa04f, lsl #32
   96018: f2cd555b     	movk	x27, #0x6aaa, lsl #32
   9601c: f2bfec99     	movk	x25, #0xff64, lsl #16
   96020: f2b7b915     	movk	x21, #0xbdc8, lsl #16
   96024: f2b4257a     	movk	x26, #0xa12b, lsl #16
   96028: f2a29097     	movk	x23, #0x1484, lsl #16
   9602c: f2b872d3     	movk	x19, #0xc396, lsl #16
   96030: f2bad4b6     	movk	x22, #0xd6a5, lsl #16
   96034: f2bf04b8     	movk	x24, #0xf825, lsl #16
   96038: f2bc2a89     	movk	x9, #0xe154, lsl #16
   9603c: 7100681f     	cmp	w0, #0x1a
   96040: f2ff43dc     	movk	x28, #0xfa1e, lsl #48
   96044: f2e51e1b     	movk	x27, #0x28f0, lsl #48
   96048: f2de47d9     	movk	x25, #0xf23e, lsl #32
   9604c: f2c19d75     	movk	x21, #0xceb, lsl #32
   96050: f2d9d27a     	movk	x26, #0xce93, lsl #32
   96054: f2c2d677     	movk	x23, #0x16b3, lsl #32
   96058: f2cbd1f3     	movk	x19, #0x5e8f, lsl #32
   9605c: f2d910b6     	movk	x22, #0xc885, lsl #32
   96060: f2ddc198     	movk	x24, #0xee0c, lsl #32
   96064: f2c76bc9     	movk	x9, #0x3b5e, lsl #32
   96068: aa0103f4     	mov	x20, x1
   9606c: 9a9cb368     	csel	x8, x27, x28, lt
   96070: f2f1e7b9     	movk	x25, #0x8f3d, lsl #48
   96074: f2f91ab5     	movk	x21, #0xc8d5, lsl #48
   96078: f2f644ba     	movk	x26, #0xb225, lsl #48
   9607c: f2f67997     	movk	x23, #0xb3cc, lsl #48
   96080: f2fe59b3     	movk	x19, #0xf2cd, lsl #48
   96084: f2fec236     	movk	x22, #0xf611, lsl #48
   96088: f2eb8478     	movk	x24, #0x5c23, lsl #48
   9608c: f2ef98a9     	movk	x9, #0x7cc5, lsl #48
   96090: f9000be2     	str	x2, [sp, #0x10]
   96094: b9000fe0     	str	w0, [sp, #0xc]
   96098: f81f83a8     	stur	x8, [x29, #-0x8]
   9609c: eb19013f     	cmp	x9, x25
   960a0: 54000660     	b.eq	0x9616c <.text+0x8d58c>
   960a4: aa0903e8     	mov	x8, x9
   960a8: eb1a013f     	cmp	x9, x26
   960ac: 540007a0     	b.eq	0x961a0 <.text+0x8d5c0>
   960b0: d28ea2a9     	mov	x9, #0x7515
   960b4: eb17011f     	cmp	x8, x23
   960b8: f2b642e9     	movk	x9, #0xb217, lsl #16
   960bc: fa551104     	ccmp	x8, x21, #0x4, ne
   960c0: f2dbf909     	movk	x9, #0xdfc8, lsl #32
   960c4: f2eed149     	movk	x9, #0x768a, lsl #48
   960c8: 54fffea0     	b.eq	0x9609c <.text+0x8d4bc>
   960cc: eb13011f     	cmp	x8, x19
   960d0: 54000780     	b.eq	0x961c0 <.text+0x8d5e0>
   960d4: eb16011f     	cmp	x8, x22
   960d8: 540008c0     	b.eq	0x961f0 <.text+0x8d610>
   960dc: eb1c011f     	cmp	x8, x28
   960e0: 540009a0     	b.eq	0x96214 <.text+0x8d634>
   960e4: d2851989     	mov	x9, #0x28cc
   960e8: eb1b011f     	cmp	x8, x27
   960ec: f2b87c49     	movk	x9, #0xc3e2, lsl #16
   960f0: fa581104     	ccmp	x8, x24, #0x4, ne
   960f4: f2cf0329     	movk	x9, #0x7819, lsl #32
   960f8: f2ed70a9     	movk	x9, #0x6b85, lsl #48
   960fc: 54fffd00     	b.eq	0x9609c <.text+0x8d4bc>
   96100: d286b029     	mov	x9, #0x3581
   96104: f2b79749     	movk	x9, #0xbcba, lsl #16
   96108: f2c02669     	movk	x9, #0x133, lsl #32
   9610c: f2eec3e9     	movk	x9, #0x761f, lsl #48
   96110: eb09011f     	cmp	x8, x9
   96114: 54000900     	b.eq	0x96234 <.text+0x8d654>
   96118: d28ea2a9     	mov	x9, #0x7515
   9611c: f2b642e9     	movk	x9, #0xb217, lsl #16
   96120: f2dbf909     	movk	x9, #0xdfc8, lsl #32
   96124: f2eed149     	movk	x9, #0x768a, lsl #48
   96128: eb09011f     	cmp	x8, x9
   9612c: 54000980     	b.eq	0x9625c <.text+0x8d67c>
   96130: d291d02a     	mov	x10, #0x8e81
   96134: f85f83a9     	ldur	x9, [x29, #-0x8]
   96138: f2bc2a8a     	movk	x10, #0xe154, lsl #16
   9613c: f2c76bca     	movk	x10, #0x3b5e, lsl #32
   96140: f2ef98aa     	movk	x10, #0x7cc5, lsl #48
   96144: eb0a011f     	cmp	x8, x10
   96148: 54fffaa0     	b.eq	0x9609c <.text+0x8d4bc>
   9614c: d285198a     	mov	x10, #0x28cc
   96150: aa0803e9     	mov	x9, x8
   96154: f2b87c4a     	movk	x10, #0xc3e2, lsl #16
   96158: f2cf032a     	movk	x10, #0x7819, lsl #32
   9615c: f2ed70aa     	movk	x10, #0x6b85, lsl #48
   96160: eb0a011f     	cmp	x8, x10
   96164: 54fff9c1     	b.ne	0x9609c <.text+0x8d4bc>
   96168: 14000049     	b	0x9628c <.text+0x8d6ac>
   9616c: f9400288     	ldr	x8, [x20]
   96170: aa1403e0     	mov	x0, x20
   96174: f00005e1     	adrp	x1, 0x155000
   96178: 912aa021     	add	x1, x1, #0xaa8
   9617c: f9436d08     	ldr	x8, [x8, #0x6d8]
   96180: d63f0100     	blr	x8
   96184: d286b028     	mov	x8, #0x3581
   96188: 7100001f     	cmp	w0, #0x0
   9618c: f2b79748     	movk	x8, #0xbcba, lsl #16
   96190: f2c02668     	movk	x8, #0x133, lsl #32
   96194: f2eec3e8     	movk	x8, #0x761f, lsl #48
   96198: 9a950109     	csel	x9, x8, x21, eq
   9619c: 17ffffc0     	b	0x9609c <.text+0x8d4bc>
   961a0: f00005e8     	adrp	x8, 0x155000
   961a4: f9455900     	ldr	x0, [x8, #0xab0]
   961a8: 9402ca42     	bl	0x148ab0 <pthread_detach@plt>
   961ac: d2851989     	mov	x9, #0x28cc
   961b0: f2b87c49     	movk	x9, #0xc3e2, lsl #16
   961b4: f2cf0329     	movk	x9, #0x7819, lsl #32
   961b8: f2ed70a9     	movk	x9, #0x6b85, lsl #48
   961bc: 17ffffb8     	b	0x9609c <.text+0x8d4bc>
   961c0: f00005e8     	adrp	x8, 0x155000
   961c4: 912a7108     	add	x8, x8, #0xa9c
   961c8: 5280004a     	mov	w10, #0x2
   961cc: d2851989     	mov	x9, #0x28cc
   961d0: f2b87c49     	movk	x9, #0xc3e2, lsl #16
   961d4: f2cf0329     	movk	x9, #0x7819, lsl #32
   961d8: 889ffd0a     	stlr	w10, [x8]
   961dc: 5280058a     	mov	w10, #0x2c
   961e0: f9400be8     	ldr	x8, [sp, #0x10]
   961e4: f2ed70a9     	movk	x9, #0x6b85, lsl #48
   961e8: b900010a     	str	w10, [x8]
   961ec: 17ffffac     	b	0x9609c <.text+0x8d4bc>
   961f0: b9400fe8     	ldr	w8, [sp, #0xc]
   961f4: f00005e9     	adrp	x9, 0x155000
   961f8: aa1403e0     	mov	x0, x20
   961fc: aa1f03e1     	mov	x1, xzr
   96200: b90aa128     	str	w8, [x9, #0xaa0]
   96204: 94001368     	bl	0x9afa4 <.text+0x923c4>
   96208: 7200001f     	tst	w0, #0x1
   9620c: 9a9912e9     	csel	x9, x23, x25, ne
   96210: 17ffffa3     	b	0x9609c <.text+0x8d4bc>
   96214: 2a1f03e0     	mov	w0, wzr
   96218: 52800021     	mov	w1, #0x1
   9621c: f00005e2     	adrp	x2, 0x155000
   96220: 912a7042     	add	x2, x2, #0xa9c
   96224: 9402c9d7     	bl	0x148980 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d7b4>
   96228: 7100001f     	cmp	w0, #0x0
   9622c: 9a9802c9     	csel	x9, x22, x24, eq
   96230: 17ffff9b     	b	0x9609c <.text+0x8d4bc>
   96234: f00005e0     	adrp	x0, 0x155000
   96238: 912ac000     	add	x0, x0, #0xab0
   9623c: aa1f03e1     	mov	x1, xzr
   96240: d503201f     	nop
   96244: 10000342     	adr	x2, #0x68
   96248: aa1f03e3     	mov	x3, xzr
   9624c: 9402ca1d     	bl	0x148ac0 <pthread_create@plt>
   96250: 7100001f     	cmp	w0, #0x0
   96254: 9a930349     	csel	x9, x26, x19, eq
   96258: 17ffff91     	b	0x9609c <.text+0x8d4bc>
   9625c: f00005e8     	adrp	x8, 0x155000
   96260: 912a7108     	add	x8, x8, #0xa9c
   96264: 5280004a     	mov	w10, #0x2
   96268: d2851989     	mov	x9, #0x28cc
   9626c: f2b87c49     	movk	x9, #0xc3e2, lsl #16
   96270: f2cf0329     	movk	x9, #0x7819, lsl #32
   96274: 889ffd0a     	stlr	w10, [x8]
   96278: 5280038a     	mov	w10, #0x1c
   9627c: f9400be8     	ldr	x8, [sp, #0x10]
   96280: f2ed70a9     	movk	x9, #0x6b85, lsl #48
   96284: b900010a     	str	w10, [x8]
   96288: 17ffff85     	b	0x9609c <.text+0x8d4bc>
   9628c: a9474ff4     	ldp	x20, x19, [sp, #0x70]
   96290: a94657f6     	ldp	x22, x21, [sp, #0x60]
   96294: a9455ff8     	ldp	x24, x23, [sp, #0x50]
   96298: a94467fa     	ldp	x26, x25, [sp, #0x40]
   9629c: a9436ffc     	ldp	x28, x27, [sp, #0x30]
   962a0: a9427bfd     	ldp	x29, x30, [sp, #0x20]
   962a4: 910203ff     	add	sp, sp, #0x80
   962a8: d65f03c0     	ret
   962ac: d102c3ff     	sub	sp, sp, #0xb0
   962b0: 6d0423e9     	stp	d9, d8, [sp, #0x40]
   962b4: a9057bfd     	stp	x29, x30, [sp, #0x50]
   962b8: a9066ffc     	stp	x28, x27, [sp, #0x60]
   962bc: a90767fa     	stp	x26, x25, [sp, #0x70]
   962c0: a9085ff8     	stp	x24, x23, [sp, #0x80]
   962c4: a90957f6     	stp	x22, x21, [sp, #0x90]
   962c8: a90a4ff4     	stp	x20, x19, [sp, #0xa0]
   962cc: 910143fd     	add	x29, sp, #0x50
   962d0: d53bd048     	mrs	x8, TPIDR_EL0
   962d4: 2f00e400     	movi	d0, #0000000000000000
   962d8: f90003e8     	str	x8, [sp]
   962dc: d10073a0     	sub	x0, x29, #0x1c
   962e0: f9401508     	ldr	x8, [x8, #0x28]
   962e4: f81e83a8     	stur	x8, [x29, #-0x18]
   962e8: b81e43bf     	stur	wzr, [x29, #-0x1c]
   962ec: 94029ee9     	bl	0x13de90 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x62cc4>
   962f0: f00005e9     	adrp	x9, 0x155000
   962f4: 528000c8     	mov	w8, #0x6
   962f8: 72a00028     	movk	w8, #0x1, lsl #16
   962fc: a9027fff     	stp	xzr, xzr, [sp, #0x20]
   96300: f9000fff     	str	xzr, [sp, #0x18]
   96304: 9100a3e1     	add	x1, sp, #0x28
   96308: f9455520     	ldr	x0, [x9, #0xaa8]
   9630c: 910043e2     	add	x2, sp, #0x10
   96310: b90013e8     	str	w8, [sp, #0x10]
   96314: 1e604008     	fmov	d8, d0
   96318: f9400008     	ldr	x8, [x0]
   9631c: f9401108     	ldr	x8, [x8, #0x20]
   96320: d63f0100     	blr	x8
   96324: d2961608     	mov	x8, #0xb0b0
   96328: d28f0229     	mov	x9, #0x7811
   9632c: f2a91228     	movk	x8, #0x4891, lsl #16
   96330: f2a0e809     	movk	x9, #0x740, lsl #16
   96334: d29c70da     	mov	x26, #0xe386
   96338: d291f378     	mov	x24, #0x8f9b
   9633c: d29a0b74     	mov	x20, #0xd05b
   96340: d29c9b57     	mov	x23, #0xe4da
   96344: d2811419     	mov	x25, #0x8a0
   96348: d2828e36     	mov	x22, #0x1471
   9634c: d290ef2a     	mov	x10, #0x8779
   96350: f2dafb08     	movk	x8, #0xd7d8, lsl #32
   96354: f2ccf5a9     	movk	x9, #0x67ad, lsl #32
   96358: f2bd571a     	movk	x26, #0xeab8, lsl #16
   9635c: f2b84cf8     	movk	x24, #0xc267, lsl #16
   96360: f2bde414     	movk	x20, #0xef20, lsl #16
   96364: f2ac1ed7     	movk	x23, #0x60f6, lsl #16
   96368: f2b7a2b9     	movk	x25, #0xbd15, lsl #16
   9636c: f2a09416     	movk	x22, #0x4a0, lsl #16
   96370: f2be370a     	movk	x10, #0xf1b8, lsl #16
   96374: f2e7bea8     	movk	x8, #0x3df5, lsl #48
   96378: f2fef389     	movk	x9, #0xf79c, lsl #48
   9637c: 7100001f     	cmp	w0, #0x0
   96380: f2d83d9a     	movk	x26, #0xc1ec, lsl #32
   96384: f2de6a78     	movk	x24, #0xf353, lsl #32
   96388: f2d2d994     	movk	x20, #0x96cc, lsl #32
   9638c: f2d61757     	movk	x23, #0xb0ba, lsl #32
   96390: f2d60599     	movk	x25, #0xb02c, lsl #32
   96394: 0f00e489     	movi	v9.8b, #0x4
   96398: f2c0bfb6     	movk	x22, #0x5fd, lsl #32
   9639c: f2c66f0a     	movk	x10, #0x3378, lsl #32
   963a0: 9a880135     	csel	x21, x9, x8, eq
   963a4: f2f011fa     	movk	x26, #0x808f, lsl #48
   963a8: f2f0a798     	movk	x24, #0x853c, lsl #48
   963ac: f2f0ea74     	movk	x20, #0x8753, lsl #48
   963b0: f2f12817     	movk	x23, #0x8940, lsl #48
   963b4: f2f27cf9     	movk	x25, #0x93e7, lsl #48
   963b8: f2f42356     	movk	x22, #0xa11a, lsl #48
   963bc: f2e1d60a     	movk	x10, #0xeb0, lsl #48
   963c0: 2a0803f3     	mov	w19, w8
   963c4: eb1a015f     	cmp	x10, x26
   963c8: 54005680     	b.eq	0x96e98 <.text+0x8e2b8>
   963cc: aa0a03e9     	mov	x9, x10
   963d0: d29cd64a     	mov	x10, #0xe6b2
   963d4: f2b4034a     	movk	x10, #0xa01a, lsl #16
   963d8: 2a1303e8     	mov	w8, w19
   963dc: f2c2374a     	movk	x10, #0x11ba, lsl #32
   963e0: eb18013f     	cmp	x9, x24
   963e4: f2e4da0a     	movk	x10, #0x26d0, lsl #48
   963e8: 54fffec0     	b.eq	0x963c0 <.text+0x8d7e0>
   963ec: d2830b2a     	mov	x10, #0x1859
   963f0: 2a1303e8     	mov	w8, w19
   963f4: f2a56a6a     	movk	x10, #0x2b53, lsl #16
   963f8: eb14013f     	cmp	x9, x20
   963fc: f2cdff8a     	movk	x10, #0x6ffc, lsl #32
   96400: f2f2616a     	movk	x10, #0x930b, lsl #48
   96404: 54fffde0     	b.eq	0x963c0 <.text+0x8d7e0>
   96408: eb17013f     	cmp	x9, x23
   9640c: 54006720     	b.eq	0x970f0 <.text+0x8e510>
   96410: d2830b28     	mov	x8, #0x1859
   96414: f2a56a68     	movk	x8, #0x2b53, lsl #16
   96418: f2cdff88     	movk	x8, #0x6ffc, lsl #32
   9641c: f2f26168     	movk	x8, #0x930b, lsl #48
   96420: eb08013f     	cmp	x9, x8
   96424: 540037c0     	b.eq	0x96b1c <.text+0x8df3c>
   96428: eb19013f     	cmp	x9, x25
   9642c: 54005c80     	b.eq	0x96fbc <.text+0x8e3dc>
   96430: d28a8168     	mov	x8, #0x540b
   96434: f2abcd48     	movk	x8, #0x5e6a, lsl #16
   96438: f2cbfb88     	movk	x8, #0x5fdc, lsl #32
   9643c: f2f32e88     	movk	x8, #0x9974, lsl #48
   96440: eb08013f     	cmp	x9, x8
   96444: 54006920     	b.eq	0x97168 <.text+0x8e588>
   96448: d2985448     	mov	x8, #0xc2a2
   9644c: f2a20908     	movk	x8, #0x1048, lsl #16
   96450: f2ce2088     	movk	x8, #0x7104, lsl #32
   96454: f2f3ffc8     	movk	x8, #0x9ffe, lsl #48
   96458: eb08013f     	cmp	x9, x8
   9645c: 540046e0     	b.eq	0x96d38 <.text+0x8e158>
   96460: eb16013f     	cmp	x9, x22
   96464: 540065a0     	b.eq	0x97118 <.text+0x8e538>
   96468: d29fc14a     	mov	x10, #0xfe0a
   9646c: d280d24b     	mov	x11, #0x692
   96470: f2ad3faa     	movk	x10, #0x69fd, lsl #16
   96474: f2b100eb     	movk	x11, #0x8807, lsl #16
   96478: f2cbe74a     	movk	x10, #0x5f3a, lsl #32
   9647c: 2a1303e8     	mov	w8, w19
   96480: f2f7b8ea     	movk	x10, #0xbdc7, lsl #48
   96484: f2df7c6b     	movk	x11, #0xfbe3, lsl #32
   96488: f2f4366b     	movk	x11, #0xa1b3, lsl #48
   9648c: eb0b013f     	cmp	x9, x11
   96490: 54fff980     	b.eq	0x963c0 <.text+0x8d7e0>
   96494: d28f002a     	mov	x10, #0x7801
   96498: d291b0eb     	mov	x11, #0x8d87
   9649c: f2b40daa     	movk	x10, #0xa06d, lsl #16
   964a0: f2b45e6b     	movk	x11, #0xa2f3, lsl #16
   964a4: f2d56bea     	movk	x10, #0xab5f, lsl #32
   964a8: 2a1303e8     	mov	w8, w19
   964ac: f2e45b6a     	movk	x10, #0x22db, lsl #48
   964b0: f2d0c90b     	movk	x11, #0x8648, lsl #32
   964b4: f2f4bc6b     	movk	x11, #0xa5e3, lsl #48
   964b8: eb0b013f     	cmp	x9, x11
   964bc: 54fff820     	b.eq	0x963c0 <.text+0x8d7e0>
   964c0: d2810ca8     	mov	x8, #0x865
   964c4: f2aa6c48     	movk	x8, #0x5362, lsl #16
   964c8: f2d31d48     	movk	x8, #0x98ea, lsl #32
   964cc: f2f57fa8     	movk	x8, #0xabfd, lsl #48
   964d0: eb08013f     	cmp	x9, x8
   964d4: 54005f20     	b.eq	0x970b8 <.text+0x8e4d8>
   964d8: d28a816a     	mov	x10, #0x540b
   964dc: d2859d8b     	mov	x11, #0x2cec
   964e0: f2abcd4a     	movk	x10, #0x5e6a, lsl #16
   964e4: f2a362cb     	movk	x11, #0x1b16, lsl #16
   964e8: f2cbfb8a     	movk	x10, #0x5fdc, lsl #32
   964ec: 2a1303e8     	mov	w8, w19
   964f0: f2f32e8a     	movk	x10, #0x9974, lsl #48
   964f4: f2d2060b     	movk	x11, #0x9030, lsl #32
   964f8: f2f6d82b     	movk	x11, #0xb6c1, lsl #48
   964fc: eb0b013f     	cmp	x9, x11
   96500: 54fff600     	b.eq	0x963c0 <.text+0x8d7e0>
   96504: d2967a0a     	mov	x10, #0xb3d0
   96508: d282702b     	mov	x11, #0x1381
   9650c: f2a0acca     	movk	x10, #0x566, lsl #16
   96510: f2b4b14b     	movk	x11, #0xa58a, lsl #16
   96514: f2d4a1aa     	movk	x10, #0xa50d, lsl #32
   96518: 2a1303e8     	mov	w8, w19
   9651c: f2e4094a     	movk	x10, #0x204a, lsl #48
   96520: f2d6ec6b     	movk	x11, #0xb763, lsl #32
   96524: f2f779ab     	movk	x11, #0xbbcd, lsl #48
   96528: eb0b013f     	cmp	x9, x11
   9652c: 54fff4a0     	b.eq	0x963c0 <.text+0x8d7e0>
   96530: d29fc148     	mov	x8, #0xfe0a
   96534: f2ad3fa8     	movk	x8, #0x69fd, lsl #16
   96538: f2cbe748     	movk	x8, #0x5f3a, lsl #32
   9653c: f2f7b8e8     	movk	x8, #0xbdc7, lsl #48
   96540: eb08013f     	cmp	x9, x8
   96544: 54004740     	b.eq	0x96e2c <.text+0x8e24c>
   96548: d28381e8     	mov	x8, #0x1c0f
   9654c: f2ad68e8     	movk	x8, #0x6b47, lsl #16
   96550: f2c96068     	movk	x8, #0x4b03, lsl #32
   96554: f2f837a8     	movk	x8, #0xc1bd, lsl #48
   96558: eb08013f     	cmp	x9, x8
   9655c: 540038e0     	b.eq	0x96c78 <.text+0x8e098>
   96560: d28a0f68     	mov	x8, #0x507b
   96564: f2a58a08     	movk	x8, #0x2c50, lsl #16
   96568: f2c91588     	movk	x8, #0x48ac, lsl #32
   9656c: f2f92168     	movk	x8, #0xc90b, lsl #48
   96570: eb08013f     	cmp	x9, x8
   96574: 54002f60     	b.eq	0x96b60 <.text+0x8df80>
   96578: d28061c8     	mov	x8, #0x30e
   9657c: f2a036a8     	movk	x8, #0x1b5, lsl #16
   96580: f2d3dd28     	movk	x8, #0x9ee9, lsl #32
   96584: f2f9ee68     	movk	x8, #0xcf73, lsl #48
   96588: eb08013f     	cmp	x9, x8
   9658c: 54003160     	b.eq	0x96bb8 <.text+0x8dfd8>
   96590: d28137aa     	mov	x10, #0x9bd
   96594: d28227eb     	mov	x11, #0x113f
   96598: f2b6beca     	movk	x10, #0xb5f6, lsl #16
   9659c: f2b9d5eb     	movk	x11, #0xceaf, lsl #16
   965a0: f2d9d1ea     	movk	x10, #0xce8f, lsl #32
   965a4: 2a1303e8     	mov	w8, w19
   965a8: f2ec5aaa     	movk	x10, #0x62d5, lsl #48
   965ac: f2c9fccb     	movk	x11, #0x4fe6, lsl #32
   965b0: f2fd3feb     	movk	x11, #0xe9ff, lsl #48
   965b4: eb0b013f     	cmp	x9, x11
   965b8: 54fff040     	b.eq	0x963c0 <.text+0x8d7e0>
   965bc: d284b9c8     	mov	x8, #0x25ce
   965c0: f2b187c8     	movk	x8, #0x8c3e, lsl #16
   965c4: f2dbd848     	movk	x8, #0xdec2, lsl #32
   965c8: f2fe4028     	movk	x8, #0xf201, lsl #48
   965cc: eb08013f     	cmp	x9, x8
   965d0: 54005100     	b.eq	0x96ff0 <.text+0x8e410>
   965d4: d28f0228     	mov	x8, #0x7811
   965d8: f2a0e808     	movk	x8, #0x740, lsl #16
   965dc: f2ccf5a8     	movk	x8, #0x67ad, lsl #32
   965e0: f2fef388     	movk	x8, #0xf79c, lsl #48
   965e4: eb08013f     	cmp	x9, x8
   965e8: 54003d80     	b.eq	0x96d98 <.text+0x8e1b8>
   965ec: d28411aa     	mov	x10, #0x208d
   965f0: d299bf0b     	mov	x11, #0xcdf8
   965f4: f2a8966a     	movk	x10, #0x44b3, lsl #16
   965f8: f2bae56b     	movk	x11, #0xd72b, lsl #16
   965fc: f2d733ea     	movk	x10, #0xb99f, lsl #32
   96600: 2a1b03e8     	mov	w8, w27
   96604: f2e7de4a     	movk	x10, #0x3ef2, lsl #48
   96608: f2cab54b     	movk	x11, #0x55aa, lsl #32
   9660c: f2ffcd6b     	movk	x11, #0xfe6b, lsl #48
   96610: eb0b013f     	cmp	x9, x11
   96614: 54ffed60     	b.eq	0x963c0 <.text+0x8d7e0>
   96618: d284b9ca     	mov	x10, #0x25ce
   9661c: d295f94b     	mov	x11, #0xafca
   96620: f2b187ca     	movk	x10, #0x8c3e, lsl #16
   96624: f2af834b     	movk	x11, #0x7c1a, lsl #16
   96628: f2dbd84a     	movk	x10, #0xdec2, lsl #32
   9662c: 2a1303e8     	mov	w8, w19
   96630: f2fe402a     	movk	x10, #0xf201, lsl #48
   96634: f2c3c72b     	movk	x11, #0x1e39, lsl #32
   96638: f2e0de6b     	movk	x11, #0x6f3, lsl #48
   9663c: eb0b013f     	cmp	x9, x11
   96640: 54ffec00     	b.eq	0x963c0 <.text+0x8d7e0>
   96644: d29e47c8     	mov	x8, #0xf23e
   96648: f2bd7388     	movk	x8, #0xeb9c, lsl #16
   9664c: f2cccfc8     	movk	x8, #0x667e, lsl #32
   96650: f2e0f908     	movk	x8, #0x7c8, lsl #48
   96654: eb08013f     	cmp	x9, x8
   96658: 54003bc0     	b.eq	0x96dd0 <.text+0x8e1f0>
   9665c: d28411aa     	mov	x10, #0x208d
   96660: d2832d0b     	mov	x11, #0x1968
   96664: f2a8966a     	movk	x10, #0x44b3, lsl #16
   96668: f2ab264b     	movk	x11, #0x5932, lsl #16
   9666c: f2d733ea     	movk	x10, #0xb99f, lsl #32
   96670: 2a1c03e8     	mov	w8, w28
   96674: f2e7de4a     	movk	x10, #0x3ef2, lsl #48
   96678: f2d0672b     	movk	x11, #0x8339, lsl #32
   9667c: f2e1626b     	movk	x11, #0xb13, lsl #48
   96680: eb0b013f     	cmp	x9, x11
   96684: 54ffe9e0     	b.eq	0x963c0 <.text+0x8d7e0>
   96688: d290ef2b     	mov	x11, #0x8779
   9668c: 2a1303e8     	mov	w8, w19
   96690: f2be370b     	movk	x11, #0xf1b8, lsl #16
   96694: aa1503ea     	mov	x10, x21
   96698: f2c66f0b     	movk	x11, #0x3378, lsl #32
   9669c: f2e1d60b     	movk	x11, #0xeb0, lsl #48
   966a0: eb0b013f     	cmp	x9, x11
   966a4: 54ffe8e0     	b.eq	0x963c0 <.text+0x8d7e0>
   966a8: d299aa6a     	mov	x10, #0xcd53
   966ac: d29d424b     	mov	x11, #0xea12
   966b0: f2b5bcca     	movk	x10, #0xade6, lsl #16
   966b4: f2a5590b     	movk	x11, #0x2ac8, lsl #16
   966b8: f2ddffea     	movk	x10, #0xefff, lsl #32
   966bc: 2a1303e8     	mov	w8, w19
   966c0: f2e27a8a     	movk	x10, #0x13d4, lsl #48
   966c4: f2c3ac0b     	movk	x11, #0x1d60, lsl #32
   966c8: f2e2046b     	movk	x11, #0x1023, lsl #48
   966cc: eb0b013f     	cmp	x9, x11
   966d0: 54ffe780     	b.eq	0x963c0 <.text+0x8d7e0>
   966d4: d299aa68     	mov	x8, #0xcd53
   966d8: f2b5bcc8     	movk	x8, #0xade6, lsl #16
   966dc: f2ddffe8     	movk	x8, #0xefff, lsl #32
   966e0: f2e27a88     	movk	x8, #0x13d4, lsl #48
   966e4: eb08013f     	cmp	x9, x8
   966e8: 54004180     	b.eq	0x96f18 <.text+0x8e338>
   966ec: d28c98c8     	mov	x8, #0x64c6
   966f0: f2b69be8     	movk	x8, #0xb4df, lsl #16
   966f4: f2d950e8     	movk	x8, #0xca87, lsl #32
   966f8: f2e2c588     	movk	x8, #0x162c, lsl #48
   966fc: eb08013f     	cmp	x9, x8
   96700: 54004c80     	b.eq	0x97090 <.text+0x8e4b0>
   96704: d28fbe68     	mov	x8, #0x7df3
   96708: f2b81008     	movk	x8, #0xc080, lsl #16
   9670c: f2cb5308     	movk	x8, #0x5a98, lsl #32
   96710: f2e2e088     	movk	x8, #0x1704, lsl #48
   96714: eb08013f     	cmp	x9, x8
   96718: 54004a00     	b.eq	0x97058 <.text+0x8e478>
   9671c: d28381ea     	mov	x10, #0x1c0f
   96720: d2804b2b     	mov	x11, #0x259
   96724: f2ad68ea     	movk	x10, #0x6b47, lsl #16
   96728: f2adc54b     	movk	x11, #0x6e2a, lsl #16
   9672c: f2c9606a     	movk	x10, #0x4b03, lsl #32
   96730: 2a1303e8     	mov	w8, w19
   96734: f2f837aa     	movk	x10, #0xc1bd, lsl #48
   96738: f2d8d96b     	movk	x11, #0xc6cb, lsl #32
   9673c: f2e2edcb     	movk	x11, #0x176e, lsl #48
   96740: eb0b013f     	cmp	x9, x11
   96744: 54ffe3e0     	b.eq	0x963c0 <.text+0x8d7e0>
   96748: d28a0f6a     	mov	x10, #0x507b
   9674c: d29bf76b     	mov	x11, #0xdfbb
   96750: f2a58a0a     	movk	x10, #0x2c50, lsl #16
   96754: f2bfa80b     	movk	x11, #0xfd40, lsl #16
   96758: f2c9158a     	movk	x10, #0x48ac, lsl #32
   9675c: 2a1303e8     	mov	w8, w19
   96760: f2f9216a     	movk	x10, #0xc90b, lsl #48
   96764: f2dd580b     	movk	x11, #0xeac0, lsl #32
   96768: f2e3940b     	movk	x11, #0x1ca0, lsl #48
   9676c: eb0b013f     	cmp	x9, x11
   96770: 54ffe280     	b.eq	0x963c0 <.text+0x8d7e0>
   96774: d29c2348     	mov	x8, #0xe11a
   96778: f2bce0e8     	movk	x8, #0xe707, lsl #16
   9677c: f2ca52c8     	movk	x8, #0x5296, lsl #32
   96780: f2e3be68     	movk	x8, #0x1df3, lsl #48
   96784: eb08013f     	cmp	x9, x8
   96788: 54003ea0     	b.eq	0x96f5c <.text+0x8e37c>
   9678c: d2967a08     	mov	x8, #0xb3d0
   96790: f2a0acc8     	movk	x8, #0x566, lsl #16
   96794: f2d4a1a8     	movk	x8, #0xa50d, lsl #32
   96798: f2e40948     	movk	x8, #0x204a, lsl #48
   9679c: eb08013f     	cmp	x9, x8
   967a0: 540039a0     	b.eq	0x96ed4 <.text+0x8e2f4>
   967a4: d29fc14a     	mov	x10, #0xfe0a
   967a8: d28f002b     	mov	x11, #0x7801
   967ac: f2ad3faa     	movk	x10, #0x69fd, lsl #16
   967b0: f2b40dab     	movk	x11, #0xa06d, lsl #16
   967b4: f2cbe74a     	movk	x10, #0x5f3a, lsl #32
   967b8: 2a1303e8     	mov	w8, w19
   967bc: f2f7b8ea     	movk	x10, #0xbdc7, lsl #48
   967c0: f2d56beb     	movk	x11, #0xab5f, lsl #32
   967c4: f2e45b6b     	movk	x11, #0x22db, lsl #48
   967c8: eb0b013f     	cmp	x9, x11
   967cc: 54ffdfa0     	b.eq	0x963c0 <.text+0x8d7e0>
   967d0: d280ea8a     	mov	x10, #0x754
   967d4: d291254b     	mov	x11, #0x892a
   967d8: f2b40f0a     	movk	x10, #0xa078, lsl #16
   967dc: f2beb12b     	movk	x11, #0xf589, lsl #16
   967e0: f2c3f28a     	movk	x10, #0x1f94, lsl #32
   967e4: 2a1303e8     	mov	w8, w19
   967e8: f2e6504a     	movk	x10, #0x3282, lsl #48
   967ec: f2ddc5eb     	movk	x11, #0xee2f, lsl #32
   967f0: f2e4980b     	movk	x11, #0x24c0, lsl #48
   967f4: eb0b013f     	cmp	x9, x11
   967f8: 54ffde40     	b.eq	0x963c0 <.text+0x8d7e0>
   967fc: d2967a0a     	mov	x10, #0xb3d0
   96800: d296062b     	mov	x11, #0xb031
   96804: f2a0acca     	movk	x10, #0x566, lsl #16
   96808: f2b3982b     	movk	x11, #0x9cc1, lsl #16
   9680c: f2d4a1aa     	movk	x10, #0xa50d, lsl #32
   96810: 2a1303e8     	mov	w8, w19
   96814: f2e4094a     	movk	x10, #0x204a, lsl #48
   96818: f2dffd6b     	movk	x11, #0xffeb, lsl #32
   9681c: f2e4a2cb     	movk	x11, #0x2516, lsl #48
   96820: eb0b013f     	cmp	x9, x11
   96824: 54ffdce0     	b.eq	0x963c0 <.text+0x8d7e0>
   96828: d299aa6a     	mov	x10, #0xcd53
   9682c: d280124b     	mov	x11, #0x92
   96830: f2b5bcca     	movk	x10, #0xade6, lsl #16
   96834: f2a2dacb     	movk	x11, #0x16d6, lsl #16
   96838: f2ddffea     	movk	x10, #0xefff, lsl #32
   9683c: 2a1303e8     	mov	w8, w19
   96840: f2e27a8a     	movk	x10, #0x13d4, lsl #48
   96844: f2d3a0cb     	movk	x11, #0x9d06, lsl #32
   96848: f2e4d00b     	movk	x11, #0x2680, lsl #48
   9684c: eb0b013f     	cmp	x9, x11
   96850: 54ffdb80     	b.eq	0x963c0 <.text+0x8d7e0>
   96854: d29cd648     	mov	x8, #0xe6b2
   96858: f2b40348     	movk	x8, #0xa01a, lsl #16
   9685c: f2c23748     	movk	x8, #0x11ba, lsl #32
   96860: f2e4da08     	movk	x8, #0x26d0, lsl #48
   96864: eb08013f     	cmp	x9, x8
   96868: 54001ba0     	b.eq	0x96bdc <.text+0x8dffc>
   9686c: d29cd64a     	mov	x10, #0xe6b2
   96870: d284428b     	mov	x11, #0x2214
   96874: f2b4034a     	movk	x10, #0xa01a, lsl #16
   96878: f2adcd8b     	movk	x11, #0x6e6c, lsl #16
   9687c: f2c2374a     	movk	x10, #0x11ba, lsl #32
   96880: 2a1303e8     	mov	w8, w19
   96884: f2e4da0a     	movk	x10, #0x26d0, lsl #48
   96888: f2c4e0ab     	movk	x11, #0x2705, lsl #32
   9688c: f2e5d34b     	movk	x11, #0x2e9a, lsl #48
   96890: eb0b013f     	cmp	x9, x11
   96894: 54ffd960     	b.eq	0x963c0 <.text+0x8d7e0>
   96898: d280ea88     	mov	x8, #0x754
   9689c: f2b40f08     	movk	x8, #0xa078, lsl #16
   968a0: f2c3f288     	movk	x8, #0x1f94, lsl #32
   968a4: f2e65048     	movk	x8, #0x3282, lsl #48
   968a8: eb08013f     	cmp	x9, x8
   968ac: 54001a40     	b.eq	0x96bf4 <.text+0x8e014>
   968b0: d289f428     	mov	x8, #0x4fa1
   968b4: f2a7f848     	movk	x8, #0x3fc2, lsl #16
   968b8: f2c97328     	movk	x8, #0x4b99, lsl #32
   968bc: f2e6cb88     	movk	x8, #0x365c, lsl #48
   968c0: eb08013f     	cmp	x9, x8
   968c4: 54002000     	b.eq	0x96cc4 <.text+0x8e0e4>
   968c8: d298d7a8     	mov	x8, #0xc6bd
   968cc: f2bb4e28     	movk	x8, #0xda71, lsl #16
   968d0: f2cc8448     	movk	x8, #0x6422, lsl #32
   968d4: f2e761a8     	movk	x8, #0x3b0d, lsl #48
   968d8: eb08013f     	cmp	x9, x8
   968dc: 54002160     	b.eq	0x96d08 <.text+0x8e128>
   968e0: d2830b2a     	mov	x10, #0x1859
   968e4: d283b58b     	mov	x11, #0x1dac
   968e8: f2a56a6a     	movk	x10, #0x2b53, lsl #16
   968ec: f2b3ebcb     	movk	x11, #0x9f5e, lsl #16
   968f0: f2cdff8a     	movk	x10, #0x6ffc, lsl #32
   968f4: 2a1303e8     	mov	w8, w19
   968f8: f2f2616a     	movk	x10, #0x930b, lsl #48
   968fc: f2d6ec4b     	movk	x11, #0xb762, lsl #32
   96900: f2e7694b     	movk	x11, #0x3b4a, lsl #48
   96904: eb0b013f     	cmp	x9, x11
   96908: 54ffd5c0     	b.eq	0x963c0 <.text+0x8d7e0>
   9690c: d2961608     	mov	x8, #0xb0b0
   96910: f2a91228     	movk	x8, #0x4891, lsl #16
   96914: f2dafb08     	movk	x8, #0xd7d8, lsl #32
   96918: f2e7bea8     	movk	x8, #0x3df5, lsl #48
   9691c: eb08013f     	cmp	x9, x8
   96920: 540019a0     	b.eq	0x96c54 <.text+0x8e074>
   96924: d28411a8     	mov	x8, #0x208d
   96928: f2a89668     	movk	x8, #0x44b3, lsl #16
   9692c: f2d733e8     	movk	x8, #0xb99f, lsl #32
   96930: f2e7de48     	movk	x8, #0x3ef2, lsl #48
   96934: eb08013f     	cmp	x9, x8
   96938: 540029c0     	b.eq	0x96e70 <.text+0x8e290>
   9693c: d28411aa     	mov	x10, #0x208d
   96940: d28981ab     	mov	x11, #0x4c0d
   96944: f2a8966a     	movk	x10, #0x44b3, lsl #16
   96948: f2aa5bab     	movk	x11, #0x52dd, lsl #16
   9694c: f2d733ea     	movk	x10, #0xb99f, lsl #32
   96950: b9400fe8     	ldr	w8, [sp, #0xc]
   96954: f2e7de4a     	movk	x10, #0x3ef2, lsl #48
   96958: f2cfb9eb     	movk	x11, #0x7dcf, lsl #32
   9695c: f2e91fcb     	movk	x11, #0x48fe, lsl #48
   96960: eb0b013f     	cmp	x9, x11
   96964: 54ffd2e0     	b.eq	0x963c0 <.text+0x8d7e0>
   96968: d28137aa     	mov	x10, #0x9bd
   9696c: d29a504b     	mov	x11, #0xd282
   96970: f2b6beca     	movk	x10, #0xb5f6, lsl #16
   96974: f2b2afab     	movk	x11, #0x957d, lsl #16
   96978: f2d9d1ea     	movk	x10, #0xce8f, lsl #32
   9697c: 2a1303e8     	mov	w8, w19
   96980: f2ec5aaa     	movk	x10, #0x62d5, lsl #48
   96984: f2c15bab     	movk	x11, #0xadd, lsl #32
   96988: f2ea93eb     	movk	x11, #0x549f, lsl #48
   9698c: eb0b013f     	cmp	x9, x11
   96990: 54ffd180     	b.eq	0x963c0 <.text+0x8d7e0>
   96994: d296062a     	mov	x10, #0xb031
   96998: d28c86cb     	mov	x11, #0x6436
   9699c: f2b3982a     	movk	x10, #0x9cc1, lsl #16
   969a0: f2a50d2b     	movk	x11, #0x2869, lsl #16
   969a4: f2dffd6a     	movk	x10, #0xffeb, lsl #32
   969a8: 2a1303e8     	mov	w8, w19
   969ac: f2e4a2ca     	movk	x10, #0x2516, lsl #48
   969b0: f2d8bbeb     	movk	x11, #0xc5df, lsl #32
   969b4: f2eadbcb     	movk	x11, #0x56de, lsl #48
   969b8: eb0b013f     	cmp	x9, x11
   969bc: 54ffd020     	b.eq	0x963c0 <.text+0x8d7e0>
   969c0: d298544a     	mov	x10, #0xc2a2
   969c4: d292678b     	mov	x11, #0x933c
   969c8: f2a2090a     	movk	x10, #0x1048, lsl #16
   969cc: f2a8270b     	movk	x11, #0x4138, lsl #16
   969d0: f2ce208a     	movk	x10, #0x7104, lsl #32
   969d4: 2a1303e8     	mov	w8, w19
   969d8: f2f3ffca     	movk	x10, #0x9ffe, lsl #48
   969dc: f2d7710b     	movk	x11, #0xbb88, lsl #32
   969e0: f2eb844b     	movk	x11, #0x5c22, lsl #48
   969e4: eb0b013f     	cmp	x9, x11
   969e8: 54ffcec0     	b.eq	0x963c0 <.text+0x8d7e0>
   969ec: d28381ea     	mov	x10, #0x1c0f
   969f0: d289768b     	mov	x11, #0x4bb4
   969f4: f2ad68ea     	movk	x10, #0x6b47, lsl #16
   969f8: f2a10eeb     	movk	x11, #0x877, lsl #16
   969fc: f2c9606a     	movk	x10, #0x4b03, lsl #32
   96a00: 2a1303e8     	mov	w8, w19
   96a04: f2f837aa     	movk	x10, #0xc1bd, lsl #48
   96a08: f2cb2e8b     	movk	x11, #0x5974, lsl #32
   96a0c: f2ebdfeb     	movk	x11, #0x5eff, lsl #48
   96a10: eb0b013f     	cmp	x9, x11
   96a14: 54ffcd60     	b.eq	0x963c0 <.text+0x8d7e0>
   96a18: d28137a8     	mov	x8, #0x9bd
   96a1c: f2b6bec8     	movk	x8, #0xb5f6, lsl #16
   96a20: f2d9d1e8     	movk	x8, #0xce8f, lsl #32
   96a24: f2ec5aa8     	movk	x8, #0x62d5, lsl #48
   96a28: eb08013f     	cmp	x9, x8
   96a2c: 54001e60     	b.eq	0x96df8 <.text+0x8e218>
   96a30: d296062a     	mov	x10, #0xb031
   96a34: d29dc2ab     	mov	x11, #0xee15
   96a38: f2b3982a     	movk	x10, #0x9cc1, lsl #16
   96a3c: f2a3fc2b     	movk	x11, #0x1fe1, lsl #16
   96a40: f2dffd6a     	movk	x10, #0xffeb, lsl #32
   96a44: 2a1303e8     	mov	w8, w19
   96a48: f2e4a2ca     	movk	x10, #0x2516, lsl #48
   96a4c: f2ca6ecb     	movk	x11, #0x5376, lsl #32
   96a50: f2ed552b     	movk	x11, #0x6aa9, lsl #48
   96a54: eb0b013f     	cmp	x9, x11
   96a58: 54ffcb40     	b.eq	0x963c0 <.text+0x8d7e0>
   96a5c: d28920aa     	mov	x10, #0x4905
   96a60: d29ac5ab     	mov	x11, #0xd62d
   96a64: f2a9a98a     	movk	x10, #0x4d4c, lsl #16
   96a68: f2b4e2eb     	movk	x11, #0xa717, lsl #16
   96a6c: f2d488aa     	movk	x10, #0xa445, lsl #32
   96a70: 2a1303e8     	mov	w8, w19
   96a74: f2f3b22a     	movk	x10, #0x9d91, lsl #48
   96a78: f2dad08b     	movk	x11, #0xd684, lsl #32
   96a7c: f2eebd4b     	movk	x11, #0x75ea, lsl #48
   96a80: eb0b013f     	cmp	x9, x11
   96a84: 54ffc9e0     	b.eq	0x963c0 <.text+0x8d7e0>
   96a88: d28b9708     	mov	x8, #0x5cb8
   96a8c: f2a4f2a8     	movk	x8, #0x2795, lsl #16
   96a90: f2c2be88     	movk	x8, #0x15f4, lsl #32
   96a94: f2eef488     	movk	x8, #0x77a4, lsl #48
   96a98: eb08013f     	cmp	x9, x8
   96a9c: 54001040     	b.eq	0x96ca4 <.text+0x8e0c4>
   96aa0: d28f002a     	mov	x10, #0x7801
   96aa4: d28db76b     	mov	x11, #0x6dbb
   96aa8: f2b40daa     	movk	x10, #0xa06d, lsl #16
   96aac: f2b80b0b     	movk	x11, #0xc058, lsl #16
   96ab0: f2d56bea     	movk	x10, #0xab5f, lsl #32
   96ab4: 2a1303e8     	mov	w8, w19
   96ab8: f2e45b6a     	movk	x10, #0x22db, lsl #48
   96abc: f2deadab     	movk	x11, #0xf56d, lsl #32
   96ac0: f2efd10b     	movk	x11, #0x7e88, lsl #48
   96ac4: eb0b013f     	cmp	x9, x11
   96ac8: 54ffc7c0     	b.eq	0x963c0 <.text+0x8d7e0>
   96acc: d28411aa     	mov	x10, #0x208d
   96ad0: d28e810b     	mov	x11, #0x7408
   96ad4: f2a8966a     	movk	x10, #0x44b3, lsl #16
   96ad8: f2a9c28b     	movk	x11, #0x4e14, lsl #16
   96adc: f2d733ea     	movk	x10, #0xb99f, lsl #32
   96ae0: b9400be8     	ldr	w8, [sp, #0x8]
   96ae4: f2e7de4a     	movk	x10, #0x3ef2, lsl #48
   96ae8: f2c879ab     	movk	x11, #0x43cd, lsl #32
   96aec: f2efee8b     	movk	x11, #0x7f74, lsl #48
   96af0: eb0b013f     	cmp	x9, x11
   96af4: 54ffc660     	b.eq	0x963c0 <.text+0x8d7e0>
   96af8: d28920ab     	mov	x11, #0x4905
   96afc: 2a1303e8     	mov	w8, w19
   96b00: f2a9a98b     	movk	x11, #0x4d4c, lsl #16
   96b04: aa0903ea     	mov	x10, x9
   96b08: f2d488ab     	movk	x11, #0xa445, lsl #32
   96b0c: f2f3b22b     	movk	x11, #0x9d91, lsl #48
   96b10: eb0b013f     	cmp	x9, x11
   96b14: 54ffc561     	b.ne	0x963c0 <.text+0x8d7e0>
   96b18: 140001a4     	b	0x971a8 <.text+0x8e5c8>
   96b1c: 2a1f03e0     	mov	w0, wzr
   96b20: 52800021     	mov	w1, #0x1
   96b24: d503201f     	nop
   96b28: 105f7ae2     	adr	x2, #0xbef5c
   96b2c: 9402c62d     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   96b30: d283b589     	mov	x9, #0x1dac
   96b34: d298d7aa     	mov	x10, #0xc6bd
   96b38: f2b3ebc9     	movk	x9, #0x9f5e, lsl #16
   96b3c: f2bb4e2a     	movk	x10, #0xda71, lsl #16
   96b40: f2d6ec49     	movk	x9, #0xb762, lsl #32
   96b44: f2cc844a     	movk	x10, #0x6422, lsl #32
   96b48: 7100001f     	cmp	w0, #0x0
   96b4c: f2e76949     	movk	x9, #0x3b4a, lsl #48
   96b50: f2e761aa     	movk	x10, #0x3b0d, lsl #48
   96b54: 2a1303e8     	mov	w8, w19
   96b58: 9a89014a     	csel	x10, x10, x9, eq
   96b5c: 17fffe19     	b	0x963c0 <.text+0x8d7e0>
   96b60: d503201f     	nop
   96b64: 105f7908     	adr	x8, #0xbef20
   96b68: d503201f     	nop
   96b6c: 105e60e1     	adr	x1, #0xbcc1c
   96b70: 52800802     	mov	w2, #0x40
   96b74: 089ffd1f     	stlrb	wzr, [x8]
   96b78: f94017e0     	ldr	x0, [sp, #0x28]
   96b7c: 94000bd3     	bl	0x99ac8 <.text+0x90ee8>
   96b80: f00005e8     	adrp	x8, 0x155000
   96b84: b9000be0     	str	w0, [sp, #0x8]
   96b88: b94aa508     	ldr	w8, [x8, #0xaa4]
   96b8c: 7100011f     	cmp	w8, #0x0
   96b90: 1a9f07e8     	cset	w8, ne
   96b94: 2a080008     	orr	w8, w0, w8
   96b98: 7200011f     	tst	w8, #0x1
   96b9c: d28e8108     	mov	x8, #0x7408
   96ba0: f2a9c288     	movk	x8, #0x4e14, lsl #16
   96ba4: f2c879a8     	movk	x8, #0x43cd, lsl #32
   96ba8: f2efee88     	movk	x8, #0x7f74, lsl #48
   96bac: 9a94110a     	csel	x10, x8, x20, ne
   96bb0: 2a1303e8     	mov	w8, w19
   96bb4: 17fffe03     	b	0x963c0 <.text+0x8d7e0>
   96bb8: 1e604100     	fmov	d0, d8
   96bbc: d10073a0     	sub	x0, x29, #0x1c
   96bc0: 94029cb4     	bl	0x13de90 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x62cc4>
   96bc4: d28920aa     	mov	x10, #0x4905
   96bc8: 2a1303e8     	mov	w8, w19
   96bcc: f2a9a98a     	movk	x10, #0x4d4c, lsl #16
   96bd0: f2d488aa     	movk	x10, #0xa445, lsl #32
   96bd4: f2f3b22a     	movk	x10, #0x9d91, lsl #48
   96bd8: 17fffdfa     	b	0x963c0 <.text+0x8d7e0>
   96bdc: d28381ea     	mov	x10, #0x1c0f
   96be0: 2a1303e8     	mov	w8, w19
   96be4: f2ad68ea     	movk	x10, #0x6b47, lsl #16
   96be8: f2c9606a     	movk	x10, #0x4b03, lsl #32
   96bec: f2f837aa     	movk	x10, #0xc1bd, lsl #48
   96bf0: 1400001e     	b	0x96c68 <.text+0x8e088>
   96bf4: d503201f     	nop
   96bf8: 105f7488     	adr	x8, #0xbee90
   96bfc: d503201f     	nop
   96c00: 105e5c81     	adr	x1, #0xbcb90
   96c04: 52800802     	mov	w2, #0x40
   96c08: 089ffd1f     	stlrb	wzr, [x8]
   96c0c: f94017e0     	ldr	x0, [sp, #0x28]
   96c10: 94000bae     	bl	0x99ac8 <.text+0x90ee8>
   96c14: f00005e8     	adrp	x8, 0x155000
   96c18: d28db769     	mov	x9, #0x6dbb
   96c1c: f2b80b09     	movk	x9, #0xc058, lsl #16
   96c20: 2a0003fc     	mov	w28, w0
   96c24: f2deada9     	movk	x9, #0xf56d, lsl #32
   96c28: b94aa508     	ldr	w8, [x8, #0xaa4]
   96c2c: f2efd109     	movk	x9, #0x7e88, lsl #48
   96c30: 7100011f     	cmp	w8, #0x0
   96c34: 1a9f07e8     	cset	w8, ne
   96c38: 2a080008     	orr	w8, w0, w8
   96c3c: 7200011f     	tst	w8, #0x1
   96c40: d2832d08     	mov	x8, #0x1968
   96c44: f2ab2648     	movk	x8, #0x5932, lsl #16
   96c48: f2d06728     	movk	x8, #0x8339, lsl #32
   96c4c: f2e16268     	movk	x8, #0xb13, lsl #48
   96c50: 1400010d     	b	0x97084 <.text+0x8e4a4>
   96c54: d289f42a     	mov	x10, #0x4fa1
   96c58: 2a1303e8     	mov	w8, w19
   96c5c: f2a7f84a     	movk	x10, #0x3fc2, lsl #16
   96c60: f2c9732a     	movk	x10, #0x4b99, lsl #32
   96c64: f2e6cb8a     	movk	x10, #0x365c, lsl #48
   96c68: f00005e9     	adrp	x9, 0x155000
   96c6c: 5280056b     	mov	w11, #0x2b
   96c70: b90aa52b     	str	w11, [x9, #0xaa4]
   96c74: 17fffdd3     	b	0x963c0 <.text+0x8d7e0>
   96c78: f00005e8     	adrp	x8, 0x155000
   96c7c: f9455500     	ldr	x0, [x8, #0xaa8]
   96c80: f9400008     	ldr	x8, [x0]
   96c84: f9401508     	ldr	x8, [x8, #0x28]
   96c88: d63f0100     	blr	x8
   96c8c: d289f42a     	mov	x10, #0x4fa1
   96c90: 2a1303e8     	mov	w8, w19
   96c94: f2a7f84a     	movk	x10, #0x3fc2, lsl #16
   96c98: f2c9732a     	movk	x10, #0x4b99, lsl #32
   96c9c: f2e6cb8a     	movk	x10, #0x365c, lsl #48
   96ca0: 17fffdc8     	b	0x963c0 <.text+0x8d7e0>
   96ca4: b00005e9     	adrp	x9, 0x153000
   96ca8: d284b9ca     	mov	x10, #0x25ce
   96cac: f2b187ca     	movk	x10, #0x8c3e, lsl #16
   96cb0: 2a1303e8     	mov	w8, w19
   96cb4: f2dbd84a     	movk	x10, #0xdec2, lsl #32
   96cb8: fd43c520     	ldr	d0, [x9, #0x788]
   96cbc: f2fe402a     	movk	x10, #0xf201, lsl #48
   96cc0: 140000c6     	b	0x96fd8 <.text+0x8e3f8>
   96cc4: 52800048     	mov	w8, #0x2
   96cc8: f00005e9     	adrp	x9, 0x155000
   96ccc: 912a7129     	add	x9, x9, #0xa9c
   96cd0: 889ffd28     	stlr	w8, [x9]
   96cd4: d29ac5a9     	mov	x9, #0xd62d
   96cd8: b85e43a8     	ldur	w8, [x29, #-0x1c]
   96cdc: f2b4e2e9     	movk	x9, #0xa717, lsl #16
   96ce0: f2dad089     	movk	x9, #0xd684, lsl #32
   96ce4: f2eebd49     	movk	x9, #0x75ea, lsl #48
   96ce8: 7100011f     	cmp	w8, #0x0
   96cec: d28061c8     	mov	x8, #0x30e
   96cf0: f2a036a8     	movk	x8, #0x1b5, lsl #16
   96cf4: f2d3dd28     	movk	x8, #0x9ee9, lsl #32
   96cf8: f2f9ee68     	movk	x8, #0xcf73, lsl #48
   96cfc: 9a89010a     	csel	x10, x8, x9, eq
   96d00: 2a1303e8     	mov	w8, w19
   96d04: 17fffdaf     	b	0x963c0 <.text+0x8d7e0>
   96d08: f00005e8     	adrp	x8, 0x155000
   96d0c: d28b9709     	mov	x9, #0x5cb8
   96d10: f2a4f2a9     	movk	x9, #0x2795, lsl #16
   96d14: f2c2be89     	movk	x9, #0x15f4, lsl #32
   96d18: 396a5908     	ldrb	w8, [x8, #0xa96]
   96d1c: f2eef489     	movk	x9, #0x77a4, lsl #48
   96d20: 7100011f     	cmp	w8, #0x0
   96d24: d295f948     	mov	x8, #0xafca
   96d28: f2af8348     	movk	x8, #0x7c1a, lsl #16
   96d2c: f2c3c728     	movk	x8, #0x1e39, lsl #32
   96d30: f2e0de68     	movk	x8, #0x6f3, lsl #48
   96d34: 140000d4     	b	0x97084 <.text+0x8e4a4>
   96d38: d503201f     	nop
   96d3c: 105f6a68     	adr	x8, #0xbed4c
   96d40: d503201f     	nop
   96d44: 105e5261     	adr	x1, #0xbca4c
   96d48: 52800182     	mov	w2, #0xc
   96d4c: 089ffd1f     	stlrb	wzr, [x8]
   96d50: f94017e0     	ldr	x0, [sp, #0x28]
   96d54: 94000b5d     	bl	0x99ac8 <.text+0x90ee8>
   96d58: f00005e8     	adrp	x8, 0x155000
   96d5c: d299bf09     	mov	x9, #0xcdf8
   96d60: f2bae569     	movk	x9, #0xd72b, lsl #16
   96d64: 2a0003fb     	mov	w27, w0
   96d68: f2cab549     	movk	x9, #0x55aa, lsl #32
   96d6c: b94aa508     	ldr	w8, [x8, #0xaa4]
   96d70: f2ffcd69     	movk	x9, #0xfe6b, lsl #48
   96d74: 7100011f     	cmp	w8, #0x0
   96d78: 1a9f07e8     	cset	w8, ne
   96d7c: 2a080008     	orr	w8, w0, w8
   96d80: 7200011f     	tst	w8, #0x1
   96d84: d2810ca8     	mov	x8, #0x865
   96d88: f2aa6c48     	movk	x8, #0x5362, lsl #16
   96d8c: f2d31d48     	movk	x8, #0x98ea, lsl #32
   96d90: f2f57fa8     	movk	x8, #0xabfd, lsl #48
   96d94: 140000ae     	b	0x9704c <.text+0x8e46c>
   96d98: f00005e8     	adrp	x8, 0x155000
   96d9c: d29dc2a9     	mov	x9, #0xee15
   96da0: f2a3fc29     	movk	x9, #0x1fe1, lsl #16
   96da4: f2ca6ec9     	movk	x9, #0x5376, lsl #32
   96da8: b94aa108     	ldr	w8, [x8, #0xaa0]
   96dac: f2ed5529     	movk	x9, #0x6aa9, lsl #48
   96db0: 7100811f     	cmp	w8, #0x20
   96db4: d28227e8     	mov	x8, #0x113f
   96db8: f2b9d5e8     	movk	x8, #0xceaf, lsl #16
   96dbc: f2c9fcc8     	movk	x8, #0x4fe6, lsl #32
   96dc0: f2fd3fe8     	movk	x8, #0xe9ff, lsl #48
   96dc4: 9a89c10a     	csel	x10, x8, x9, gt
   96dc8: 2a1303e8     	mov	w8, w19
   96dcc: 17fffd7d     	b	0x963c0 <.text+0x8d7e0>
   96dd0: f00005e8     	adrp	x8, 0x155000
   96dd4: 396a5d08     	ldrb	w8, [x8, #0xa97]
   96dd8: 7100011f     	cmp	w8, #0x0
   96ddc: d2912548     	mov	x8, #0x892a
   96de0: f2beb128     	movk	x8, #0xf589, lsl #16
   96de4: f2ddc5e8     	movk	x8, #0xee2f, lsl #32
   96de8: f2e49808     	movk	x8, #0x24c0, lsl #48
   96dec: 9a96110a     	csel	x10, x8, x22, ne
   96df0: 2a1303e8     	mov	w8, w19
   96df4: 17fffd73     	b	0x963c0 <.text+0x8d7e0>
   96df8: 2a1f03e0     	mov	w0, wzr
   96dfc: 52800021     	mov	w1, #0x1
   96e00: d503201f     	nop
   96e04: 105f6402     	adr	x2, #0xbec80
   96e08: 9402c576     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   96e0c: d29a5049     	mov	x9, #0xd282
   96e10: 7100001f     	cmp	w0, #0x0
   96e14: f2b2afa9     	movk	x9, #0x957d, lsl #16
   96e18: 2a1303e8     	mov	w8, w19
   96e1c: f2c15ba9     	movk	x9, #0xadd, lsl #32
   96e20: f2ea93e9     	movk	x9, #0x549f, lsl #48
   96e24: 9a8902ea     	csel	x10, x23, x9, eq
   96e28: 17fffd66     	b	0x963c0 <.text+0x8d7e0>
   96e2c: 2a1f03e0     	mov	w0, wzr
   96e30: 52800021     	mov	w1, #0x1
   96e34: d503201f     	nop
   96e38: 105f62a2     	adr	x2, #0xbec54
   96e3c: 9402c569     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   96e40: d280d249     	mov	x9, #0x692
   96e44: d28fbe6a     	mov	x10, #0x7df3
   96e48: f2b100e9     	movk	x9, #0x8807, lsl #16
   96e4c: f2b8100a     	movk	x10, #0xc080, lsl #16
   96e50: f2df7c69     	movk	x9, #0xfbe3, lsl #32
   96e54: f2cb530a     	movk	x10, #0x5a98, lsl #32
   96e58: 7100001f     	cmp	w0, #0x0
   96e5c: f2f43669     	movk	x9, #0xa1b3, lsl #48
   96e60: f2e2e08a     	movk	x10, #0x1704, lsl #48
   96e64: 2a1303e8     	mov	w8, w19
   96e68: 9a89014a     	csel	x10, x10, x9, eq
   96e6c: 17fffd55     	b	0x963c0 <.text+0x8d7e0>
   96e70: d2844288     	mov	x8, #0x2214
   96e74: d2897689     	mov	x9, #0x4bb4
   96e78: f2adcd88     	movk	x8, #0x6e6c, lsl #16
   96e7c: f2a10ee9     	movk	x9, #0x877, lsl #16
   96e80: f2c4e0a8     	movk	x8, #0x2705, lsl #32
   96e84: f2cb2e89     	movk	x9, #0x5974, lsl #32
   96e88: f2e5d348     	movk	x8, #0x2e9a, lsl #48
   96e8c: f2ebdfe9     	movk	x9, #0x5eff, lsl #48
   96e90: 7200027f     	tst	w19, #0x1
   96e94: 1400006e     	b	0x9704c <.text+0x8e46c>
   96e98: d503201f     	nop
   96e9c: 105e47ad     	adr	x13, #0xbc8f4
   96ea0: 394009aa     	ldrb	w10, [x13, #0x2]
   96ea4: 394001a8     	ldrb	w8, [x13]
   96ea8: 394005a9     	ldrb	w9, [x13, #0x1]
   96eac: 521f0d4c     	eor	w12, w10, #0x1e
   96eb0: d298544a     	mov	x10, #0xc2a2
   96eb4: f2a2090a     	movk	x10, #0x1048, lsl #16
   96eb8: 521f0d0b     	eor	w11, w8, #0x1e
   96ebc: f2ce208a     	movk	x10, #0x7104, lsl #32
   96ec0: 521f0d29     	eor	w9, w9, #0x1e
   96ec4: 2a1303e8     	mov	w8, w19
   96ec8: f2f3ffca     	movk	x10, #0x9ffe, lsl #48
   96ecc: 390001ab     	strb	w11, [x13]
   96ed0: 140000a0     	b	0x97150 <.text+0x8e570>
   96ed4: 2a1f03e0     	mov	w0, wzr
   96ed8: 52800021     	mov	w1, #0x1
   96edc: d503201f     	nop
   96ee0: 105f5d42     	adr	x2, #0xbeba8
   96ee4: 9402c53f     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   96ee8: d2827029     	mov	x9, #0x1381
   96eec: d28c98ca     	mov	x10, #0x64c6
   96ef0: f2b4b149     	movk	x9, #0xa58a, lsl #16
   96ef4: f2b69bea     	movk	x10, #0xb4df, lsl #16
   96ef8: f2d6ec69     	movk	x9, #0xb763, lsl #32
   96efc: f2d950ea     	movk	x10, #0xca87, lsl #32
   96f00: 7100001f     	cmp	w0, #0x0
   96f04: f2f779a9     	movk	x9, #0xbbcd, lsl #48
   96f08: f2e2c58a     	movk	x10, #0x162c, lsl #48
   96f0c: 2a1303e8     	mov	w8, w19
   96f10: 9a89014a     	csel	x10, x10, x9, eq
   96f14: 17fffd2b     	b	0x963c0 <.text+0x8d7e0>
   96f18: 2a1f03e0     	mov	w0, wzr
   96f1c: 52800021     	mov	w1, #0x1
   96f20: d503201f     	nop
   96f24: 105f5b22     	adr	x2, #0xbeb64
   96f28: 9402c52e     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   96f2c: d29e47c9     	mov	x9, #0xf23e
   96f30: d280124a     	mov	x10, #0x92
   96f34: f2bd7389     	movk	x9, #0xeb9c, lsl #16
   96f38: f2a2daca     	movk	x10, #0x16d6, lsl #16
   96f3c: f2cccfc9     	movk	x9, #0x667e, lsl #32
   96f40: f2d3a0ca     	movk	x10, #0x9d06, lsl #32
   96f44: 7100001f     	cmp	w0, #0x0
   96f48: f2e0f909     	movk	x9, #0x7c8, lsl #48
   96f4c: f2e4d00a     	movk	x10, #0x2680, lsl #48
   96f50: 2a1303e8     	mov	w8, w19
   96f54: 9a8a012a     	csel	x10, x9, x10, eq
   96f58: 17fffd1a     	b	0x963c0 <.text+0x8d7e0>
   96f5c: d503201f     	nop
   96f60: 105e41ac     	adr	x12, #0xbc834
   96f64: 528016ad     	mov	w13, #0xb5
   96f68: 39400589     	ldrb	w9, [x12, #0x1]
   96f6c: 3940098a     	ldrb	w10, [x12, #0x2]
   96f70: 39400d8b     	ldrb	w11, [x12, #0x3]
   96f74: 39400188     	ldrb	w8, [x12]
   96f78: 4a0d0129     	eor	w9, w9, w13
   96f7c: 4a0d014a     	eor	w10, w10, w13
   96f80: 4a0d016b     	eor	w11, w11, w13
   96f84: 4a0d0108     	eor	w8, w8, w13
   96f88: 39000589     	strb	w9, [x12, #0x1]
   96f8c: 3900098a     	strb	w10, [x12, #0x2]
   96f90: d28a816a     	mov	x10, #0x540b
   96f94: 39000d8b     	strb	w11, [x12, #0x3]
   96f98: 52800029     	mov	w9, #0x1
   96f9c: f00005eb     	adrp	x11, 0x155000
   96fa0: f2abcd4a     	movk	x10, #0x5e6a, lsl #16
   96fa4: f2cbfb8a     	movk	x10, #0x5fdc, lsl #32
   96fa8: 39000188     	strb	w8, [x12]
   96fac: 2a1303e8     	mov	w8, w19
   96fb0: f2f32e8a     	movk	x10, #0x9974, lsl #48
   96fb4: 392a6169     	strb	w9, [x11, #0xa98]
   96fb8: 17fffd02     	b	0x963c0 <.text+0x8d7e0>
   96fbc: b00005e9     	adrp	x9, 0x153000
   96fc0: d28a0f6a     	mov	x10, #0x507b
   96fc4: f2a58a0a     	movk	x10, #0x2c50, lsl #16
   96fc8: 2a1303e8     	mov	w8, w19
   96fcc: f2c9158a     	movk	x10, #0x48ac, lsl #32
   96fd0: fd43c520     	ldr	d0, [x9, #0x788]
   96fd4: f2f9216a     	movk	x10, #0xc90b, lsl #48
   96fd8: 2e291c00     	eor	v0.8b, v0.8b, v9.8b
   96fdc: f00005eb     	adrp	x11, 0x155000
   96fe0: fd03c520     	str	d0, [x9, #0x788]
   96fe4: 52800029     	mov	w9, #0x1
   96fe8: 392a5969     	strb	w9, [x11, #0xa96]
   96fec: 17fffcf5     	b	0x963c0 <.text+0x8d7e0>
   96ff0: d503201f     	nop
   96ff4: 105f5488     	adr	x8, #0xbea90
   96ff8: d503201f     	nop
   96ffc: 105e3c61     	adr	x1, #0xbc78c
   97000: 52800182     	mov	w2, #0xc
   97004: 089ffd1f     	stlrb	wzr, [x8]
   97008: f94017e0     	ldr	x0, [sp, #0x28]
   9700c: 94000aaf     	bl	0x99ac8 <.text+0x90ee8>
   97010: d00005e8     	adrp	x8, 0x155000
   97014: d28981a9     	mov	x9, #0x4c0d
   97018: f2aa5ba9     	movk	x9, #0x52dd, lsl #16
   9701c: b9000fe0     	str	w0, [sp, #0xc]
   97020: f2cfb9e9     	movk	x9, #0x7dcf, lsl #32
   97024: b94aa508     	ldr	w8, [x8, #0xaa4]
   97028: f2e91fc9     	movk	x9, #0x48fe, lsl #48
   9702c: 7100011f     	cmp	w8, #0x0
   97030: 1a9f07e8     	cset	w8, ne
   97034: 2a080008     	orr	w8, w0, w8
   97038: 7200011f     	tst	w8, #0x1
   9703c: d28c86c8     	mov	x8, #0x6436
   97040: f2a50d28     	movk	x8, #0x2869, lsl #16
   97044: f2d8bbe8     	movk	x8, #0xc5df, lsl #32
   97048: f2eadbc8     	movk	x8, #0x56de, lsl #48
   9704c: 9a88112a     	csel	x10, x9, x8, ne
   97050: 2a1303e8     	mov	w8, w19
   97054: 17fffcdb     	b	0x963c0 <.text+0x8d7e0>
   97058: d00005e8     	adrp	x8, 0x155000
   9705c: d29c2349     	mov	x9, #0xe11a
   97060: f2bce0e9     	movk	x9, #0xe707, lsl #16
   97064: f2ca52c9     	movk	x9, #0x5296, lsl #32
   97068: 396a6108     	ldrb	w8, [x8, #0xa98]
   9706c: f2e3be69     	movk	x9, #0x1df3, lsl #48
   97070: 7100011f     	cmp	w8, #0x0
   97074: d2859d88     	mov	x8, #0x2cec
   97078: f2a362c8     	movk	x8, #0x1b16, lsl #16
   9707c: f2d20608     	movk	x8, #0x9030, lsl #32
   97080: f2f6d828     	movk	x8, #0xb6c1, lsl #48
   97084: 9a89110a     	csel	x10, x8, x9, ne
   97088: 2a1303e8     	mov	w8, w19
   9708c: 17fffccd     	b	0x963c0 <.text+0x8d7e0>
   97090: d00005e8     	adrp	x8, 0x155000
   97094: 396a5d08     	ldrb	w8, [x8, #0xa97]
   97098: 7100011f     	cmp	w8, #0x0
   9709c: d2926788     	mov	x8, #0x933c
   970a0: f2a82708     	movk	x8, #0x4138, lsl #16
   970a4: f2d77108     	movk	x8, #0xbb88, lsl #32
   970a8: f2eb8448     	movk	x8, #0x5c22, lsl #48
   970ac: 9a9a110a     	csel	x10, x8, x26, ne
   970b0: 2a1303e8     	mov	w8, w19
   970b4: 17fffcc3     	b	0x963c0 <.text+0x8d7e0>
   970b8: d00005e8     	adrp	x8, 0x155000
   970bc: d29d4249     	mov	x9, #0xea12
   970c0: f2a55909     	movk	x9, #0x2ac8, lsl #16
   970c4: f2c3ac09     	movk	x9, #0x1d60, lsl #32
   970c8: b94aa108     	ldr	w8, [x8, #0xaa0]
   970cc: f2e20469     	movk	x9, #0x1023, lsl #48
   970d0: 7100791f     	cmp	w8, #0x1e
   970d4: d291b0e8     	mov	x8, #0x8d87
   970d8: f2b45e68     	movk	x8, #0xa2f3, lsl #16
   970dc: f2d0c908     	movk	x8, #0x8648, lsl #32
   970e0: f2f4bc68     	movk	x8, #0xa5e3, lsl #48
   970e4: 9a88c12a     	csel	x10, x9, x8, gt
   970e8: 2a1303e8     	mov	w8, w19
   970ec: 17fffcb5     	b	0x963c0 <.text+0x8d7e0>
   970f0: d00005e8     	adrp	x8, 0x155000
   970f4: 396a5908     	ldrb	w8, [x8, #0xa96]
   970f8: 7100011f     	cmp	w8, #0x0
   970fc: d29bf768     	mov	x8, #0xdfbb
   97100: f2bfa808     	movk	x8, #0xfd40, lsl #16
   97104: f2dd5808     	movk	x8, #0xeac0, lsl #32
   97108: f2e39408     	movk	x8, #0x1ca0, lsl #48
   9710c: 9a99110a     	csel	x10, x8, x25, ne
   97110: 2a1303e8     	mov	w8, w19
   97114: 17fffcab     	b	0x963c0 <.text+0x8d7e0>
   97118: d503201f     	nop
   9711c: 105e33ad     	adr	x13, #0xbc674
   97120: 394001a8     	ldrb	w8, [x13]
   97124: 394009aa     	ldrb	w10, [x13, #0x2]
   97128: 394005a9     	ldrb	w9, [x13, #0x1]
   9712c: 521f0d0b     	eor	w11, w8, #0x1e
   97130: 2a1303e8     	mov	w8, w19
   97134: 521f0d4c     	eor	w12, w10, #0x1e
   97138: d280ea8a     	mov	x10, #0x754
   9713c: f2b40f0a     	movk	x10, #0xa078, lsl #16
   97140: 521f0d29     	eor	w9, w9, #0x1e
   97144: f2c3f28a     	movk	x10, #0x1f94, lsl #32
   97148: 390001ab     	strb	w11, [x13]
   9714c: f2e6504a     	movk	x10, #0x3282, lsl #48
   97150: 390005a9     	strb	w9, [x13, #0x1]
   97154: d00005e9     	adrp	x9, 0x155000
   97158: 5280002b     	mov	w11, #0x1
   9715c: 390009ac     	strb	w12, [x13, #0x2]
   97160: 392a5d2b     	strb	w11, [x9, #0xa97]
   97164: 17fffc97     	b	0x963c0 <.text+0x8d7e0>
   97168: d503201f     	nop
   9716c: 105f4908     	adr	x8, #0xbe920
   97170: d503201f     	nop
   97174: 105e3101     	adr	x1, #0xbc620
   97178: 52800182     	mov	w2, #0xc
   9717c: 089ffd1f     	stlrb	wzr, [x8]
   97180: f94017e0     	ldr	x0, [sp, #0x28]
   97184: 94000a51     	bl	0x99ac8 <.text+0x90ee8>
   97188: d2804b29     	mov	x9, #0x259
   9718c: 7200001f     	tst	w0, #0x1
   97190: f2adc549     	movk	x9, #0x6e2a, lsl #16
   97194: 2a1303e8     	mov	w8, w19
   97198: f2d8d969     	movk	x9, #0xc6cb, lsl #32
   9719c: f2e2edc9     	movk	x9, #0x176e, lsl #48
   971a0: 9a98112a     	csel	x10, x9, x24, ne
   971a4: 17fffc87     	b	0x963c0 <.text+0x8d7e0>
   971a8: f94003e8     	ldr	x8, [sp]
   971ac: f9401508     	ldr	x8, [x8, #0x28]
   971b0: f85e83a9     	ldur	x9, [x29, #-0x18]
   971b4: eb09011f     	cmp	x8, x9
   971b8: 54000161     	b.ne	0x971e4 <.text+0x8e604>
   971bc: a94a4ff4     	ldp	x20, x19, [sp, #0xa0]
   971c0: aa1f03e0     	mov	x0, xzr
   971c4: a94957f6     	ldp	x22, x21, [sp, #0x90]
   971c8: a9485ff8     	ldp	x24, x23, [sp, #0x80]
   971cc: a94767fa     	ldp	x26, x25, [sp, #0x70]
   971d0: a9466ffc     	ldp	x28, x27, [sp, #0x60]
   971d4: a9457bfd     	ldp	x29, x30, [sp, #0x50]
   971d8: 6d4423e9     	ldp	d9, d8, [sp, #0x40]
   971dc: 9102c3ff     	add	sp, sp, #0xb0
   971e0: d65f03c0     	ret
   971e4: 9402c60b     	bl	0x148a10 <__stack_chk_fail@plt>
   971e8: d00005e8     	adrp	x8, 0x155000
   971ec: 912a7108     	add	x8, x8, #0xa9c
   971f0: 88dffd08     	ldar	w8, [x8]
   971f4: 7100091f     	cmp	w8, #0x2
   971f8: 1a9f17e0     	cset	w0, eq
   971fc: d65f03c0     	ret
   97200: d101c3ff     	sub	sp, sp, #0x70
   97204: a9017bfd     	stp	x29, x30, [sp, #0x10]
   97208: a9026ffc     	stp	x28, x27, [sp, #0x20]
   9720c: a90367fa     	stp	x26, x25, [sp, #0x30]
   97210: a9045ff8     	stp	x24, x23, [sp, #0x40]
   97214: a90557f6     	stp	x22, x21, [sp, #0x50]
   97218: a9064ff4     	stp	x20, x19, [sp, #0x60]
   9721c: 910043fd     	add	x29, sp, #0x10
   97220: 91008028     	add	x8, x1, #0x20
   97224: d28ffc19     	mov	x25, #0x7fe0
   97228: d28ab45a     	mov	x26, #0x55a2
   9722c: d28caf5c     	mov	x28, #0x657a
   97230: d2981e9b     	mov	x27, #0xc0f4
   97234: d2847f15     	mov	x21, #0x23f8
   97238: a90003e8     	stp	x8, x0, [sp]
   9723c: d2854ef8     	mov	x24, #0x2a77
   97240: d28ffc08     	mov	x8, #0x7fe0
   97244: f2b645b9     	movk	x25, #0xb22d, lsl #16
   97248: f2befb5a     	movk	x26, #0xf7da, lsl #16
   9724c: f2bfb5fc     	movk	x28, #0xfdaf, lsl #16
   97250: f2a0bf3b     	movk	x27, #0x5f9, lsl #16
   97254: f2a9a455     	movk	x21, #0x4d22, lsl #16
   97258: f2be0f18     	movk	x24, #0xf078, lsl #16
   9725c: f2b645a8     	movk	x8, #0xb22d, lsl #16
   97260: f2cd59b9     	movk	x25, #0x6acd, lsl #32
   97264: f2da359a     	movk	x26, #0xd1ac, lsl #32
   97268: f2d3ffbc     	movk	x28, #0x9ffd, lsl #32
   9726c: f2cb685b     	movk	x27, #0x5b42, lsl #32
   97270: f2ce0d55     	movk	x21, #0x706a, lsl #32
   97274: f2d04018     	movk	x24, #0x8200, lsl #32
   97278: f2cd59a8     	movk	x8, #0x6acd, lsl #32
   9727c: aa0103f3     	mov	x19, x1
   97280: f2e5f739     	movk	x25, #0x2fb9, lsl #48
   97284: f2f0f53a     	movk	x26, #0x87a9, lsl #48
   97288: f2f6963c     	movk	x28, #0xb4b1, lsl #48
   9728c: f2f841db     	movk	x27, #0xc20e, lsl #48
   97290: f2fc2095     	movk	x21, #0xe104, lsl #48
   97294: f2e7aa98     	movk	x24, #0x3d54, lsl #48
   97298: f2e5f728     	movk	x8, #0x2fb9, lsl #48
   9729c: eb1a011f     	cmp	x8, x26
   972a0: 54000300     	b.eq	0x97300 <.text+0x8e720>
   972a4: eb1c011f     	cmp	x8, x28
   972a8: 540003e0     	b.eq	0x97324 <.text+0x8e744>
   972ac: eb1b011f     	cmp	x8, x27
   972b0: 54000480     	b.eq	0x97340 <.text+0x8e760>
   972b4: eb15011f     	cmp	x8, x21
   972b8: 54000540     	b.eq	0x97360 <.text+0x8e780>
   972bc: eb19011f     	cmp	x8, x25
   972c0: 54000660     	b.eq	0x9738c <.text+0x8e7ac>
   972c4: eb18011f     	cmp	x8, x24
   972c8: 540006c0     	b.eq	0x973a0 <.text+0x8e7c0>
   972cc: d28500e9     	mov	x9, #0x2807
   972d0: f2b939c9     	movk	x9, #0xc9ce, lsl #16
   972d4: f2cb1509     	movk	x9, #0x58a8, lsl #32
   972d8: f2e86729     	movk	x9, #0x4339, lsl #48
   972dc: eb09011f     	cmp	x8, x9
   972e0: 54000760     	b.eq	0x973cc <.text+0x8e7ec>
   972e4: d2818b29     	mov	x9, #0xc59
   972e8: f2a0d629     	movk	x9, #0x6b1, lsl #16
   972ec: f2d59cc9     	movk	x9, #0xace6, lsl #32
   972f0: f2e62d49     	movk	x9, #0x316a, lsl #48
   972f4: eb09011f     	cmp	x8, x9
   972f8: 54fffd21     	b.ne	0x9729c <.text+0x8e6bc>
   972fc: 1400003e     	b	0x973f4 <.text+0x8e814>
   97300: d00005e8     	adrp	x8, 0x155000
   97304: b94aa514     	ldr	w20, [x8, #0xaa4]
   97308: d28500e8     	mov	x8, #0x2807
   9730c: f2b939c8     	movk	x8, #0xc9ce, lsl #16
   97310: f2cb1508     	movk	x8, #0x58a8, lsl #32
   97314: 7100029f     	cmp	w20, #0x0
   97318: f2e86728     	movk	x8, #0x4339, lsl #48
   9731c: 9a9c0108     	csel	x8, x8, x28, eq
   97320: 17ffffdf     	b	0x9729c <.text+0x8e6bc>
   97324: d2818b28     	mov	x8, #0xc59
   97328: f94007e9     	ldr	x9, [sp, #0x8]
   9732c: f2a0d628     	movk	x8, #0x6b1, lsl #16
   97330: f2d59cc8     	movk	x8, #0xace6, lsl #32
   97334: f2e62d48     	movk	x8, #0x316a, lsl #48
   97338: b9000134     	str	w20, [x9]
   9733c: 17ffffd8     	b	0x9729c <.text+0x8e6bc>
   97340: d2818b28     	mov	x8, #0xc59
   97344: f94007e9     	ldr	x9, [sp, #0x8]
   97348: 5280004a     	mov	w10, #0x2
   9734c: f2a0d628     	movk	x8, #0x6b1, lsl #16
   97350: f2d59cc8     	movk	x8, #0xace6, lsl #32
   97354: f2e62d48     	movk	x8, #0x316a, lsl #48
   97358: b900012a     	str	w10, [x9]
   9735c: 17ffffd0     	b	0x9729c <.text+0x8e6bc>
   97360: d00005e8     	adrp	x8, 0x155000
   97364: aa1703e0     	mov	x0, x23
   97368: aa1603e2     	mov	x2, x22
   9736c: f9456101     	ldr	x1, [x8, #0xac0]
   97370: 9402c60c     	bl	0x148ba0 <memcpy@plt>
   97374: d2818b28     	mov	x8, #0xc59
   97378: f9009676     	str	x22, [x19, #0x128]
   9737c: f2a0d628     	movk	x8, #0x6b1, lsl #16
   97380: f2d59cc8     	movk	x8, #0xace6, lsl #32
   97384: f2e62d48     	movk	x8, #0x316a, lsl #48
   97388: 17ffffc5     	b	0x9729c <.text+0x8e6bc>
   9738c: d00005e8     	adrp	x8, 0x155000
   97390: 396a4108     	ldrb	w8, [x8, #0xa90]
   97394: 7100011f     	cmp	w8, #0x0
   97398: 9a9a1308     	csel	x8, x24, x26, ne
   9739c: 17ffffc0     	b	0x9729c <.text+0x8e6bc>
   973a0: f94003e0     	ldr	x0, [sp]
   973a4: 52800601     	mov	w1, #0x30
   973a8: 9402b38f     	bl	0x1441e4 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x69018>
   973ac: f9407a68     	ldr	x8, [x19, #0xf0]
   973b0: b2400109     	orr	x9, x8, #0x1
   973b4: d2818b28     	mov	x8, #0xc59
   973b8: f2a0d628     	movk	x8, #0x6b1, lsl #16
   973bc: f2d59cc8     	movk	x8, #0xace6, lsl #32
   973c0: f2e62d48     	movk	x8, #0x316a, lsl #48
   973c4: f9007a69     	str	x9, [x19, #0xf0]
   973c8: 17ffffb5     	b	0x9729c <.text+0x8e6bc>
   973cc: d00005e8     	adrp	x8, 0x155000
   973d0: 52800021     	mov	w1, #0x1
   973d4: f9455d16     	ldr	x22, [x8, #0xab8]
   973d8: aa1603e0     	mov	x0, x22
   973dc: 9402c5ed     	bl	0x148b90 <calloc@plt>
   973e0: f100001f     	cmp	x0, #0x0
   973e4: aa0003f7     	mov	x23, x0
   973e8: 9a950368     	csel	x8, x27, x21, eq
   973ec: f9009a60     	str	x0, [x19, #0x130]
   973f0: 17ffffab     	b	0x9729c <.text+0x8e6bc>
   973f4: a9464ff4     	ldp	x20, x19, [sp, #0x60]
   973f8: a94557f6     	ldp	x22, x21, [sp, #0x50]
   973fc: a9445ff8     	ldp	x24, x23, [sp, #0x40]
   97400: a94367fa     	ldp	x26, x25, [sp, #0x30]
   97404: a9426ffc     	ldp	x28, x27, [sp, #0x20]
   97408: a9417bfd     	ldp	x29, x30, [sp, #0x10]
   9740c: 9101c3ff     	add	sp, sp, #0x70
   97410: d65f03c0     	ret
   97414: a9ba7bfd     	stp	x29, x30, [sp, #-0x60]!
   97418: a9016ffc     	stp	x28, x27, [sp, #0x10]
   9741c: a90267fa     	stp	x26, x25, [sp, #0x20]
   97420: a9035ff8     	stp	x24, x23, [sp, #0x30]
   97424: a90457f6     	stp	x22, x21, [sp, #0x40]
   97428: a9054ff4     	stp	x20, x19, [sp, #0x50]
   9742c: 910003fd     	mov	x29, sp
   97430: d101c3ff     	sub	sp, sp, #0x70
   97434: b81a43a5     	stur	w5, [x29, #-0x5c]
   97438: d2829db5     	mov	x21, #0x14ed
   9743c: f81c83a3     	stur	x3, [x29, #-0x38]
   97440: d296bfbb     	mov	x27, #0xb5fd
   97444: a93e8ba0     	stp	x0, x2, [x29, #-0x18]
   97448: d29bc117     	mov	x23, #0xde08
   9744c: f81d83a1     	stur	x1, [x29, #-0x28]
   97450: d53bd048     	mrs	x8, TPIDR_EL0
   97454: a93913a8     	stp	x8, x4, [x29, #-0x70]
   97458: d288fbd9     	mov	x25, #0x47de
   9745c: f9401508     	ldr	x8, [x8, #0x28]
   97460: d293b9fa     	mov	x26, #0x9dcf
   97464: d28e18d3     	mov	x19, #0x70c6
   97468: d29b79d4     	mov	x20, #0xdbce
   9746c: d287e1f8     	mov	x24, #0x3f0f
   97470: d2806796     	mov	x22, #0x33c
   97474: d281bf7c     	mov	x28, #0xdfb
   97478: d296aeae     	mov	x14, #0xb575
   9747c: d29ac66f     	mov	x15, #0xd633
   97480: d29bc109     	mov	x9, #0xde08
   97484: f2a1da15     	movk	x21, #0xed0, lsl #16
   97488: f81f83a8     	stur	x8, [x29, #-0x8]
   9748c: f2abd9bb     	movk	x27, #0x5ecd, lsl #16
   97490: f2b92137     	movk	x23, #0xc909, lsl #16
   97494: f2be6db9     	movk	x25, #0xf36d, lsl #16
   97498: f2a6121a     	movk	x26, #0x3090, lsl #16
   9749c: f2b0e473     	movk	x19, #0x8723, lsl #16
   974a0: f2a6af14     	movk	x20, #0x3578, lsl #16
   974a4: f2aec878     	movk	x24, #0x7643, lsl #16
   974a8: f2ab1dd6     	movk	x22, #0x58ee, lsl #16
   974ac: f2a52b1c     	movk	x28, #0x2958, lsl #16
   974b0: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   974b4: f2aeccef     	movk	x15, #0x7667, lsl #16
   974b8: f2b92129     	movk	x9, #0xc909, lsl #16
   974bc: f2c723d5     	movk	x21, #0x391e, lsl #32
   974c0: f2c21a9b     	movk	x27, #0x10d4, lsl #32
   974c4: f2c66877     	movk	x23, #0x3343, lsl #32
   974c8: f2dc2b39     	movk	x25, #0xe159, lsl #32
   974cc: f2d08dda     	movk	x26, #0x846e, lsl #32
   974d0: f2d324d3     	movk	x19, #0x9926, lsl #32
   974d4: f2cc3b54     	movk	x20, #0x61da, lsl #32
   974d8: f2df2f58     	movk	x24, #0xf97a, lsl #32
   974dc: f2c45e76     	movk	x22, #0x22f3, lsl #32
   974e0: f2d3f0fc     	movk	x28, #0x9f87, lsl #32
   974e4: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   974e8: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   974ec: f2c66869     	movk	x9, #0x3343, lsl #32
   974f0: f2ff58b5     	movk	x21, #0xfac5, lsl #48
   974f4: f2f82a1b     	movk	x27, #0xc150, lsl #48
   974f8: f2f4f497     	movk	x23, #0xa7a4, lsl #48
   974fc: f2f16899     	movk	x25, #0x8b44, lsl #48
   97500: f2f1e91a     	movk	x26, #0x8f48, lsl #48
   97504: f2f33e73     	movk	x19, #0x99f3, lsl #48
   97508: f2f3be54     	movk	x20, #0x9df2, lsl #48
   9750c: f2f3cdb8     	movk	x24, #0x9e6d, lsl #48
   97510: f2f4a416     	movk	x22, #0xa520, lsl #48
   97514: f2fab6bc     	movk	x28, #0xd5b5, lsl #48
   97518: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   9751c: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97520: f2f4f489     	movk	x9, #0xa7a4, lsl #48
   97524: aa0903e8     	mov	x8, x9
   97528: d2977029     	mov	x9, #0xbb81
   9752c: f2b1b469     	movk	x9, #0x8da3, lsl #16
   97530: eb19011f     	cmp	x8, x25
   97534: f2ce7109     	movk	x9, #0x7388, lsl #32
   97538: f2ecab69     	movk	x9, #0x655b, lsl #48
   9753c: 54ffff40     	b.eq	0x97524 <.text+0x8e944>
   97540: d296bfa9     	mov	x9, #0xb5fd
   97544: eb1a011f     	cmp	x8, x26
   97548: f2abd9a9     	movk	x9, #0x5ecd, lsl #16
   9754c: f2c21a89     	movk	x9, #0x10d4, lsl #32
   97550: f2f82a09     	movk	x9, #0xc150, lsl #48
   97554: 54fffe80     	b.eq	0x97524 <.text+0x8e944>
   97558: eb13011f     	cmp	x8, x19
   9755c: 54002240     	b.eq	0x979a4 <.text+0x8edc4>
   97560: d28ce749     	mov	x9, #0x673a
   97564: eb14011f     	cmp	x8, x20
   97568: f2b0d329     	movk	x9, #0x8699, lsl #16
   9756c: f2c913a9     	movk	x9, #0x489d, lsl #32
   97570: f2e08ba9     	movk	x9, #0x45d, lsl #48
   97574: 54fffd80     	b.eq	0x97524 <.text+0x8e944>
   97578: eb18011f     	cmp	x8, x24
   9757c: 54001d40     	b.eq	0x97924 <.text+0x8ed44>
   97580: eb16011f     	cmp	x8, x22
   97584: 54004ba0     	b.eq	0x97ef8 <.text+0x8f318>
   97588: d29e0729     	mov	x9, #0xf039
   9758c: eb17011f     	cmp	x8, x23
   97590: f2a866c9     	movk	x9, #0x4336, lsl #16
   97594: f2df8c49     	movk	x9, #0xfc62, lsl #32
   97598: f2fa0f09     	movk	x9, #0xd078, lsl #48
   9759c: 54fffc40     	b.eq	0x97524 <.text+0x8e944>
   975a0: eb1b011f     	cmp	x8, x27
   975a4: 54002fc0     	b.eq	0x97b9c <.text+0x8efbc>
   975a8: d288ca89     	mov	x9, #0x4654
   975ac: f2ada089     	movk	x9, #0x6d04, lsl #16
   975b0: f2d81a29     	movk	x9, #0xc0d1, lsl #32
   975b4: f2f9e189     	movk	x9, #0xcf0c, lsl #48
   975b8: eb09011f     	cmp	x8, x9
   975bc: 54002320     	b.eq	0x97a20 <.text+0x8ee40>
   975c0: d29e0729     	mov	x9, #0xf039
   975c4: f2a866c9     	movk	x9, #0x4336, lsl #16
   975c8: f2df8c49     	movk	x9, #0xfc62, lsl #32
   975cc: f2fa0f09     	movk	x9, #0xd078, lsl #48
   975d0: eb09011f     	cmp	x8, x9
   975d4: 54002720     	b.eq	0x97ab8 <.text+0x8eed8>
   975d8: eb1c011f     	cmp	x8, x28
   975dc: 54fffa40     	b.eq	0x97524 <.text+0x8e944>
   975e0: d29c3809     	mov	x9, #0xe1c0
   975e4: f2a8a829     	movk	x9, #0x4541, lsl #16
   975e8: f2da79a9     	movk	x9, #0xd3cd, lsl #32
   975ec: f2fb1e09     	movk	x9, #0xd8f0, lsl #48
   975f0: eb09011f     	cmp	x8, x9
   975f4: 54004180     	b.eq	0x97e24 <.text+0x8f244>
   975f8: d2946c29     	mov	x9, #0xa361
   975fc: f2a64929     	movk	x9, #0x3249, lsl #16
   97600: f2db5209     	movk	x9, #0xda90, lsl #32
   97604: f2fca449     	movk	x9, #0xe522, lsl #48
   97608: eb09011f     	cmp	x8, x9
   9760c: d2953449     	mov	x9, #0xa9a2
   97610: f2b84809     	movk	x9, #0xc240, lsl #16
   97614: f2cfb289     	movk	x9, #0x7d94, lsl #32
   97618: f2fd2529     	movk	x9, #0xe929, lsl #48
   9761c: fa491104     	ccmp	x8, x9, #0x4, ne
   97620: d28c69c9     	mov	x9, #0x634e
   97624: f2bc3229     	movk	x9, #0xe191, lsl #16
   97628: f2c343a9     	movk	x9, #0x1a1d, lsl #32
   9762c: f2ff1389     	movk	x9, #0xf89c, lsl #48
   97630: 54fff7a0     	b.eq	0x97524 <.text+0x8e944>
   97634: eb0e011f     	cmp	x8, x14
   97638: 54004f40     	b.eq	0x98020 <.text+0x8f440>
   9763c: d2906169     	mov	x9, #0x830b
   97640: eb0f011f     	cmp	x8, x15
   97644: f2b51dc9     	movk	x9, #0xa8ee, lsl #16
   97648: f2d204e9     	movk	x9, #0x9027, lsl #32
   9764c: f2ef6fc9     	movk	x9, #0x7b7e, lsl #48
   97650: 54fff6a0     	b.eq	0x97524 <.text+0x8e944>
   97654: d28c69c9     	mov	x9, #0x634e
   97658: d298cbea     	mov	x10, #0xc65f
   9765c: f2bc3229     	movk	x9, #0xe191, lsl #16
   97660: f2ae378a     	movk	x10, #0x71bc, lsl #16
   97664: f2c343a9     	movk	x9, #0x1a1d, lsl #32
   97668: f2c3852a     	movk	x10, #0x1c29, lsl #32
   9766c: f2ff1389     	movk	x9, #0xf89c, lsl #48
   97670: f2fe8f8a     	movk	x10, #0xf47c, lsl #48
   97674: eb0a011f     	cmp	x8, x10
   97678: 54fff560     	b.eq	0x97524 <.text+0x8e944>
   9767c: d2943369     	mov	x9, #0xa19b
   97680: f2bd12e9     	movk	x9, #0xe897, lsl #16
   97684: f2c93b89     	movk	x9, #0x49dc, lsl #32
   97688: f2fef1a9     	movk	x9, #0xf78d, lsl #48
   9768c: eb09011f     	cmp	x8, x9
   97690: 54004ec0     	b.eq	0x98068 <.text+0x8f488>
   97694: d28c69c9     	mov	x9, #0x634e
   97698: f2bc3229     	movk	x9, #0xe191, lsl #16
   9769c: f2c343a9     	movk	x9, #0x1a1d, lsl #32
   976a0: f2ff1389     	movk	x9, #0xf89c, lsl #48
   976a4: eb09011f     	cmp	x8, x9
   976a8: 54003440     	b.eq	0x97d30 <.text+0x8f150>
   976ac: eb15011f     	cmp	x8, x21
   976b0: 54002460     	b.eq	0x97b3c <.text+0x8ef5c>
   976b4: d28ce749     	mov	x9, #0x673a
   976b8: f2b0d329     	movk	x9, #0x8699, lsl #16
   976bc: f2c913a9     	movk	x9, #0x489d, lsl #32
   976c0: f2e08ba9     	movk	x9, #0x45d, lsl #48
   976c4: eb09011f     	cmp	x8, x9
   976c8: 54001bc0     	b.eq	0x97a40 <.text+0x8ee60>
   976cc: d288ca89     	mov	x9, #0x4654
   976d0: d29b9c6a     	mov	x10, #0xdce3
   976d4: f2ada089     	movk	x9, #0x6d04, lsl #16
   976d8: f2bcc34a     	movk	x10, #0xe61a, lsl #16
   976dc: f2d81a29     	movk	x9, #0xc0d1, lsl #32
   976e0: f2cdf08a     	movk	x10, #0x6f84, lsl #32
   976e4: f2f9e189     	movk	x9, #0xcf0c, lsl #48
   976e8: f2e08cea     	movk	x10, #0x467, lsl #48
   976ec: eb0a011f     	cmp	x8, x10
   976f0: 54fff1a0     	b.eq	0x97524 <.text+0x8e944>
   976f4: d2855ba9     	mov	x9, #0x2add
   976f8: f2a28549     	movk	x9, #0x142a, lsl #16
   976fc: f2da4109     	movk	x9, #0xd208, lsl #32
   97700: f2e1bcc9     	movk	x9, #0xde6, lsl #48
   97704: eb09011f     	cmp	x8, x9
   97708: 54002000     	b.eq	0x97b08 <.text+0x8ef28>
   9770c: d294f229     	mov	x9, #0xa791
   97710: d284114a     	mov	x10, #0x208a
   97714: f2a788e9     	movk	x9, #0x3c47, lsl #16
   97718: f2a08b8a     	movk	x10, #0x45c, lsl #16
   9771c: f2cbcca9     	movk	x9, #0x5e65, lsl #32
   97720: f2d6488a     	movk	x10, #0xb244, lsl #32
   97724: f2eaa969     	movk	x9, #0x554b, lsl #48
   97728: f2e30eca     	movk	x10, #0x1876, lsl #48
   9772c: eb0a011f     	cmp	x8, x10
   97730: 54ffefa0     	b.eq	0x97524 <.text+0x8e944>
   97734: d28d8f69     	mov	x9, #0x6c7b
   97738: f2bb76c9     	movk	x9, #0xdbb6, lsl #16
   9773c: f2c0c2a9     	movk	x9, #0x615, lsl #32
   97740: f2e32089     	movk	x9, #0x1904, lsl #48
   97744: eb09011f     	cmp	x8, x9
   97748: 54002a60     	b.eq	0x97c94 <.text+0x8f0b4>
   9774c: d298e109     	mov	x9, #0xc708
   97750: f2a4fb09     	movk	x9, #0x27d8, lsl #16
   97754: f2cd29e9     	movk	x9, #0x694f, lsl #32
   97758: f2e3cdc9     	movk	x9, #0x1e6e, lsl #48
   9775c: eb09011f     	cmp	x8, x9
   97760: 54003a80     	b.eq	0x97eb0 <.text+0x8f2d0>
   97764: d28c69c9     	mov	x9, #0x634e
   97768: d296aa0a     	mov	x10, #0xb550
   9776c: f2bc3229     	movk	x9, #0xe191, lsl #16
   97770: f2aa38aa     	movk	x10, #0x51c5, lsl #16
   97774: f2c343a9     	movk	x9, #0x1a1d, lsl #32
   97778: f2d3af8a     	movk	x10, #0x9d7c, lsl #32
   9777c: f2ff1389     	movk	x9, #0xf89c, lsl #48
   97780: f2e4902a     	movk	x10, #0x2481, lsl #48
   97784: eb0a011f     	cmp	x8, x10
   97788: 54ffece0     	b.eq	0x97524 <.text+0x8e944>
   9778c: d2800ae9     	mov	x9, #0x57
   97790: f2a861e9     	movk	x9, #0x430f, lsl #16
   97794: f2c2d869     	movk	x9, #0x16c3, lsl #32
   97798: f2e49f09     	movk	x9, #0x24f8, lsl #48
   9779c: eb09011f     	cmp	x8, x9
   977a0: 54004020     	b.eq	0x97fa4 <.text+0x8f3c4>
   977a4: d28c69c9     	mov	x9, #0x634e
   977a8: d29af76a     	mov	x10, #0xd7bb
   977ac: f2bc3229     	movk	x9, #0xe191, lsl #16
   977b0: f2bb3f2a     	movk	x10, #0xd9f9, lsl #16
   977b4: f2c343a9     	movk	x9, #0x1a1d, lsl #32
   977b8: f2c1ffaa     	movk	x10, #0xffd, lsl #32
   977bc: f2ff1389     	movk	x9, #0xf89c, lsl #48
   977c0: f2e605ca     	movk	x10, #0x302e, lsl #48
   977c4: eb0a011f     	cmp	x8, x10
   977c8: 54ffeae0     	b.eq	0x97524 <.text+0x8e944>
   977cc: d280ca09     	mov	x9, #0x650
   977d0: f2a7c849     	movk	x9, #0x3e42, lsl #16
   977d4: f2dbca09     	movk	x9, #0xde50, lsl #32
   977d8: f2e60969     	movk	x9, #0x304b, lsl #48
   977dc: eb09011f     	cmp	x8, x9
   977e0: 540040e0     	b.eq	0x97ffc <.text+0x8f41c>
   977e4: d29e6449     	mov	x9, #0xf322
   977e8: d28edf8a     	mov	x10, #0x76fc
   977ec: f2b2bd69     	movk	x9, #0x95eb, lsl #16
   977f0: f2aa568a     	movk	x10, #0x52b4, lsl #16
   977f4: f2c33c89     	movk	x9, #0x19e4, lsl #32
   977f8: f2db566a     	movk	x10, #0xdab3, lsl #32
   977fc: f2e03269     	movk	x9, #0x193, lsl #48
   97800: f2e89dca     	movk	x10, #0x44ee, lsl #48
   97804: eb0a011f     	cmp	x8, x10
   97808: 54ffe8e0     	b.eq	0x97524 <.text+0x8e944>
   9780c: d2829da9     	mov	x9, #0x14ed
   97810: d28bcbaa     	mov	x10, #0x5e5d
   97814: f2a1da09     	movk	x9, #0xed0, lsl #16
   97818: f2bcddca     	movk	x10, #0xe6ee, lsl #16
   9781c: f2c723c9     	movk	x9, #0x391e, lsl #32
   97820: f2d9b34a     	movk	x10, #0xcd9a, lsl #32
   97824: f2ff58a9     	movk	x9, #0xfac5, lsl #48
   97828: f2e8a1ea     	movk	x10, #0x450f, lsl #48
   9782c: eb0a011f     	cmp	x8, x10
   97830: 54ffe7a0     	b.eq	0x97524 <.text+0x8e944>
   97834: d294f229     	mov	x9, #0xa791
   97838: f2a788e9     	movk	x9, #0x3c47, lsl #16
   9783c: f2cbcca9     	movk	x9, #0x5e65, lsl #32
   97840: f2eaa969     	movk	x9, #0x554b, lsl #48
   97844: eb09011f     	cmp	x8, x9
   97848: 540037e0     	b.eq	0x97f44 <.text+0x8f364>
   9784c: d297b2ca     	mov	x10, #0xbd96
   97850: f2a9736a     	movk	x10, #0x4b9b, lsl #16
   97854: f2d288aa     	movk	x10, #0x9445, lsl #32
   97858: f2eb8b0a     	movk	x10, #0x5c58, lsl #48
   9785c: eb0a011f     	cmp	x8, x10
   97860: 54ffe620     	b.eq	0x97524 <.text+0x8e944>
   97864: d297e2c9     	mov	x9, #0xbf16
   97868: f2b6e789     	movk	x9, #0xb73c, lsl #16
   9786c: f2d1a349     	movk	x9, #0x8d1a, lsl #32
   97870: f2ec6949     	movk	x9, #0x634a, lsl #48
   97874: eb09011f     	cmp	x8, x9
   97878: 540030e0     	b.eq	0x97e94 <.text+0x8f2b4>
   9787c: d28c7c09     	mov	x9, #0x63e0
   97880: f2b2b109     	movk	x9, #0x9588, lsl #16
   97884: f2d56a09     	movk	x9, #0xab50, lsl #32
   97888: f2eca4a9     	movk	x9, #0x6525, lsl #48
   9788c: eb09011f     	cmp	x8, x9
   97890: 540021c0     	b.eq	0x97cc8 <.text+0x8f0e8>
   97894: d2977029     	mov	x9, #0xbb81
   97898: f2b1b469     	movk	x9, #0x8da3, lsl #16
   9789c: f2ce7109     	movk	x9, #0x7388, lsl #32
   978a0: f2ecab69     	movk	x9, #0x655b, lsl #48
   978a4: eb09011f     	cmp	x8, x9
   978a8: 54002a40     	b.eq	0x97df0 <.text+0x8f210>
   978ac: d28c69c9     	mov	x9, #0x634e
   978b0: d2802f0a     	mov	x10, #0x178
   978b4: f2bc3229     	movk	x9, #0xe191, lsl #16
   978b8: f2adc36a     	movk	x10, #0x6e1b, lsl #16
   978bc: f2c343a9     	movk	x9, #0x1a1d, lsl #32
   978c0: f2c0142a     	movk	x10, #0xa1, lsl #32
   978c4: f2ff1389     	movk	x9, #0xf89c, lsl #48
   978c8: f2ee13aa     	movk	x10, #0x709d, lsl #48
   978cc: eb0a011f     	cmp	x8, x10
   978d0: 54ffe2a0     	b.eq	0x97524 <.text+0x8e944>
   978d4: d2906169     	mov	x9, #0x830b
   978d8: f2b51dc9     	movk	x9, #0xa8ee, lsl #16
   978dc: f2d204e9     	movk	x9, #0x9027, lsl #32
   978e0: f2ef6fc9     	movk	x9, #0x7b7e, lsl #48
   978e4: eb09011f     	cmp	x8, x9
   978e8: 54002680     	b.eq	0x97db8 <.text+0x8f1d8>
   978ec: d29ca4c9     	mov	x9, #0xe526
   978f0: f2b8ee89     	movk	x9, #0xc774, lsl #16
   978f4: f2d559e9     	movk	x9, #0xaacf, lsl #32
   978f8: f2efb1e9     	movk	x9, #0x7d8f, lsl #48
   978fc: eb09011f     	cmp	x8, x9
   97900: 54002280     	b.eq	0x97d50 <.text+0x8f170>
   97904: d29e644a     	mov	x10, #0xf322
   97908: aa0803e9     	mov	x9, x8
   9790c: f2b2bd6a     	movk	x10, #0x95eb, lsl #16
   97910: f2c33c8a     	movk	x10, #0x19e4, lsl #32
   97914: f2e0326a     	movk	x10, #0x193, lsl #48
   97918: eb0a011f     	cmp	x8, x10
   9791c: 54ffe041     	b.ne	0x97524 <.text+0x8e944>
   97920: 140001db     	b	0x9808c <.text+0x8f4ac>
   97924: a97e57a8     	ldp	x8, x21, [x29, #-0x20]
   97928: 528000a4     	mov	w4, #0x5
   9792c: f85d83a1     	ldur	x1, [x29, #-0x28]
   97930: f85f03a2     	ldur	x2, [x29, #-0x10]
   97934: f9400103     	ldr	x3, [x8]
   97938: aa1503e0     	mov	x0, x21
   9793c: f85a83a5     	ldur	x5, [x29, #-0x58]
   97940: 94003df8     	bl	0xa7120 <.text+0x9e540>
   97944: b94002a8     	ldr	w8, [x21]
   97948: d28c7c09     	mov	x9, #0x63e0
   9794c: d29ac66f     	mov	x15, #0xd633
   97950: d296aeae     	mov	x14, #0xb575
   97954: d2829db5     	mov	x21, #0x14ed
   97958: f2b2b109     	movk	x9, #0x9588, lsl #16
   9795c: 7100011f     	cmp	w8, #0x0
   97960: d2953448     	mov	x8, #0xa9a2
   97964: f2b84808     	movk	x8, #0xc240, lsl #16
   97968: f2aeccef     	movk	x15, #0x7667, lsl #16
   9796c: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97970: f2a1da15     	movk	x21, #0xed0, lsl #16
   97974: f2cfb288     	movk	x8, #0x7d94, lsl #32
   97978: f2d56a09     	movk	x9, #0xab50, lsl #32
   9797c: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97980: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97984: f2c723d5     	movk	x21, #0x391e, lsl #32
   97988: f2fd2528     	movk	x8, #0xe929, lsl #48
   9798c: f2eca4a9     	movk	x9, #0x6525, lsl #48
   97990: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97994: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97998: f2ff58b5     	movk	x21, #0xfac5, lsl #48
   9799c: 9a880129     	csel	x9, x9, x8, eq
   979a0: 17fffee1     	b	0x97524 <.text+0x8e944>
   979a4: a97e57a8     	ldp	x8, x21, [x29, #-0x20]
   979a8: 52800024     	mov	w4, #0x1
   979ac: f85d83a1     	ldur	x1, [x29, #-0x28]
   979b0: f85f03a2     	ldur	x2, [x29, #-0x10]
   979b4: f9400103     	ldr	x3, [x8]
   979b8: aa1503e0     	mov	x0, x21
   979bc: 940044c9     	bl	0xa8ce0 <.text+0xa0100>
   979c0: b94002a8     	ldr	w8, [x21]
   979c4: d29c3809     	mov	x9, #0xe1c0
   979c8: d29ac66f     	mov	x15, #0xd633
   979cc: d296aeae     	mov	x14, #0xb575
   979d0: d2829db5     	mov	x21, #0x14ed
   979d4: f2a8a829     	movk	x9, #0x4541, lsl #16
   979d8: 7100011f     	cmp	w8, #0x0
   979dc: d298cbe8     	mov	x8, #0xc65f
   979e0: f2ae3788     	movk	x8, #0x71bc, lsl #16
   979e4: f2aeccef     	movk	x15, #0x7667, lsl #16
   979e8: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   979ec: f2a1da15     	movk	x21, #0xed0, lsl #16
   979f0: f2c38528     	movk	x8, #0x1c29, lsl #32
   979f4: f2da79a9     	movk	x9, #0xd3cd, lsl #32
   979f8: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   979fc: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97a00: f2c723d5     	movk	x21, #0x391e, lsl #32
   97a04: f2fe8f88     	movk	x8, #0xf47c, lsl #48
   97a08: f2fb1e09     	movk	x9, #0xd8f0, lsl #48
   97a0c: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97a10: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97a14: f2ff58b5     	movk	x21, #0xfac5, lsl #48
   97a18: 9a880129     	csel	x9, x9, x8, eq
   97a1c: 17fffec2     	b	0x97524 <.text+0x8e944>
   97a20: d2829da9     	mov	x9, #0x14ed
   97a24: d503201f     	nop
   97a28: 105f0268     	adr	x8, #0xbe04c
   97a2c: f2a1da09     	movk	x9, #0xed0, lsl #16
   97a30: f2c723c9     	movk	x9, #0x391e, lsl #32
   97a34: f2ff58a9     	movk	x9, #0xfac5, lsl #48
   97a38: 089ffd1f     	stlrb	wzr, [x8]
   97a3c: 17fffeba     	b	0x97524 <.text+0x8e944>
   97a40: d503201f     	nop
   97a44: 105f01a8     	adr	x8, #0xbe034
   97a48: d503201f     	nop
   97a4c: 105de423     	adr	x3, #0xbbc84
   97a50: 089ffd1f     	stlrb	wzr, [x8]
   97a54: a97e8bb5     	ldp	x21, x2, [x29, #-0x18]
   97a58: a97d97a1     	ldp	x1, x5, [x29, #-0x28]
   97a5c: aa1503e0     	mov	x0, x21
   97a60: b85a43a4     	ldur	w4, [x29, #-0x5c]
   97a64: 94003748     	bl	0xa5784 <.text+0x9cba4>
   97a68: b94002a8     	ldr	w8, [x21]
   97a6c: d29ac66f     	mov	x15, #0xd633
   97a70: d296aeae     	mov	x14, #0xb575
   97a74: d2829db5     	mov	x21, #0x14ed
   97a78: f2aeccef     	movk	x15, #0x7667, lsl #16
   97a7c: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97a80: 7100011f     	cmp	w8, #0x0
   97a84: d296aa08     	mov	x8, #0xb550
   97a88: f2aa38a8     	movk	x8, #0x51c5, lsl #16
   97a8c: f2a1da15     	movk	x21, #0xed0, lsl #16
   97a90: f2d3af88     	movk	x8, #0x9d7c, lsl #32
   97a94: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97a98: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97a9c: f2c723d5     	movk	x21, #0x391e, lsl #32
   97aa0: f2e49028     	movk	x8, #0x2481, lsl #48
   97aa4: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97aa8: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97aac: f2ff58b5     	movk	x21, #0xfac5, lsl #48
   97ab0: 9a880269     	csel	x9, x19, x8, eq
   97ab4: 17fffe9c     	b	0x97524 <.text+0x8e944>
   97ab8: 2a1f03e0     	mov	w0, wzr
   97abc: 52800021     	mov	w1, #0x1
   97ac0: d503201f     	nop
   97ac4: 105efd82     	adr	x2, #0xbdfb0
   97ac8: 9402c246     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   97acc: d2855ba8     	mov	x8, #0x2add
   97ad0: d29ac66f     	mov	x15, #0xd633
   97ad4: d296aeae     	mov	x14, #0xb575
   97ad8: f2a28548     	movk	x8, #0x142a, lsl #16
   97adc: f2aeccef     	movk	x15, #0x7667, lsl #16
   97ae0: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97ae4: f2da4108     	movk	x8, #0xd208, lsl #32
   97ae8: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97aec: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97af0: 7100001f     	cmp	w0, #0x0
   97af4: f2e1bcc8     	movk	x8, #0xde6, lsl #48
   97af8: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97afc: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97b00: 9a9c0109     	csel	x9, x8, x28, eq
   97b04: 17fffe88     	b	0x97524 <.text+0x8e944>
   97b08: d00005e8     	adrp	x8, 0x155000
   97b0c: d28d8f69     	mov	x9, #0x6c7b
   97b10: f2bb76c9     	movk	x9, #0xdbb6, lsl #16
   97b14: f2c0c2a9     	movk	x9, #0x615, lsl #32
   97b18: 396a4908     	ldrb	w8, [x8, #0xa92]
   97b1c: f2e32089     	movk	x9, #0x1904, lsl #48
   97b20: 7100011f     	cmp	w8, #0x0
   97b24: d29b9c68     	mov	x8, #0xdce3
   97b28: f2bcc348     	movk	x8, #0xe61a, lsl #16
   97b2c: f2cdf088     	movk	x8, #0x6f84, lsl #32
   97b30: f2e08ce8     	movk	x8, #0x467, lsl #48
   97b34: 9a891109     	csel	x9, x8, x9, ne
   97b38: 17fffe7b     	b	0x97524 <.text+0x8e944>
   97b3c: 2a1f03e0     	mov	w0, wzr
   97b40: 52800021     	mov	w1, #0x1
   97b44: d503201f     	nop
   97b48: 105ef942     	adr	x2, #0xbdf28
   97b4c: 9402c225     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   97b50: d2943368     	mov	x8, #0xa19b
   97b54: d28bcba9     	mov	x9, #0x5e5d
   97b58: d29ac66f     	mov	x15, #0xd633
   97b5c: d296aeae     	mov	x14, #0xb575
   97b60: f2bd12e8     	movk	x8, #0xe897, lsl #16
   97b64: f2bcddc9     	movk	x9, #0xe6ee, lsl #16
   97b68: f2aeccef     	movk	x15, #0x7667, lsl #16
   97b6c: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97b70: f2c93b88     	movk	x8, #0x49dc, lsl #32
   97b74: f2d9b349     	movk	x9, #0xcd9a, lsl #32
   97b78: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97b7c: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97b80: 7100001f     	cmp	w0, #0x0
   97b84: f2fef1a8     	movk	x8, #0xf78d, lsl #48
   97b88: f2e8a1e9     	movk	x9, #0x450f, lsl #48
   97b8c: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97b90: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97b94: 9a890109     	csel	x9, x8, x9, eq
   97b98: 17fffe63     	b	0x97524 <.text+0x8e944>
   97b9c: d503201f     	nop
   97ba0: 105ef688     	adr	x8, #0xbded0
   97ba4: 089ffd1f     	stlrb	wzr, [x8]
   97ba8: 910003e8     	mov	x8, sp
   97bac: d1004109     	sub	x9, x8, #0x10
   97bb0: f81e03a9     	stur	x9, [x29, #-0x20]
   97bb4: 9100013f     	mov	sp, x9
   97bb8: 910003e9     	mov	x9, sp
   97bbc: d100412a     	sub	x10, x9, #0x10
   97bc0: f81d03aa     	stur	x10, [x29, #-0x30]
   97bc4: 9100015f     	mov	sp, x10
   97bc8: 910003ea     	mov	x10, sp
   97bcc: d100414b     	sub	x11, x10, #0x10
   97bd0: f81b03ab     	stur	x11, [x29, #-0x50]
   97bd4: 9100017f     	mov	sp, x11
   97bd8: 910003eb     	mov	x11, sp
   97bdc: d100416c     	sub	x12, x11, #0x10
   97be0: f81a83ac     	stur	x12, [x29, #-0x58]
   97be4: 9100019f     	mov	sp, x12
   97be8: a97e8bb5     	ldp	x21, x2, [x29, #-0x18]
   97bec: d503201f     	nop
   97bf0: 105dd60c     	adr	x12, #0xbbac0
   97bf4: f81f011f     	stur	xzr, [x8, #-0x10]
   97bf8: f85d83a1     	ldur	x1, [x29, #-0x28]
   97bfc: f81f013f     	stur	xzr, [x9, #-0x10]
   97c00: f85983a3     	ldur	x3, [x29, #-0x68]
   97c04: b9400188     	ldr	w8, [x12]
   97c08: aa1503e0     	mov	x0, x21
   97c0c: 39401189     	ldrb	w9, [x12, #0x4]
   97c10: d503201f     	nop
   97c14: 10b5d26c     	adr	x12, #-0x945b4
   97c18: d503201f     	nop
   97c1c: 105dd524     	adr	x4, #0xbbaa4
   97c20: f85c83a5     	ldur	x5, [x29, #-0x38]
   97c24: b81f0168     	stur	w8, [x11, #-0x10]
   97c28: f81f014c     	stur	x12, [x10, #-0x10]
   97c2c: 381f4169     	sturb	w9, [x11, #-0xc]
   97c30: 94004987     	bl	0xaa24c <.text+0xa166c>
   97c34: b94002a8     	ldr	w8, [x21]
   97c38: d297b2c9     	mov	x9, #0xbd96
   97c3c: d29ac66f     	mov	x15, #0xd633
   97c40: d296aeae     	mov	x14, #0xb575
   97c44: d2829db5     	mov	x21, #0x14ed
   97c48: f2a97369     	movk	x9, #0x4b9b, lsl #16
   97c4c: 7100011f     	cmp	w8, #0x0
   97c50: d29af768     	mov	x8, #0xd7bb
   97c54: f2bb3f28     	movk	x8, #0xd9f9, lsl #16
   97c58: f2aeccef     	movk	x15, #0x7667, lsl #16
   97c5c: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97c60: f2a1da15     	movk	x21, #0xed0, lsl #16
   97c64: f2c1ffa8     	movk	x8, #0xffd, lsl #32
   97c68: f2d288a9     	movk	x9, #0x9445, lsl #32
   97c6c: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97c70: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97c74: f2c723d5     	movk	x21, #0x391e, lsl #32
   97c78: f2e605c8     	movk	x8, #0x302e, lsl #48
   97c7c: f2eb8b09     	movk	x9, #0x5c58, lsl #48
   97c80: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97c84: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97c88: f2ff58b5     	movk	x21, #0xfac5, lsl #48
   97c8c: 9a880129     	csel	x9, x9, x8, eq
   97c90: 17fffe25     	b	0x97524 <.text+0x8e944>
   97c94: 900005e8     	adrp	x8, 0x153000
   97c98: d288ca89     	mov	x9, #0x4654
   97c9c: 4f07e561     	movi	v1.16b, #0xeb
   97ca0: d00005ea     	adrp	x10, 0x155000
   97ca4: f2ada089     	movk	x9, #0x6d04, lsl #16
   97ca8: 3dc1b100     	ldr	q0, [x8, #0x6c0]
   97cac: f2d81a29     	movk	x9, #0xc0d1, lsl #32
   97cb0: f2f9e189     	movk	x9, #0xcf0c, lsl #48
   97cb4: 6e211c00     	eor	v0.16b, v0.16b, v1.16b
   97cb8: 3d81b100     	str	q0, [x8, #0x6c0]
   97cbc: 52800028     	mov	w8, #0x1
   97cc0: 392a4948     	strb	w8, [x10, #0xa92]
   97cc4: 17fffe18     	b	0x97524 <.text+0x8e944>
   97cc8: a97e57a8     	ldp	x8, x21, [x29, #-0x20]
   97ccc: a97d07a4     	ldp	x4, x1, [x29, #-0x30]
   97cd0: f9400103     	ldr	x3, [x8]
   97cd4: aa1503e0     	mov	x0, x21
   97cd8: f85f03a2     	ldur	x2, [x29, #-0x10]
   97cdc: 94003a70     	bl	0xa669c <.text+0x9dabc>
   97ce0: b94002a8     	ldr	w8, [x21]
   97ce4: d29ac66f     	mov	x15, #0xd633
   97ce8: d296aeae     	mov	x14, #0xb575
   97cec: d2829db5     	mov	x21, #0x14ed
   97cf0: f2aeccef     	movk	x15, #0x7667, lsl #16
   97cf4: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97cf8: 7100011f     	cmp	w8, #0x0
   97cfc: d2946c28     	mov	x8, #0xa361
   97d00: f2a64928     	movk	x8, #0x3249, lsl #16
   97d04: f2a1da15     	movk	x21, #0xed0, lsl #16
   97d08: f2db5208     	movk	x8, #0xda90, lsl #32
   97d0c: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97d10: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97d14: f2c723d5     	movk	x21, #0x391e, lsl #32
   97d18: f2fca448     	movk	x8, #0xe522, lsl #48
   97d1c: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97d20: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97d24: f2ff58b5     	movk	x21, #0xfac5, lsl #48
   97d28: 9a8802c9     	csel	x9, x22, x8, eq
   97d2c: 17fffdfe     	b	0x97524 <.text+0x8e944>
   97d30: f85e03a8     	ldur	x8, [x29, #-0x20]
   97d34: f9400108     	ldr	x8, [x8]
   97d38: f81c03a8     	stur	x8, [x29, #-0x40]
   97d3c: f100011f     	cmp	x8, #0x0
   97d40: f85f03a8     	ldur	x8, [x29, #-0x10]
   97d44: fa401904     	ccmp	x8, #0x0, #0x4, ne
   97d48: 9a8f11c9     	csel	x9, x14, x15, ne
   97d4c: 17fffdf6     	b	0x97524 <.text+0x8e944>
   97d50: d503201f     	nop
   97d54: 105dcaed     	adr	x13, #0xbb95c
   97d58: 528012b0     	mov	w16, #0x95
   97d5c: 394001a8     	ldrb	w8, [x13]
   97d60: 394005a9     	ldrb	w9, [x13, #0x1]
   97d64: 394009aa     	ldrb	w10, [x13, #0x2]
   97d68: 39400dab     	ldrb	w11, [x13, #0x3]
   97d6c: 4a100108     	eor	w8, w8, w16
   97d70: 394011ac     	ldrb	w12, [x13, #0x4]
   97d74: 4a100129     	eor	w9, w9, w16
   97d78: 4a10014a     	eor	w10, w10, w16
   97d7c: 390001a8     	strb	w8, [x13]
   97d80: 4a100168     	eor	w8, w11, w16
   97d84: 390005a9     	strb	w9, [x13, #0x1]
   97d88: 4a10018b     	eor	w11, w12, w16
   97d8c: 390009aa     	strb	w10, [x13, #0x2]
   97d90: d296bfa9     	mov	x9, #0xb5fd
   97d94: 39000da8     	strb	w8, [x13, #0x3]
   97d98: 52800028     	mov	w8, #0x1
   97d9c: d00005ea     	adrp	x10, 0x155000
   97da0: f2abd9a9     	movk	x9, #0x5ecd, lsl #16
   97da4: f2c21a89     	movk	x9, #0x10d4, lsl #32
   97da8: 390011ab     	strb	w11, [x13, #0x4]
   97dac: f2f82a09     	movk	x9, #0xc150, lsl #48
   97db0: 392a4548     	strb	w8, [x10, #0xa91]
   97db4: 17fffddc     	b	0x97524 <.text+0x8e944>
   97db8: f85d03a8     	ldur	x8, [x29, #-0x30]
   97dbc: f9400108     	ldr	x8, [x8]
   97dc0: f81b83a8     	stur	x8, [x29, #-0x48]
   97dc4: f100011f     	cmp	x8, #0x0
   97dc8: f85f03a8     	ldur	x8, [x29, #-0x10]
   97dcc: fa401904     	ccmp	x8, #0x0, #0x4, ne
   97dd0: d298e108     	mov	x8, #0xc708
   97dd4: f2a4fb08     	movk	x8, #0x27d8, lsl #16
   97dd8: f2cd29e8     	movk	x8, #0x694f, lsl #32
   97ddc: f2e3cdc8     	movk	x8, #0x1e6e, lsl #48
   97de0: 9a991109     	csel	x9, x8, x25, ne
   97de4: f85e03a8     	ldur	x8, [x29, #-0x20]
   97de8: f900011f     	str	xzr, [x8]
   97dec: 17fffdce     	b	0x97524 <.text+0x8e944>
   97df0: f85e83a8     	ldur	x8, [x29, #-0x18]
   97df4: d297e2c9     	mov	x9, #0xbf16
   97df8: f2b6e789     	movk	x9, #0xb73c, lsl #16
   97dfc: f2d1a349     	movk	x9, #0x8d1a, lsl #32
   97e00: b9400108     	ldr	w8, [x8]
   97e04: f2ec6949     	movk	x9, #0x634a, lsl #48
   97e08: 7100011f     	cmp	w8, #0x0
   97e0c: d28edf88     	mov	x8, #0x76fc
   97e10: f2aa5688     	movk	x8, #0x52b4, lsl #16
   97e14: f2db5668     	movk	x8, #0xdab3, lsl #32
   97e18: f2e89dc8     	movk	x8, #0x44ee, lsl #48
   97e1c: 9a890109     	csel	x9, x8, x9, eq
   97e20: 17fffdc1     	b	0x97524 <.text+0x8e944>
   97e24: a97e57a8     	ldp	x8, x21, [x29, #-0x20]
   97e28: 52800024     	mov	w4, #0x1
   97e2c: f85d83a1     	ldur	x1, [x29, #-0x28]
   97e30: f85f03a2     	ldur	x2, [x29, #-0x10]
   97e34: f9400103     	ldr	x3, [x8]
   97e38: aa1503e0     	mov	x0, x21
   97e3c: f85b03a5     	ldur	x5, [x29, #-0x50]
   97e40: 94003f05     	bl	0xa7a54 <.text+0x9ee74>
   97e44: b94002a8     	ldr	w8, [x21]
   97e48: d29ac66f     	mov	x15, #0xd633
   97e4c: d296aeae     	mov	x14, #0xb575
   97e50: d2829db5     	mov	x21, #0x14ed
   97e54: f2aeccef     	movk	x15, #0x7667, lsl #16
   97e58: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97e5c: 7100011f     	cmp	w8, #0x0
   97e60: d2802f08     	mov	x8, #0x178
   97e64: f2adc368     	movk	x8, #0x6e1b, lsl #16
   97e68: f2a1da15     	movk	x21, #0xed0, lsl #16
   97e6c: f2c01428     	movk	x8, #0xa1, lsl #32
   97e70: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97e74: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97e78: f2c723d5     	movk	x21, #0x391e, lsl #32
   97e7c: f2ee13a8     	movk	x8, #0x709d, lsl #48
   97e80: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97e84: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97e88: f2ff58b5     	movk	x21, #0xfac5, lsl #48
   97e8c: 9a880309     	csel	x9, x24, x8, eq
   97e90: 17fffda5     	b	0x97524 <.text+0x8e944>
   97e94: d29e6449     	mov	x9, #0xf322
   97e98: f85c83a8     	ldur	x8, [x29, #-0x38]
   97e9c: f2b2bd69     	movk	x9, #0x95eb, lsl #16
   97ea0: f2c33c89     	movk	x9, #0x19e4, lsl #32
   97ea4: f2e03269     	movk	x9, #0x193, lsl #48
   97ea8: f900011f     	str	xzr, [x8]
   97eac: 17fffd9e     	b	0x97524 <.text+0x8e944>
   97eb0: f85f03a0     	ldur	x0, [x29, #-0x10]
   97eb4: f85b83a1     	ldur	x1, [x29, #-0x48]
   97eb8: f9400008     	ldr	x8, [x0]
   97ebc: f9405d08     	ldr	x8, [x8, #0xb8]
   97ec0: d63f0100     	blr	x8
   97ec4: d29ac66f     	mov	x15, #0xd633
   97ec8: d296aeae     	mov	x14, #0xb575
   97ecc: d2977029     	mov	x9, #0xbb81
   97ed0: f2aeccef     	movk	x15, #0x7667, lsl #16
   97ed4: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97ed8: f2b1b469     	movk	x9, #0x8da3, lsl #16
   97edc: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97ee0: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97ee4: f2ce7109     	movk	x9, #0x7388, lsl #32
   97ee8: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97eec: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97ef0: f2ecab69     	movk	x9, #0x655b, lsl #48
   97ef4: 17fffd8c     	b	0x97524 <.text+0x8e944>
   97ef8: f85c83a8     	ldur	x8, [x29, #-0x38]
   97efc: a97e8ba0     	ldp	x0, x2, [x29, #-0x18]
   97f00: f9400103     	ldr	x3, [x8]
   97f04: a97d07a8     	ldp	x8, x1, [x29, #-0x30]
   97f08: f9400104     	ldr	x4, [x8]
   97f0c: 94004ecc     	bl	0xaba3c <.text+0xa2e5c>
   97f10: d29ac66f     	mov	x15, #0xd633
   97f14: d296aeae     	mov	x14, #0xb575
   97f18: d28c69c9     	mov	x9, #0x634e
   97f1c: f2aeccef     	movk	x15, #0x7667, lsl #16
   97f20: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97f24: f2bc3229     	movk	x9, #0xe191, lsl #16
   97f28: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97f2c: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97f30: f2c343a9     	movk	x9, #0x1a1d, lsl #32
   97f34: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97f38: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97f3c: f2ff1389     	movk	x9, #0xf89c, lsl #48
   97f40: 17fffd79     	b	0x97524 <.text+0x8e944>
   97f44: 2a1f03e0     	mov	w0, wzr
   97f48: 52800021     	mov	w1, #0x1
   97f4c: d503201f     	nop
   97f50: 105ed942     	adr	x2, #0xbdb28
   97f54: 9402c123     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   97f58: d2841148     	mov	x8, #0x208a
   97f5c: d280ca09     	mov	x9, #0x650
   97f60: d29ac66f     	mov	x15, #0xd633
   97f64: d296aeae     	mov	x14, #0xb575
   97f68: f2a08b88     	movk	x8, #0x45c, lsl #16
   97f6c: f2a7c849     	movk	x9, #0x3e42, lsl #16
   97f70: f2aeccef     	movk	x15, #0x7667, lsl #16
   97f74: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   97f78: f2d64888     	movk	x8, #0xb244, lsl #32
   97f7c: f2dbca09     	movk	x9, #0xde50, lsl #32
   97f80: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   97f84: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   97f88: 7100001f     	cmp	w0, #0x0
   97f8c: f2e30ec8     	movk	x8, #0x1876, lsl #48
   97f90: f2e60969     	movk	x9, #0x304b, lsl #48
   97f94: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   97f98: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   97f9c: 9a880129     	csel	x9, x9, x8, eq
   97fa0: 17fffd61     	b	0x97524 <.text+0x8e944>
   97fa4: d503201f     	nop
   97fa8: 105db94a     	adr	x10, #0xbb728
   97fac: 4f07e7c3     	movi	v3.16b, #0xfe
   97fb0: d28ce749     	mov	x9, #0x673a
   97fb4: f2b0d329     	movk	x9, #0x8699, lsl #16
   97fb8: ad400540     	ldp	q0, q1, [x10]
   97fbc: f2c913a9     	movk	x9, #0x489d, lsl #32
   97fc0: f2e08ba9     	movk	x9, #0x45d, lsl #48
   97fc4: 6e231c00     	eor	v0.16b, v0.16b, v3.16b
   97fc8: 6e231c21     	eor	v1.16b, v1.16b, v3.16b
   97fcc: 39410148     	ldrb	w8, [x10, #0x40]
   97fd0: ad000540     	stp	q0, q1, [x10]
   97fd4: ad410142     	ldp	q2, q0, [x10, #0x20]
   97fd8: 521f1908     	eor	w8, w8, #0xfe
   97fdc: 6e231c41     	eor	v1.16b, v2.16b, v3.16b
   97fe0: 39010148     	strb	w8, [x10, #0x40]
   97fe4: 52800028     	mov	w8, #0x1
   97fe8: 6e231c00     	eor	v0.16b, v0.16b, v3.16b
   97fec: ad010141     	stp	q1, q0, [x10, #0x20]
   97ff0: d00005ea     	adrp	x10, 0x155000
   97ff4: 392a4d48     	strb	w8, [x10, #0xa93]
   97ff8: 17fffd4b     	b	0x97524 <.text+0x8e944>
   97ffc: d00005e8     	adrp	x8, 0x155000
   98000: 396a4d08     	ldrb	w8, [x8, #0xa93]
   98004: 7100011f     	cmp	w8, #0x0
   98008: d2800ae8     	mov	x8, #0x57
   9800c: f2a861e8     	movk	x8, #0x430f, lsl #16
   98010: f2c2d868     	movk	x8, #0x16c3, lsl #32
   98014: f2e49f08     	movk	x8, #0x24f8, lsl #48
   98018: 9a881289     	csel	x9, x20, x8, ne
   9801c: 17fffd42     	b	0x97524 <.text+0x8e944>
   98020: f85f03a0     	ldur	x0, [x29, #-0x10]
   98024: f85c03a1     	ldur	x1, [x29, #-0x40]
   98028: f9400008     	ldr	x8, [x0]
   9802c: f9405d08     	ldr	x8, [x8, #0xb8]
   98030: d63f0100     	blr	x8
   98034: d29ac66f     	mov	x15, #0xd633
   98038: d296aeae     	mov	x14, #0xb575
   9803c: d2906169     	mov	x9, #0x830b
   98040: f2aeccef     	movk	x15, #0x7667, lsl #16
   98044: f2bd550e     	movk	x14, #0xeaa8, lsl #16
   98048: f2b51dc9     	movk	x9, #0xa8ee, lsl #16
   9804c: f2cdb8cf     	movk	x15, #0x6dc6, lsl #32
   98050: f2dadd2e     	movk	x14, #0xd6e9, lsl #32
   98054: f2d204e9     	movk	x9, #0x9027, lsl #32
   98058: f2fdd7af     	movk	x15, #0xeebd, lsl #48
   9805c: f2fd29ee     	movk	x14, #0xe94f, lsl #48
   98060: f2ef6fc9     	movk	x9, #0x7b7e, lsl #48
   98064: 17fffd30     	b	0x97524 <.text+0x8e944>
   98068: b00005e8     	adrp	x8, 0x155000
   9806c: 396a4508     	ldrb	w8, [x8, #0xa91]
   98070: 7100011f     	cmp	w8, #0x0
   98074: d29ca4c8     	mov	x8, #0xe526
   98078: f2b8ee88     	movk	x8, #0xc774, lsl #16
   9807c: f2d559e8     	movk	x8, #0xaacf, lsl #32
   98080: f2efb1e8     	movk	x8, #0x7d8f, lsl #48
   98084: 9a881349     	csel	x9, x26, x8, ne
   98088: 17fffd27     	b	0x97524 <.text+0x8e944>
   9808c: f85903a8     	ldur	x8, [x29, #-0x70]
   98090: f9401508     	ldr	x8, [x8, #0x28]
   98094: f85f83a9     	ldur	x9, [x29, #-0x8]
   98098: eb09011f     	cmp	x8, x9
   9809c: 54000121     	b.ne	0x980c0 <.text+0x8f4e0>
   980a0: 910003bf     	mov	sp, x29
   980a4: a9454ff4     	ldp	x20, x19, [sp, #0x50]
   980a8: a94457f6     	ldp	x22, x21, [sp, #0x40]
   980ac: a9435ff8     	ldp	x24, x23, [sp, #0x30]
   980b0: a94267fa     	ldp	x26, x25, [sp, #0x20]
   980b4: a9416ffc     	ldp	x28, x27, [sp, #0x10]
   980b8: a8c67bfd     	ldp	x29, x30, [sp], #0x60
   980bc: d65f03c0     	ret
   980c0: 9402c254     	bl	0x148a10 <__stack_chk_fail@plt>
   980c4: a9ba7bfd     	stp	x29, x30, [sp, #-0x60]!
   980c8: a9016ffc     	stp	x28, x27, [sp, #0x10]
   980cc: a90267fa     	stp	x26, x25, [sp, #0x20]
   980d0: a9035ff8     	stp	x24, x23, [sp, #0x30]
   980d4: a90457f6     	stp	x22, x21, [sp, #0x40]
   980d8: a9054ff4     	stp	x20, x19, [sp, #0x50]
   980dc: 910003fd     	mov	x29, sp
   980e0: d101c3ff     	sub	sp, sp, #0x70
   980e4: a93a13a2     	stp	x2, x4, [x29, #-0x60]
   980e8: d2801b49     	mov	x9, #0xda
   980ec: f81f03a0     	stur	x0, [x29, #-0x10]
   980f0: d53bd048     	mrs	x8, TPIDR_EL0
   980f4: f81903a8     	stur	x8, [x29, #-0x70]
   980f8: f2bf1949     	movk	x9, #0xf8ca, lsl #16
   980fc: f9401508     	ldr	x8, [x8, #0x28]
   98100: f2d3dcc9     	movk	x9, #0x9ee6, lsl #32
   98104: 7100787f     	cmp	w3, #0x1e
   98108: f2e1ba29     	movk	x9, #0xdd1, lsl #48
   9810c: d29732d6     	mov	x22, #0xb996
   98110: d29f507b     	mov	x27, #0xfa83
   98114: f81f83a8     	stur	x8, [x29, #-0x8]
   98118: d29bdf88     	mov	x8, #0xdefc
   9811c: f2a1dd88     	movk	x8, #0xeec, lsl #16
   98120: d288442b     	mov	x11, #0x4221
   98124: f2cda668     	movk	x8, #0x6d33, lsl #32
   98128: d2925cd7     	mov	x23, #0x92e6
   9812c: f2e7d6a8     	movk	x8, #0x3eb5, lsl #48
   98130: d29c87f4     	mov	x20, #0xe43f
   98134: 9a88c128     	csel	x8, x9, x8, gt
   98138: d29bf118     	mov	x24, #0xdf88
   9813c: d29eb593     	mov	x19, #0xf5ac
   98140: d2994419     	mov	x25, #0xca20
   98144: d2897f1a     	mov	x26, #0x4bf8
   98148: d2915f5c     	mov	x28, #0x8afa
   9814c: f81983a8     	stur	x8, [x29, #-0x68]
   98150: d28307cc     	mov	x12, #0x183e
   98154: d29553cd     	mov	x13, #0xaa9e
   98158: d2884429     	mov	x9, #0x4221
   9815c: f2ad1e76     	movk	x22, #0x68f3, lsl #16
   98160: f2a3467b     	movk	x27, #0x1a33, lsl #16
   98164: f2ab736b     	movk	x11, #0x5b9b, lsl #16
   98168: f2abf077     	movk	x23, #0x5f83, lsl #16
   9816c: f2b54894     	movk	x20, #0xaa44, lsl #16
   98170: f2ab2278     	movk	x24, #0x5913, lsl #16
   98174: f2bdc753     	movk	x19, #0xee3a, lsl #16
   98178: f2b04dd9     	movk	x25, #0x826e, lsl #16
   9817c: f2bae05a     	movk	x26, #0xd702, lsl #16
   98180: f2a4a8fc     	movk	x28, #0x2547, lsl #16
   98184: f2bc952c     	movk	x12, #0xe4a9, lsl #16
   98188: f2b202ed     	movk	x13, #0x9017, lsl #16
   9818c: f2ab7369     	movk	x9, #0x5b9b, lsl #16
   98190: f2c9e8d6     	movk	x22, #0x4f46, lsl #32
   98194: f2dba79b     	movk	x27, #0xdd3c, lsl #32
   98198: f2dbdfeb     	movk	x11, #0xdeff, lsl #32
   9819c: f2d69677     	movk	x23, #0xb4b3, lsl #32
   981a0: f2c98d74     	movk	x20, #0x4c6b, lsl #32
   981a4: f2ddd6f8     	movk	x24, #0xeeb7, lsl #32
   981a8: f2d208b3     	movk	x19, #0x9045, lsl #32
   981ac: f2ce0179     	movk	x25, #0x700b, lsl #32
   981b0: f2d3b73a     	movk	x26, #0x9db9, lsl #32
   981b4: f2dbb1dc     	movk	x28, #0xdd8e, lsl #32
   981b8: f2dac0ac     	movk	x12, #0xd605, lsl #32
   981bc: f2ccfe2d     	movk	x13, #0x67f1, lsl #32
   981c0: f2dbdfe9     	movk	x9, #0xdeff, lsl #32
   981c4: aa0103f5     	mov	x21, x1
   981c8: f2ff01d6     	movk	x22, #0xf80e, lsl #48
   981cc: f2f2625b     	movk	x27, #0x9312, lsl #48
   981d0: f2fddaeb     	movk	x11, #0xeed7, lsl #48
   981d4: f2f025b7     	movk	x23, #0x812d, lsl #48
   981d8: f2f07d94     	movk	x20, #0x83ec, lsl #48
   981dc: f2f2bad8     	movk	x24, #0x95d6, lsl #48
   981e0: f2f42013     	movk	x19, #0xa100, lsl #48
   981e4: f2f96e79     	movk	x25, #0xcb73, lsl #48
   981e8: f2fb7b5a     	movk	x26, #0xdbda, lsl #48
   981ec: f2fb7e7c     	movk	x28, #0xdbf3, lsl #48
   981f0: f2fc31ac     	movk	x12, #0xe18d, lsl #48
   981f4: f2fc45cd     	movk	x13, #0xe22e, lsl #48
   981f8: f2fddae9     	movk	x9, #0xeed7, lsl #48
   981fc: aa0903e8     	mov	x8, x9
   98200: d29ba529     	mov	x9, #0xdd29
   98204: f2a55f89     	movk	x9, #0x2afc, lsl #16
   98208: eb17011f     	cmp	x8, x23
   9820c: f2d12449     	movk	x9, #0x8922, lsl #32
   98210: f2ec76a9     	movk	x9, #0x63b5, lsl #48
   98214: 54ffff40     	b.eq	0x981fc <.text+0x8f61c>
   98218: eb14011f     	cmp	x8, x20
   9821c: 54001d80     	b.eq	0x985cc <.text+0x8f9ec>
   98220: eb1b011f     	cmp	x8, x27
   98224: 54002000     	b.eq	0x98624 <.text+0x8fa44>
   98228: d29863c9     	mov	x9, #0xc31e
   9822c: eb18011f     	cmp	x8, x24
   98230: f2a08e09     	movk	x9, #0x470, lsl #16
   98234: f2dff2c9     	movk	x9, #0xff96, lsl #32
   98238: f2e65a69     	movk	x9, #0x32d3, lsl #48
   9823c: 54fffe00     	b.eq	0x981fc <.text+0x8f61c>
   98240: d2819149     	mov	x9, #0xc8a
   98244: eb13011f     	cmp	x8, x19
   98248: f2ac7f89     	movk	x9, #0x63fc, lsl #16
   9824c: f2de90e9     	movk	x9, #0xf487, lsl #32
   98250: f2fdeee9     	movk	x9, #0xef77, lsl #48
   98254: 54fffd40     	b.eq	0x981fc <.text+0x8f61c>
   98258: d29732c9     	mov	x9, #0xb996
   9825c: eb19011f     	cmp	x8, x25
   98260: f2ad1e69     	movk	x9, #0x68f3, lsl #16
   98264: f2c9e8c9     	movk	x9, #0x4f46, lsl #32
   98268: f2ff01c9     	movk	x9, #0xf80e, lsl #48
   9826c: 54fffc80     	b.eq	0x981fc <.text+0x8f61c>
   98270: eb1a011f     	cmp	x8, x26
   98274: 54002bc0     	b.eq	0x987ec <.text+0x8fc0c>
   98278: eb1c011f     	cmp	x8, x28
   9827c: 54000e60     	b.eq	0x98448 <.text+0x8f868>
   98280: eb0c011f     	cmp	x8, x12
   98284: 54fffbc0     	b.eq	0x981fc <.text+0x8f61c>
   98288: eb0d011f     	cmp	x8, x13
   9828c: 54002fc0     	b.eq	0x98884 <.text+0x8fca4>
   98290: d29f5069     	mov	x9, #0xfa83
   98294: eb0b011f     	cmp	x8, x11
   98298: f2a34669     	movk	x9, #0x1a33, lsl #16
   9829c: f2dba789     	movk	x9, #0xdd3c, lsl #32
   982a0: f2f26249     	movk	x9, #0x9312, lsl #48
   982a4: 54fffac0     	b.eq	0x981fc <.text+0x8f61c>
   982a8: eb16011f     	cmp	x8, x22
   982ac: 54002de0     	b.eq	0x98868 <.text+0x8fc88>
   982b0: d2801b49     	mov	x9, #0xda
   982b4: f2bf1949     	movk	x9, #0xf8ca, lsl #16
   982b8: f2d3dcc9     	movk	x9, #0x9ee6, lsl #32
   982bc: f2e1ba29     	movk	x9, #0xdd1, lsl #48
   982c0: eb09011f     	cmp	x8, x9
   982c4: 54000ca0     	b.eq	0x98458 <.text+0x8f878>
   982c8: d28ac669     	mov	x9, #0x5633
   982cc: f2a180c9     	movk	x9, #0xc06, lsl #16
   982d0: f2d94589     	movk	x9, #0xca2c, lsl #32
   982d4: f2e34c49     	movk	x9, #0x1a62, lsl #48
   982d8: eb09011f     	cmp	x8, x9
   982dc: 54002540     	b.eq	0x98784 <.text+0x8fba4>
   982e0: d287a769     	mov	x9, #0x3d3b
   982e4: f2a69dc9     	movk	x9, #0x34ee, lsl #16
   982e8: f2d0a2c9     	movk	x9, #0x8516, lsl #32
   982ec: f2e44ce9     	movk	x9, #0x2267, lsl #48
   982f0: eb09011f     	cmp	x8, x9
   982f4: 54002a80     	b.eq	0x98844 <.text+0x8fc64>
   982f8: d29732c9     	mov	x9, #0xb996
   982fc: d29582ca     	mov	x10, #0xac16
   98300: f2ad1e69     	movk	x9, #0x68f3, lsl #16
   98304: f2a26bca     	movk	x10, #0x135e, lsl #16
   98308: f2c9e8c9     	movk	x9, #0x4f46, lsl #32
   9830c: f2c1e52a     	movk	x10, #0xf29, lsl #32
   98310: f2ff01c9     	movk	x9, #0xf80e, lsl #48
   98314: f2e6004a     	movk	x10, #0x3002, lsl #48
   98318: eb0a011f     	cmp	x8, x10
   9831c: 54fff700     	b.eq	0x981fc <.text+0x8f61c>
   98320: d29863c9     	mov	x9, #0xc31e
   98324: f2a08e09     	movk	x9, #0x470, lsl #16
   98328: f2dff2c9     	movk	x9, #0xff96, lsl #32
   9832c: f2e65a69     	movk	x9, #0x32d3, lsl #48
   98330: eb09011f     	cmp	x8, x9
   98334: 54000d60     	b.eq	0x984e0 <.text+0x8f900>
   98338: d29bdf89     	mov	x9, #0xdefc
   9833c: f2a1dd89     	movk	x9, #0xeec, lsl #16
   98340: f2cda669     	movk	x9, #0x6d33, lsl #32
   98344: f2e7d6a9     	movk	x9, #0x3eb5, lsl #48
   98348: eb09011f     	cmp	x8, x9
   9834c: 54002260     	b.eq	0x98798 <.text+0x8fbb8>
   98350: d29732c9     	mov	x9, #0xb996
   98354: d29bea6a     	mov	x10, #0xdf53
   98358: f2ad1e69     	movk	x9, #0x68f3, lsl #16
   9835c: f2b10aea     	movk	x10, #0x8857, lsl #16
   98360: f2c9e8c9     	movk	x9, #0x4f46, lsl #32
   98364: f2c5a3ca     	movk	x10, #0x2d1e, lsl #32
   98368: f2ff01c9     	movk	x9, #0xf80e, lsl #48
   9836c: f2ea336a     	movk	x10, #0x519b, lsl #48
   98370: eb0a011f     	cmp	x8, x10
   98374: 54fff440     	b.eq	0x981fc <.text+0x8f61c>
   98378: d2922c69     	mov	x9, #0x9163
   9837c: f2aa2469     	movk	x9, #0x5123, lsl #16
   98380: f2c97b09     	movk	x9, #0x4bd8, lsl #32
   98384: f2ebf7c9     	movk	x9, #0x5fbe, lsl #48
   98388: eb09011f     	cmp	x8, x9
   9838c: 54001e20     	b.eq	0x98750 <.text+0x8fb70>
   98390: d29ba529     	mov	x9, #0xdd29
   98394: f2a55f89     	movk	x9, #0x2afc, lsl #16
   98398: f2d12449     	movk	x9, #0x8922, lsl #32
   9839c: f2ec76a9     	movk	x9, #0x63b5, lsl #48
   983a0: eb09011f     	cmp	x8, x9
   983a4: 54001c40     	b.eq	0x9872c <.text+0x8fb4c>
   983a8: d29732c9     	mov	x9, #0xb996
   983ac: d289ebea     	mov	x10, #0x4f5f
   983b0: f2ad1e69     	movk	x9, #0x68f3, lsl #16
   983b4: f2a7a44a     	movk	x10, #0x3d22, lsl #16
   983b8: f2c9e8c9     	movk	x9, #0x4f46, lsl #32
   983bc: f2da364a     	movk	x10, #0xd1b2, lsl #32
   983c0: f2ff01c9     	movk	x9, #0xf80e, lsl #48
   983c4: f2ed950a     	movk	x10, #0x6ca8, lsl #48
   983c8: eb0a011f     	cmp	x8, x10
   983cc: 54fff180     	b.eq	0x981fc <.text+0x8f61c>
   983d0: d295e7a9     	mov	x9, #0xaf3d
   983d4: f2b65ca9     	movk	x9, #0xb2e5, lsl #16
   983d8: f2cfbae9     	movk	x9, #0x7dd7, lsl #32
   983dc: f2ed9b49     	movk	x9, #0x6cda, lsl #48
   983e0: eb09011f     	cmp	x8, x9
   983e4: 54001580     	b.eq	0x98694 <.text+0x8fab4>
   983e8: d29f5069     	mov	x9, #0xfa83
   983ec: d28f41ea     	mov	x10, #0x7a0f
   983f0: f2a34669     	movk	x9, #0x1a33, lsl #16
   983f4: f2b7184a     	movk	x10, #0xb8c2, lsl #16
   983f8: f2dba789     	movk	x9, #0xdd3c, lsl #32
   983fc: f2ceb8aa     	movk	x10, #0x75c5, lsl #32
   98400: f2f26249     	movk	x9, #0x9312, lsl #48
   98404: f2ee4cca     	movk	x10, #0x7266, lsl #48
   98408: eb0a011f     	cmp	x8, x10
   9840c: 54ffef80     	b.eq	0x981fc <.text+0x8f61c>
   98410: d2951aa9     	mov	x9, #0xa8d5
   98414: f2b66e29     	movk	x9, #0xb371, lsl #16
   98418: f2ca3a89     	movk	x9, #0x51d4, lsl #32
   9841c: f2ee7289     	movk	x9, #0x7394, lsl #48
   98420: eb09011f     	cmp	x8, x9
   98424: 54001780     	b.eq	0x98714 <.text+0x8fb34>
   98428: d281914a     	mov	x10, #0xc8a
   9842c: aa0803e9     	mov	x9, x8
   98430: f2ac7f8a     	movk	x10, #0x63fc, lsl #16
   98434: f2de90ea     	movk	x10, #0xf487, lsl #32
   98438: f2fdeeea     	movk	x10, #0xef77, lsl #48
   9843c: eb0a011f     	cmp	x8, x10
   98440: 54ffede1     	b.ne	0x981fc <.text+0x8f61c>
   98444: 14000132     	b	0x9890c <.text+0x8fd2c>
   98448: 52800028     	mov	w8, #0x1
   9844c: f85d83aa     	ldur	x10, [x29, #-0x28]
   98450: 39000148     	strb	w8, [x10]
   98454: 17ffff6a     	b	0x981fc <.text+0x8f61c>
   98458: f85f03b6     	ldur	x22, [x29, #-0x10]
   9845c: aa1503e1     	mov	x1, x21
   98460: f85d03a2     	ldur	x2, [x29, #-0x30]
   98464: f85c03a3     	ldur	x3, [x29, #-0x40]
   98468: aa1603e0     	mov	x0, x22
   9846c: 94005acc     	bl	0xaef9c <.text+0xa63bc>
   98470: b94002c8     	ldr	w8, [x22]
   98474: d2951aa9     	mov	x9, #0xa8d5
   98478: d29553cd     	mov	x13, #0xaa9e
   9847c: d28307cc     	mov	x12, #0x183e
   98480: d288442b     	mov	x11, #0x4221
   98484: d29732d6     	mov	x22, #0xb996
   98488: 7100011f     	cmp	w8, #0x0
   9848c: d289ebe8     	mov	x8, #0x4f5f
   98490: f2a7a448     	movk	x8, #0x3d22, lsl #16
   98494: f2b66e29     	movk	x9, #0xb371, lsl #16
   98498: f2b202ed     	movk	x13, #0x9017, lsl #16
   9849c: f2bc952c     	movk	x12, #0xe4a9, lsl #16
   984a0: f2ab736b     	movk	x11, #0x5b9b, lsl #16
   984a4: f2ad1e76     	movk	x22, #0x68f3, lsl #16
   984a8: f2da3648     	movk	x8, #0xd1b2, lsl #32
   984ac: f2ca3a89     	movk	x9, #0x51d4, lsl #32
   984b0: f2ccfe2d     	movk	x13, #0x67f1, lsl #32
   984b4: f2dac0ac     	movk	x12, #0xd605, lsl #32
   984b8: f2dbdfeb     	movk	x11, #0xdeff, lsl #32
   984bc: f2c9e8d6     	movk	x22, #0x4f46, lsl #32
   984c0: f2ed9508     	movk	x8, #0x6ca8, lsl #48
   984c4: f2ee7289     	movk	x9, #0x7394, lsl #48
   984c8: f2fc45cd     	movk	x13, #0xe22e, lsl #48
   984cc: f2fc31ac     	movk	x12, #0xe18d, lsl #48
   984d0: f2fddaeb     	movk	x11, #0xeed7, lsl #48
   984d4: f2ff01d6     	movk	x22, #0xf80e, lsl #48
   984d8: 9a880129     	csel	x9, x9, x8, eq
   984dc: 17ffff48     	b	0x981fc <.text+0x8f61c>
   984e0: d503201f     	nop
   984e4: 105eac88     	adr	x8, #0xbd590
   984e8: 089ffd1f     	stlrb	wzr, [x8]
   984ec: 910003e8     	mov	x8, sp
   984f0: d1004109     	sub	x9, x8, #0x10
   984f4: f81d83a9     	stur	x9, [x29, #-0x28]
   984f8: 9100013f     	mov	sp, x9
   984fc: 910003e9     	mov	x9, sp
   98500: d1004124     	sub	x4, x9, #0x10
   98504: 9100009f     	mov	sp, x4
   98508: 910003ea     	mov	x10, sp
   9850c: d100414b     	sub	x11, x10, #0x10
   98510: f81e03ab     	stur	x11, [x29, #-0x20]
   98514: 9100017f     	mov	sp, x11
   98518: 910003eb     	mov	x11, sp
   9851c: d100416c     	sub	x12, x11, #0x10
   98520: f81c83ac     	stur	x12, [x29, #-0x38]
   98524: 9100019f     	mov	sp, x12
   98528: 910003ec     	mov	x12, sp
   9852c: d100418d     	sub	x13, x12, #0x10
   98530: f81c03ad     	stur	x13, [x29, #-0x40]
   98534: 910001bf     	mov	sp, x13
   98538: f85f03b6     	ldur	x22, [x29, #-0x10]
   9853c: aa1503e1     	mov	x1, x21
   98540: f85a03a2     	ldur	x2, [x29, #-0x60]
   98544: d503201f     	nop
   98548: 105d8bc3     	adr	x3, #0xbb178
   9854c: 381f011f     	sturb	wzr, [x8, #-0x10]
   98550: aa1603e0     	mov	x0, x22
   98554: f81f013f     	stur	xzr, [x9, #-0x10]
   98558: f81f015f     	stur	xzr, [x10, #-0x10]
   9855c: f81f017f     	stur	xzr, [x11, #-0x10]
   98560: b81f019f     	stur	wzr, [x12, #-0x10]
   98564: f81e83a4     	stur	x4, [x29, #-0x18]
   98568: 940051c5     	bl	0xacc7c <.text+0xa409c>
   9856c: b94002c8     	ldr	w8, [x22]
   98570: d29553cd     	mov	x13, #0xaa9e
   98574: f2b202ed     	movk	x13, #0x9017, lsl #16
   98578: d28307cc     	mov	x12, #0x183e
   9857c: d288442b     	mov	x11, #0x4221
   98580: d29732d6     	mov	x22, #0xb996
   98584: 7100011f     	cmp	w8, #0x0
   98588: d29bea68     	mov	x8, #0xdf53
   9858c: f2b10ae8     	movk	x8, #0x8857, lsl #16
   98590: f2ccfe2d     	movk	x13, #0x67f1, lsl #32
   98594: f2bc952c     	movk	x12, #0xe4a9, lsl #16
   98598: f2ab736b     	movk	x11, #0x5b9b, lsl #16
   9859c: f2ad1e76     	movk	x22, #0x68f3, lsl #16
   985a0: f2c5a3c8     	movk	x8, #0x2d1e, lsl #32
   985a4: f2fc45cd     	movk	x13, #0xe22e, lsl #48
   985a8: f2dac0ac     	movk	x12, #0xd605, lsl #32
   985ac: f2dbdfeb     	movk	x11, #0xdeff, lsl #32
   985b0: f2c9e8d6     	movk	x22, #0x4f46, lsl #32
   985b4: f2ea3368     	movk	x8, #0x519b, lsl #48
   985b8: f2fc31ac     	movk	x12, #0xe18d, lsl #48
   985bc: f2fddaeb     	movk	x11, #0xeed7, lsl #48
   985c0: f2ff01d6     	movk	x22, #0xf80e, lsl #48
   985c4: 9a8801a9     	csel	x9, x13, x8, eq
   985c8: 17ffff0d     	b	0x981fc <.text+0x8f61c>
   985cc: f94002a8     	ldr	x8, [x21]
   985d0: aa1503e0     	mov	x0, x21
   985d4: f85b03a1     	ldur	x1, [x29, #-0x50]
   985d8: f9405d08     	ldr	x8, [x8, #0xb8]
   985dc: d63f0100     	blr	x8
   985e0: d29553cd     	mov	x13, #0xaa9e
   985e4: d28307cc     	mov	x12, #0x183e
   985e8: d288442b     	mov	x11, #0x4221
   985ec: d2819149     	mov	x9, #0xc8a
   985f0: f2b202ed     	movk	x13, #0x9017, lsl #16
   985f4: f2bc952c     	movk	x12, #0xe4a9, lsl #16
   985f8: f2ab736b     	movk	x11, #0x5b9b, lsl #16
   985fc: f2ac7f89     	movk	x9, #0x63fc, lsl #16
   98600: f2ccfe2d     	movk	x13, #0x67f1, lsl #32
   98604: f2dac0ac     	movk	x12, #0xd605, lsl #32
   98608: f2dbdfeb     	movk	x11, #0xdeff, lsl #32
   9860c: f2de90e9     	movk	x9, #0xf487, lsl #32
   98610: f2fc45cd     	movk	x13, #0xe22e, lsl #48
   98614: f2fc31ac     	movk	x12, #0xe18d, lsl #48
   98618: f2fddaeb     	movk	x11, #0xeed7, lsl #48
   9861c: f2fdeee9     	movk	x9, #0xef77, lsl #48
   98620: 17fffef7     	b	0x981fc <.text+0x8f61c>
   98624: 2a1f03e0     	mov	w0, wzr
   98628: 52800021     	mov	w1, #0x1
   9862c: d503201f     	nop
   98630: 105ea222     	adr	x2, #0xbd444
   98634: 9402bf6b     	bl	0x1483e0 <Java_com_adjust_sdk_sig_NativeLibHelper_nSign+0x6d214>
   98638: d28f41e8     	mov	x8, #0x7a0f
   9863c: d287a769     	mov	x9, #0x3d3b
   98640: d29553cd     	mov	x13, #0xaa9e
   98644: d28307cc     	mov	x12, #0x183e
   98648: d288442b     	mov	x11, #0x4221
   9864c: f2b71848     	movk	x8, #0xb8c2, lsl #16
   98650: f2a69dc9     	movk	x9, #0x34ee, lsl #16
   98654: f2b202ed     	movk	x13, #0x9017, lsl #16
   98658: f2bc952c     	movk	x12, #0xe4a9, lsl #16
   9865c: f2ab736b     	movk	x11, #0x5b9b, lsl #16
   98660: f2ceb8a8     	movk	x8, #0x75c5, lsl #32
   98664: f2d0a2c9     	movk	x9, #0x8516, lsl #32
   98668: f2ccfe2d     	movk	x13, #0x67f1, lsl #32
   9866c: f2dac0ac     	movk	x12, #0xd605, lsl #32
   98670: f2dbdfeb     	movk	x11, #0xdeff, lsl #32
   98674: 7100001f     	cmp	w0, #0x0
   98678: f2ee4cc8     	movk	x8, #0x7266, lsl #48
   9867c: f2e44ce9     	movk	x9, #0x2267, lsl #48
   98680: f2fc45cd     	movk	x13, #0xe22e, lsl #48
   98684: f2fc31ac     	movk	x12, #0xe18d, lsl #48
   98688: f2fddaeb     	movk	x11, #0xeed7, lsl #48
   9868c: 9a880129     	csel	x9, x9, x8, eq
   98690: 17fffedb     	b	0x981fc <.text+0x8f61c>
   98694: a97edba8     	ldp	x8, x22, [x29, #-0x18]
   98698: aa1503e1     	mov	x1, x21
   9869c: f85c83a4     	ldur	x4, [x29, #-0x38]
   986a0: f9400102     	ldr	x2, [x8]
   986a4: f85e03a8     	ldur	x8, [x29, #-0x20]
   986a8: aa1603e0     	mov	x0, x22
   986ac: f9400103     	ldr	x3, [x8]
   986b0: 94005747     	bl	0xae3cc <.text+0xa57ec>
   986b4: b94002c8     	ldr	w8, [x22]
   986b8: d29553cd     	mov	x13, #0xaa9e
   986bc: d28307cc     	mov	x12, #0x183e
   986c0: d288442b     	mov	x11, #0x4221
   986c4: d29732d6     	mov	x22, #0xb996
   986c8: f2b202ed     	movk	x13, #0x9017, lsl #16
   986cc: 7100011f     	cmp	w8, #0x0
   986d0: d28ac668     	mov	x8, #0x5633
   986d4: f2a180c8     	movk	x8, #0xc06, lsl #16
   986d8: f2bc952c     	movk	x12, #0xe4a9, lsl #16
   986dc: f2ab736b     	movk	x11, #0x5b9b, lsl #16
   986e0: f2ad1e76     	movk	x22, #0x68f3, lsl #16
   986e4: f2d94588     	movk	x8, #0xca2c, lsl #32
   986e8: f2ccfe2d     	movk	x13, #0x67f1, lsl #32
   986ec: f2dac0ac     	movk	x12, #0xd605, lsl #32
   986f0: f2dbdfeb     	movk	x11, #0xdeff, lsl #32
   986f4: f2c9e8d6     	movk	x22, #0x4f46, lsl #32
   986f8: f2e34c48     	movk	x8, #0x1a62, lsl #48
   986fc: f2fc45cd     	movk	x13, #0xe22e, lsl #48
   98700: f2fc31ac     	movk	x12, #0xe18d, lsl #48
   98704: f2fddaeb     	movk	x11, #0xeed7, lsl #48
   98708: f2ff01d6     	movk	x22, #0xf80e, lsl #48
   9870c: 9a990109     	csel	x9, x8, x25, eq
   98710: 17fffebb     	b	0x981fc <.text+0x8f61c>
   98714: f85c03a8     	ldur	x8, [x29, #-0x40]
   98718: b9400108     	ldr	w8, [x8]
   9871c: 51000508     	sub	w8, w8, #0x1
   98720: 7100091f     	cmp	w8, #0x2
   98724: 9a8c3389     	csel	x9, x28, x12, lo
   98728: 17fffeb5     	b	0x981fc <.text+0x8f61c>
   9872c: f85e03a8     	ldur	x8, [x29, #-0x20]
   98730: f9400108     	ldr	x8, [x8]
   98734: f100011f     	cmp	x8, #0x0
   98738: f81b03a8     	stur	x8, [x29, #-0x50]
   9873c: fa401aa4     	ccmp	x21, #0x0, #0x4, ne
   98740: f85e83a8     	ldur	x8, [x29, #-0x18]
   98744: 9a931289     	csel	x9, x20, x19, ne
   98748: f900011f     	str	xzr, [x8]
   9874c: 17fffeac     	b	0x981fc <.text+0x8f61c>
   98750: f00005c8     	adrp	x8, 0x153000
   98754: d29863c9     	mov	x9, #0xc31e
   98758: 4f07e561     	movi	v1.16b, #0xeb
   9875c: b00005ea     	adrp	x10, 0x155000
   98760: f2a08e09     	movk	x9, #0x470, lsl #16
   98764: 3dc1b100     	ldr	q0, [x8, #0x6c0]
   98768: f2dff2c9     	movk	x9, #0xff96, lsl #32
   9876c: f2e65a69     	movk	x9, #0x32d3, lsl #48
   98770: 6e211c00     	eor	v0.16b, v0.16b, v1.16b
   98774: 3d81b100     	str	q0, [x8, #0x6c0]
   98778: 52800028     	mov	w8, #0x1
   9877c: 392a4948     	strb	w8, [x10, #0xa92]
   98780: 17fffe9f     	b	0x981fc <.text+0x8f61c>
   98784: f85c83a8     	ldur	x8, [x29, #-0x38]
   98788: f85983a9     	ldur	x9, [x29, #-0x68]
   9878c: f9400108     	ldr	x8, [x8]
   98790: f81d03a8     	stur	x8, [x29, #-0x30]
   98794: 17fffe9a     	b	0x981fc <.text+0x8f61c>
   98798: a97d0fa2     	ldp	x2, x3, [x29, #-0x30]
   9879c: aa1503e1     	mov	x1, x21
   987a0: f85f03a0     	ldur	x0, [x29, #-0x10]
   987a4: 94005be6     	bl	0xaf73c <.text+0xa6b5c>
   987a8: d29553cd     	mov	x13, #0xaa9e
   987ac: d28307cc     	mov	x12, #0x183e
   987b0: d288442b     	mov	x11, #0x4221
   987b4: d29732c9     	mov	x9, #0xb996
   987b8: f2b202ed     	movk	x13, #0x9017, lsl #16
   987bc: f2bc952c     	movk	x12, #0xe4a9, lsl #16
   987c0: f2ab736b     	movk	x11, #0x5b9b, lsl #16
   987c4: f2ad1e69     	movk	x9, #0x68f3, lsl #16
   987c8: f2ccfe2d     	movk	x13, #0x67f1, lsl #32
   987cc: f2dac0ac     	movk	x12, #0xd605, lsl #32
   987d0: f2dbdfeb     	movk	x11, #0xdeff, lsl #32
   987d4: f2c9e8c9     	movk	x9, #0x4f46, lsl #32
   987d8: f2fc45cd     	movk	x13, #0xe22e, lsl #48
   987dc: f2fc31ac     	movk	x12, #0xe18d, lsl #48
   987e0: f2fddaeb     	movk	x11, #0xeed7, lsl #48
   987e4: f2ff01c9     	movk	x9, #0xf80e, lsl #48
   987e8: 17fffe85     	b	0x981fc <.text+0x8f61c>
   987ec: f94002a8     	ldr	x8, [x21]
   987f0: aa1503e0     	mov	x0, x21
   987f4: f85b83a1     	ldur	x1, [x29, #-0x48]
   987f8: f9405d08     	ldr	x8, [x8, #0xb8]
   987fc: d63f0100     	blr	x8
   98800: d29553cd     	mov	x13, #0xaa9e
   98804: d28307cc     	mov	x12, #0x183e
   98808: d288442b     	mov	x11, #0x4221
   9880c: d29ba529     	mov	x9, #0xdd29
   98810: f2b202ed     	movk	x13, #0x9017, lsl #16
   98814: f2bc952c     	movk	x12, #0xe4a9, lsl #16
   98818: f2ab736b     	movk	x11, #0x5b9b, lsl #16
   9881c: f2a55f89     	movk	x9, #0x2afc, lsl #16
   98820: f2ccfe2d     	movk	x13, #0x67f1, lsl #32
   98824: f2dac0ac     	movk	x12, #0xd605, lsl #32
   98828: f2dbdfeb     	movk	x11, #0xdeff, lsl #32
   9882c: f2d12449     	movk	x9, #0x8922, lsl #32
   98830: f2fc45cd     	movk	x13, #0xe22e, lsl #48
   98834: f2fc31ac     	movk	x12, #0xe18d, lsl #48
   98838: f2fddaeb     	movk	x11, #0xeed7, lsl #48
   9883c: f2ec76a9     	movk	x9, #0x63b5, lsl #48
   98840: 17fffe6f     	b	0x981fc <.text+0x8f61c>
   98844: b00005e8     	adrp	x8, 0x155000
   98848: 396a4908     	ldrb	w8, [x8, #0xa92]
   9884c: 7100011f     	cmp	w8, #0x0
   98850: d2922c68     	mov	x8, #0x9163
   98854: f2aa2468     	movk	x8, #0x5123, lsl #16
   98858: f2c97b08     	movk	x8, #0x4bd8, lsl #32
   9885c: f2ebf7c8     	movk	x8, #0x5fbe, lsl #48
   98860: 9a881309     	csel	x9, x24, x8, ne
   98864: 17fffe66     	b	0x981fc <.text+0x8f61c>
   98868: f85e83a8     	ldur	x8, [x29, #-0x18]
   9886c: f9400108     	ldr	x8, [x8]
   98870: f100011f     	cmp	x8, #0x0
   98874: f81b83a8     	stur	x8, [x29, #-0x48]
   98878: fa401aa4     	ccmp	x21, #0x0, #0x4, ne
   9887c: 9a971349     	csel	x9, x26, x23, ne
   98880: 17fffe5f     	b	0x981fc <.text+0x8f61c>
   98884: f85f03b6     	ldur	x22, [x29, #-0x10]
   98888: aa1503e1     	mov	x1, x21
   9888c: f85a83a2     	ldur	x2, [x29, #-0x58]
   98890: f85e03a3     	ldur	x3, [x29, #-0x20]
   98894: aa1603e0     	mov	x0, x22
   98898: 94004e59     	bl	0xac1fc <.text+0xa361c>
   9889c: b94002c8     	ldr	w8, [x22]
   988a0: d295e7a9     	mov	x9, #0xaf3d
   988a4: d29553cd     	mov	x13, #0xaa9e
   988a8: d28307cc     	mov	x12, #0x183e
   988ac: d288442b     	mov	x11, #0x4221
   988b0: d29732d6     	mov	x22, #0xb996
   988b4: 7100011f     	cmp	w8, #0x0
   988b8: d29582c8     	mov	x8, #0xac16
   988bc: f2a26bc8     	movk	x8, #0x135e, lsl #16
   988c0: f2b65ca9     	movk	x9, #0xb2e5, lsl #16
   988c4: f2b202ed     	movk	x13, #0x9017, lsl #16
   988c8: f2bc952c     	movk	x12, #0xe4a9, lsl #16
   988cc: f2ab736b     	movk	x11, #0x5b9b, lsl #16
   988d0: f2ad1e76     	movk	x22, #0x68f3, lsl #16
   988d4: f2c1e528     	movk	x8, #0xf29, lsl #32
   988d8: f2cfbae9     	movk	x9, #0x7dd7, lsl #32
   988dc: f2ccfe2d     	movk	x13, #0x67f1, lsl #32
   988e0: f2dac0ac     	movk	x12, #0xd605, lsl #32
   988e4: f2dbdfeb     	movk	x11, #0xdeff, lsl #32
   988e8: f2c9e8d6     	movk	x22, #0x4f46, lsl #32
   988ec: f2e60048     	movk	x8, #0x3002, lsl #48
   988f0: f2ed9b49     	movk	x9, #0x6cda, lsl #48
   988f4: f2fc45cd     	movk	x13, #0xe22e, lsl #48
   988f8: f2fc31ac     	movk	x12, #0xe18d, lsl #48
   988fc: f2fddaeb     	movk	x11, #0xeed7, lsl #48
   98900: f2ff01d6     	movk	x22, #0xf80e, lsl #48
   98904: 9a880129     	csel	x9, x9, x8, eq
   98908: 17fffe3d     	b	0x981fc <.text+0x8f61c>
   9890c: f85d83a8     	ldur	x8, [x29, #-0x28]
   98910: f85903a9     	ldur	x9, [x29, #-0x70]
   98914: 39400108     	ldrb	w8, [x8]
   98918: f9401529     	ldr	x9, [x9, #0x28]
   9891c: f85f83aa     	ldur	x10, [x29, #-0x8]
   98920: 7100011f     	cmp	w8, #0x0
   98924: 1a9f07e0     	cset	w0, ne
   98928: eb0a013f     	cmp	x9, x10
   9892c: 54000121     	b.ne	0x98950 <.text+0x8fd70>
   98930: 910003bf     	mov	sp, x29
   98934: a9454ff4     	ldp	x20, x19, [sp, #0x50]
   98938: a94457f6     	ldp	x22, x21, [sp, #0x40]
   9893c: a9435ff8     	ldp	x24, x23, [sp, #0x30]
   98940: a94267fa     	ldp	x26, x25, [sp, #0x20]
   98944: a9416ffc     	ldp	x28, x27, [sp, #0x10]
   98948: a8c67bfd     	ldp	x29, x30, [sp], #0x60
   9894c: d65f03c0     	ret
   98950: 9402c030     	bl	0x148a10 <__stack_chk_fail@plt>
   98954: d10343ff     	sub	sp, sp, #0xd0
   98958: a9077bfd     	stp	x29, x30, [sp, #0x70]
   9895c: a9086ffc     	stp	x28, x27, [sp, #0x80]
   98960: a90967fa     	stp	x26, x25, [sp, #0x90]
   98964: a90a5ff8     	stp	x24, x23, [sp, #0xa0]
   98968: a90b57f6     	stp	x22, x21, [sp, #0xb0]
   9896c: a90c4ff4     	stp	x20, x19, [sp, #0xc0]
   98970: 9101c3fd     	add	x29, sp, #0x70
   98974: a93d93a3     	stp	x3, x4, [x29, #-0x28]
   98978: d53bd048     	mrs	x8, TPIDR_EL0
   9897c: f90007e8     	str	x8, [sp, #0x8]
   98980: d290101c     	mov	x28, #0x8080
   98984: f9401508     	ldr	x8, [x8, #0x28]
   98988: d28fe893     	mov	x19, #0x7f44
   9898c: d10043a3     	sub	x3, x29, #0x10
   98990: d10053a4     	sub	x4, x29, #0x14
   98994: f2aa75bc     	movk	x28, #0x53ad, lsl #16
   98998: f2afbed3     	movk	x19, #0x7df6, lsl #16
   9899c: f2d3b67c     	movk	x28, #0x9db3, lsl #32
   989a0: f2c757f3     	movk	x19, #0x3abf, lsl #32
   989a4: aa0003f4     	mov	x20, x0
   989a8: f2f170fc     	movk	x28, #0x8b87, lsl #48
   989ac: f81f83a8     	stur	x8, [x29, #-0x8]
   989b0: f2e32ed3     	movk	x19, #0x1976, lsl #48
   989b4: f81f03bf     	stur	xzr, [x29, #-0x10]
   989b8: b81ec3bf     	stur	wzr, [x29, #-0x14]
   989bc: a9010be1     	stp	x1, x2, [sp, #0x10]
   989c0: 940015fc     	bl	0x9e1b0 <.text+0x955d0>
   989c4: f81d03b4     	stur	x20, [x29, #-0x30]
   989c8: b9400288     	ldr	w8, [x20]
   989cc: d2902ab4     	mov	x20, #0x8155
   989d0: d2910237     	mov	x23, #0x8811
   989d4: f2bb7b94     	movk	x20, #0xdbdc, lsl #16
   989d8: f2b85af7     	movk	x23, #0xc2d7, lsl #16
   989dc: d297f4fb     	mov	x27, #0xbfa7
   989e0: d2938f95     	mov	x21, #0x9c7c
   989e4: d2888c6b     	mov	x11, #0x4463
   989e8: d28011b6     	mov	x22, #0x8d
   989ec: d289172c     	mov	x12, #0x48b9
   989f0: d2863efa     	mov	x26, #0x31f7
   989f4: d297f4e9     	mov	x9, #0xbfa7
   989f8: f2d7e434     	movk	x20, #0xbf21, lsl #32
   989fc: f2c4f2b7     	movk	x23, #0x2795, lsl #32
   98a00: f2ac2cdb     	movk	x27, #0x6166, lsl #16
   98a04: f2b2c135     	movk	x21, #0x9609, lsl #16
   98a08: f2be2f6b     	movk	x11, #0xf17b, lsl #16
   98a0c: f2a8c656     	movk	x22, #0x4632, lsl #16
   98a10: f2be55ec     	movk	x12, #0xf2af, lsl #16
   98a14: f2a0e73a     	movk	x26, #0x739, lsl #16
   98a18: f2ac2cc9     	movk	x9, #0x6166, lsl #16
   98a1c: f2fcbe54     	movk	x20, #0xe5f2, lsl #48
   98a20: f2e34937     	movk	x23, #0x1a49, lsl #48
   98a24: f2d7131b     	movk	x27, #0xb898, lsl #32
   98a28: f2dcaed5     	movk	x21, #0xe576, lsl #32
   98a2c: f2d1ffcb     	movk	x11, #0x8ffe, lsl #32
   98a30: f2c5f136     	movk	x22, #0x2f89, lsl #32
   98a34: 7100011f     	cmp	w8, #0x0
   98a38: f2dacb6c     	movk	x12, #0xd65b, lsl #32
   98a3c: f2c1979a     	movk	x26, #0xcbc, lsl #32
   98a40: f2d71309     	movk	x9, #0xb898, lsl #32
   98a44: f2fa043b     	movk	x27, #0xd021, lsl #48
   98a48: f2fcb6f5     	movk	x21, #0xe5b7, lsl #48
   98a4c: f2e9ee4b     	movk	x11, #0x4f72, lsl #48
   98a50: f2e020b6     	movk	x22, #0x105, lsl #48
   98a54: f2e92aec     	movk	x12, #0x4957, lsl #48
   98a58: 9a9402f8     	csel	x24, x23, x20, eq
   98a5c: f2e3561a     	movk	x26, #0x1ab0, lsl #48
   98a60: f2fa0429     	movk	x9, #0xd021, lsl #48
   98a64: f9001fe8     	str	x8, [sp, #0x38]
   98a68: eb1c013f     	cmp	x9, x28
   98a6c: 540015e0     	b.eq	0x98d28 <.text+0x90148>
   98a70: aa0903e8     	mov	x8, x9
   98a74: aa1803e9     	mov	x9, x24
   98a78: eb1b011f     	cmp	x8, x27
   98a7c: 54ffff60     	b.eq	0x98a68 <.text+0x8fe88>
   98a80: eb15011f     	cmp	x8, x21
   98a84: 54000820     	b.eq	0x98b88 <.text+0x8ffa8>
   98a88: d2887c29     	mov	x9, #0x43e1
   98a8c: eb14011f     	cmp	x8, x20
   98a90: f2a0e529     	movk	x9, #0x729, lsl #16
   98a94: f2c406a9     	movk	x9, #0x2035, lsl #32
   98a98: f2e35949     	movk	x9, #0x1aca, lsl #48
   98a9c: 54fffe60     	b.eq	0x98a68 <.text+0x8fe88>
   98aa0: eb16011f     	cmp	x8, x22
   98aa4: 54001340     	b.eq	0x98d0c <.text+0x9012c>
   98aa8: eb13011f     	cmp	x8, x19
   98aac: 54000980     	b.eq	0x98bdc <.text+0x8fffc>
   98ab0: eb17011f     	cmp	x8, x23
   98ab4: 540009c0     	b.eq	0x98bec <.text+0x9000c>
   98ab8: d282f7e9     	mov	x9, #0x17bf
   98abc: eb1a011f     	cmp	x8, x26
   98ac0: f2a84aa9     	movk	x9, #0x4255, lsl #16
   98ac4: f2d41fc9     	movk	x9, #0xa0fe, lsl #32
   98ac8: f2e3ea69     	movk	x9, #0x1f53, lsl #48
   98acc: 54fffce0     	b.eq	0x98a68 <.text+0x8fe88>
   98ad0: d2887c29     	mov	x9, #0x43e1
   98ad4: f2a0e529     	movk	x9, #0x729, lsl #16
   98ad8: f2c406a9     	movk	x9, #0x2035, lsl #32
   98adc: f2e35949     	movk	x9, #0x1aca, lsl #48
   98ae0: eb09011f     	cmp	x8, x9
   98ae4: 54000960     	b.eq	0x98c10 <.text+0x90030>
   98ae8: d282f7e9     	mov	x9, #0x17bf
   98aec: f2a84aa9     	movk	x9, #0x4255, lsl #16
   98af0: f2d41fc9     	movk	x9, #0xa0fe, lsl #32
   98af4: f2e3ea69     	movk	x9, #0x1f53, lsl #48
   98af8: eb09011f     	cmp	x8, x9
   98afc: 54000cc0     	b.eq	0x98c94 <.text+0x900b4>
   98b00: eb0c011f     	cmp	x8, x12
   98b04: 54000a80     	b.eq	0x98c54 <.text+0x90074>
   98b08: eb0b011f     	cmp	x8, x11
   98b0c: 54000de0     	b.eq	0x98cc8 <.text+0x900e8>
   98b10: d2866709     	mov	x9, #0x3338
   98b14: d2963d0a     	mov	x10, #0xb1e8
   98b18: f2ac8189     	movk	x9, #0x640c, lsl #16
   98b1c: f2a6614a     	movk	x10, #0x330a, lsl #16
   98b20: f2c0a1a9     	movk	x9, #0x50d, lsl #32
   98b24: f2ca638a     	movk	x10, #0x531c, lsl #32
   98b28: f2eddcc9     	movk	x9, #0x6ee6, lsl #48
   98b2c: f2eafa0a     	movk	x10, #0x57d0, lsl #48
   98b30: eb0a011f     	cmp	x8, x10
   98b34: 54fff9a0     	b.eq	0x98a68 <.text+0x8fe88>
   98b38: d29cb789     	mov	x9, #0xe5bc
   98b3c: f2a9a989     	movk	x9, #0x4d4c, lsl #16
   98b40: f2d98d29     	movk	x9, #0xcc69, lsl #32
   98b44: f2ec17e9     	movk	x9, #0x60bf, lsl #48
   98b48: eb09011f     	cmp	x8, x9
   98b4c: 540006e0     	b.eq	0x98c28 <.text+0x90048>
   98b50: d29295a9     	mov	x9, #0x94ad
   98b54: f2a3ff49     	movk	x9, #0x1ffa, lsl #16
   98b58: f2d78ec9     	movk	x9, #0xbc76, lsl #32
   98b5c: f2ed72a9     	movk	x9, #0x6b95, lsl #48
   98b60: eb09011f     	cmp	x8, x9
   98b64: 54000660     	b.eq	0x98c30 <.text+0x90050>
   98b68: d286670a     	mov	x10, #0x3338
   98b6c: aa0803e9     	mov	x9, x8
   98b70: f2ac818a     	movk	x10, #0x640c, lsl #16
   98b74: f2c0a1aa     	movk	x10, #0x50d, lsl #32
   98b78: f2eddcca     	movk	x10, #0x6ee6, lsl #48
   98b7c: eb0a011f     	cmp	x8, x10
   98b80: 54fff741     	b.ne	0x98a68 <.text+0x8fe88>
   98b84: 14000071     	b	0x98d48 <.text+0x90168>
   98b88: f9401fe8     	ldr	x8, [sp, #0x38]
   98b8c: 52800021     	mov	w1, #0x1
   98b90: 93407d00     	sxtw	x0, w8
   98b94: f85d83a8     	ldur	x8, [x29, #-0x28]
   98b98: f9000100     	str	x0, [x8]
   98b9c: f9001be0     	str	x0, [sp, #0x30]
   98ba0: 9402bffc     	bl	0x148b90 <calloc@plt>
   98ba4: d2888c6b     	mov	x11, #0x4463
   98ba8: d289172c     	mov	x12, #0x48b9
   98bac: f2be2f6b     	movk	x11, #0xf17b, lsl #16
   98bb0: f85e03a8     	ldur	x8, [x29, #-0x20]
   98bb4: f2be55ec     	movk	x12, #0xf2af, lsl #16
   98bb8: f2d1ffcb     	movk	x11, #0x8ffe, lsl #32
   98bbc: f2dacb6c     	movk	x12, #0xd65b, lsl #32
   98bc0: f2e9ee4b     	movk	x11, #0x4f72, lsl #48
   98bc4: f100001f     	cmp	x0, #0x0
   98bc8: f2e92aec     	movk	x12, #0x4957, lsl #48
   98bcc: 9a8b02c9     	csel	x9, x22, x11, eq
   98bd0: f90017e0     	str	x0, [sp, #0x28]
   98bd4: f9000100     	str	x0, [x8]
   98bd8: 17ffffa4     	b	0x98a68 <.text+0x8fe88>
   98bdc: f100033f     	cmp	x25, #0x0
   98be0: f90013f9     	str	x25, [sp, #0x20]
   98be4: 9a8c0349     	csel	x9, x26, x12, eq
   98be8: 17ffffa0     	b	0x98a68 <.text+0x8fe88>
   98bec: b85ec3a8     	ldur	w8, [x29, #-0x14]
   98bf0: f9001fe8     	str	x8, [sp, #0x38]
   98bf4: 7100011f     	cmp	w8, #0x0
   98bf8: d29cb788     	mov	x8, #0xe5bc
   98bfc: f2a9a988     	movk	x8, #0x4d4c, lsl #16
   98c00: f2d98d28     	movk	x8, #0xcc69, lsl #32
   98c04: f2ec17e8     	movk	x8, #0x60bf, lsl #48
   98c08: 9a950109     	csel	x9, x8, x21, eq
   98c0c: 17ffff97     	b	0x98a68 <.text+0x8fe88>
   98c10: d28fe889     	mov	x9, #0x7f44
   98c14: f85f03b9     	ldur	x25, [x29, #-0x10]
   98c18: f2afbec9     	movk	x9, #0x7df6, lsl #16
   98c1c: f2c757e9     	movk	x9, #0x3abf, lsl #32
   98c20: f2e32ec9     	movk	x9, #0x1976, lsl #48
   98c24: 17ffff91     	b	0x98a68 <.text+0x8fe88>
   98c28: 52800388     	mov	w8, #0x1c
   98c2c: 14000039     	b	0x98d10 <.text+0x90130>
   98c30: f85d83a8     	ldur	x8, [x29, #-0x28]
   98c34: d2866709     	mov	x9, #0x3338
   98c38: f2ac8189     	movk	x9, #0x640c, lsl #16
   98c3c: f2c0a1a9     	movk	x9, #0x50d, lsl #32
   98c40: f900011f     	str	xzr, [x8]
   98c44: f85e03a8     	ldur	x8, [x29, #-0x20]
   98c48: f2eddcc9     	movk	x9, #0x6ee6, lsl #48
   98c4c: f900011f     	str	xzr, [x8]
   98c50: 17ffff86     	b	0x98a68 <.text+0x8fe88>
   98c54: a94107e0     	ldp	x0, x1, [sp, #0x10]
   98c58: f94013e2     	ldr	x2, [sp, #0x20]
   98c5c: 94001734     	bl	0x9e92c <.text+0x95d4c>
   98c60: d289172c     	mov	x12, #0x48b9
   98c64: d2888c6b     	mov	x11, #0x4463
   98c68: d282f7e9     	mov	x9, #0x17bf
   98c6c: f2be55ec     	movk	x12, #0xf2af, lsl #16
   98c70: f2be2f6b     	movk	x11, #0xf17b, lsl #16
   98c74: f2a84aa9     	movk	x9, #0x4255, lsl #16
   98c78: f2dacb6c     	movk	x12, #0xd65b, lsl #32
   98c7c: f2d1ffcb     	movk	x11, #0x8ffe, lsl #32
   98c80: f2d41fc9     	movk	x9, #0xa0fe, lsl #32
   98c84: f2e92aec     	movk	x12, #0x4957, lsl #48
   98c88: f2e9ee4b     	movk	x11, #0x4f72, lsl #48
   98c8c: f2e3ea69     	movk	x9, #0x1f53, lsl #48
   98c90: 17ffff76     	b	0x98a68 <.text+0x8fe88>
   98c94: f85d03a8     	ldur	x8, [x29, #-0x30]
   98c98: d2963d09     	mov	x9, #0xb1e8
   98c9c: f2a66149     	movk	x9, #0x330a, lsl #16
   98ca0: f2ca6389     	movk	x9, #0x531c, lsl #32
   98ca4: b9400108     	ldr	w8, [x8]
   98ca8: f2eafa09     	movk	x9, #0x57d0, lsl #48
   98cac: 7100011f     	cmp	w8, #0x0
   98cb0: d29295a8     	mov	x8, #0x94ad
   98cb4: f2a3ff48     	movk	x8, #0x1ffa, lsl #16
   98cb8: f2d78ec8     	movk	x8, #0xbc76, lsl #32
   98cbc: f2ed72a8     	movk	x8, #0x6b95, lsl #48
   98cc0: 9a880129     	csel	x9, x9, x8, eq
   98cc4: 17ffff69     	b	0x98a68 <.text+0x8fe88>
   98cc8: f85f03b9     	ldur	x25, [x29, #-0x10]
   98ccc: a9428be0     	ldp	x0, x2, [sp, #0x28]
   98cd0: aa1903e1     	mov	x1, x25
   98cd4: 9402bfb3     	bl	0x148ba0 <memcpy@plt>
   98cd8: d289172c     	mov	x12, #0x48b9
   98cdc: d2888c6b     	mov	x11, #0x4463
   98ce0: d28fe889     	mov	x9, #0x7f44
   98ce4: f2be55ec     	movk	x12, #0xf2af, lsl #16
   98ce8: f2be2f6b     	movk	x11, #0xf17b, lsl #16
   98cec: f2afbec9     	movk	x9, #0x7df6, lsl #16
   98cf0: f2dacb6c     	movk	x12, #0xd65b, lsl #32
   98cf4: f2d1ffcb     	movk	x11, #0x8ffe, lsl #32
   98cf8: f2c757e9     	movk	x9, #0x3abf, lsl #32
   98cfc: f2e92aec     	movk	x12, #0x4957, lsl #48
   98d00: f2e9ee4b     	movk	x11, #0x4f72, lsl #48
   98d04: f2e32ec9     	movk	x9, #0x1976, lsl #48
   98d08: 17ffff58     	b	0x98a68 <.text+0x8fe88>
   98d0c: 52800048     	mov	w8, #0x2
   98d10: d2901009     	mov	x9, #0x8080
   98d14: b81e83a8     	stur	w8, [x29, #-0x18]
   98d18: f2aa75a9     	movk	x9, #0x53ad, lsl #16
   98d1c: f2d3b669     	movk	x9, #0x9db3, lsl #32
   98d20: f2f170e9     	movk	x9, #0x8b87, lsl #48
   98d24: 17ffff51     	b	0x98a68 <.text+0x8fe88>
   98d28: d2887c29     	mov	x9, #0x43e1
   98d2c: f85d03a8     	ldur	x8, [x29, #-0x30]
   98d30: b85e83aa     	ldur	w10, [x29, #-0x18]
   98d34: f2a0e529     	movk	x9, #0x729, lsl #16
   98d38: f2c406a9     	movk	x9, #0x2035, lsl #32
   98d3c: f2e35949     	movk	x9, #0x1aca, lsl #48
   98d40: b900010a     	str	w10, [x8]
   98d44: 17ffff49     	b	0x98a68 <.text+0x8fe88>
   98d48: f94007e8     	ldr	x8, [sp, #0x8]
   98d4c: f9401508     	ldr	x8, [x8, #0x28]
   98d50: f85f83a9     	ldur	x9, [x29, #-0x8]
   98d54: eb09011f     	cmp	x8, x9
   98d58: 54000121     	b.ne	0x98d7c <.text+0x9019c>
   98d5c: a94c4ff4     	ldp	x20, x19, [sp, #0xc0]
   98d60: a94b57f6     	ldp	x22, x21, [sp, #0xb0]
   98d64: a94a5ff8     	ldp	x24, x23, [sp, #0xa0]
   98d68: a94967fa     	ldp	x26, x25, [sp, #0x90]
   98d6c: a9486ffc     	ldp	x28, x27, [sp, #0x80]
   98d70: a9477bfd     	ldp	x29, x30, [sp, #0x70]
   98d74: 910343ff     	add	sp, sp, #0xd0
   98d78: d65f03c0     	ret
   98d7c: 9402bf25     	bl	0x148a10 <__stack_chk_fail@plt>
   98d80: d10303ff     	sub	sp, sp, #0xc0
   98d84: a9067bfd     	stp	x29, x30, [sp, #0x60]
   98d88: a9076ffc     	stp	x28, x27, [sp, #0x70]
   98d8c: a90867fa     	stp	x26, x25, [sp, #0x80]
   98d90: a9095ff8     	stp	x24, x23, [sp, #0x90]
   98d94: a90a57f6     	stp	x22, x21, [sp, #0xa0]
   98d98: a90b4ff4     	stp	x20, x19, [sp, #0xb0]
   98d9c: 910183fd     	add	x29, sp, #0x60
   98da0: 51000449     	sub	w9, w2, #0x1
   98da4: f81d83a5     	stur	x5, [x29, #-0x28]
   98da8: f9001be4     	str	x4, [sp, #0x30]
   98dac: d28b5bb8     	mov	x24, #0x5add
   98db0: f9000fe3     	str	x3, [sp, #0x18]
   98db4: d53bd048     	mrs	x8, TPIDR_EL0
   98db8: f90007e8     	str	x8, [sp, #0x8]
   98dbc: f100003f     	cmp	x1, #0x0
   98dc0: f9401508     	ldr	x8, [x8, #0x28]
   98dc4: b90017e9     	str	w9, [sp, #0x14]
   98dc8: 1a9f07e9     	cset	w9, ne
   98dcc: f2a65738     	movk	x24, #0x32b9, lsl #16
   98dd0: f2d40fb8     	movk	x24, #0xa07d, lsl #32
   98dd4: f100005f     	cmp	x2, #0x0
   98dd8: f2f68c98     	movk	x24, #0xb464, lsl #48
   98ddc: d28c88aa     	mov	x10, #0x6445
   98de0: b90013e9     	str	w9, [sp, #0x10]
   98de4: d293bda9     	mov	x9, #0x9ded
   98de8: f2aba1c9     	movk	x9, #0x5d0e, lsl #16
   98dec: d28aaf6b     	mov	x11, #0x557b
   98df0: f2c14d09     	movk	x9, #0xa68, lsl #32
   98df4: d2809cb5     	mov	x21, #0x4e5
   98df8: f2ed0109     	movk	x9, #0x6808, lsl #48
   98dfc: d29cf113     	mov	x19, #0xe788
   98e00: 9a980134     	csel	x20, x9, x24, eq
   98e04: d295f059     	mov	x25, #0xaf82
   98e08: d295b49a     	mov	x26, #0xada4
   98e0c: d288dc1c     	mov	x28, #0x46e0
   98e10: d28b557b     	mov	x27, #0x5aab
   98e14: d29cf109     	mov	x9, #0xe788
   98e18: f2a9216a     	movk	x10, #0x490b, lsl #16
   98e1c: f2a2f86b     	movk	x11, #0x17c3, lsl #16
   98e20: f2a46f15     	movk	x21, #0x2378, lsl #16
   98e24: f2be9cd3     	movk	x19, #0xf4e6, lsl #16
   98e28: f2ae53f9     	movk	x25, #0x729f, lsl #16
   98e2c: f2ae85fa     	movk	x26, #0x742f, lsl #16
   98e30: f2a4c75c     	movk	x28, #0x263a, lsl #16
   98e34: f2a67c5b     	movk	x27, #0x33e2, lsl #16
   98e38: f2be9cc9     	movk	x9, #0xf4e6, lsl #16
   98e3c: f2cf002a     	movk	x10, #0x7801, lsl #32
   98e40: f2c1dccb     	movk	x11, #0xee6, lsl #32
   98e44: f2da44d5     	movk	x21, #0xd226, lsl #32
   98e48: f2ccffb3     	movk	x19, #0x67fd, lsl #32
   98e4c: f2d9ac79     	movk	x25, #0xcd63, lsl #32
   98e50: f2d5d15a     	movk	x26, #0xae8a, lsl #32
   98e54: f2d30edc     	movk	x28, #0x9876, lsl #32
   98e58: f2d7b1bb     	movk	x27, #0xbd8d, lsl #32
   98e5c: f2ccffa9     	movk	x9, #0x67fd, lsl #32
   98e60: aa0103f6     	mov	x22, x1
   98e64: aa0003f7     	mov	x23, x0
   98e68: f2ff974a     	movk	x10, #0xfcba, lsl #48
   98e6c: f2fac52b     	movk	x11, #0xd629, lsl #48
   98e70: f2f45455     	movk	x21, #0xa2a2, lsl #48
   98e74: f2f00493     	movk	x19, #0x8024, lsl #48
   98e78: f2f28bf9     	movk	x25, #0x945f, lsl #48
   98e7c: f2f577da     	movk	x26, #0xabbe, lsl #48
   98e80: f2f6449c     	movk	x28, #0xb224, lsl #48
   98e84: f2e568db     	movk	x27, #0x2b46, lsl #48
   98e88: f2f00489     	movk	x9, #0x8024, lsl #48
   98e8c: f81f83a8     	stur	x8, [x29, #-0x8]
   98e90: f81f03bf     	stur	xzr, [x29, #-0x10]
   98e94: aa0903e8     	mov	x8, x9
   98e98: aa1403e9     	mov	x9, x20
   98e9c: eb13011f     	cmp	x8, x19
   98ea0: 54ffffa0     	b.eq	0x98e94 <.text+0x902b4>
   98ea4: d28c88a9     	mov	x9, #0x6445
   98ea8: eb19011f     	cmp	x8, x25
   98eac: f2a92169     	movk	x9, #0x490b, lsl #16
   98eb0: f2cf0029     	movk	x9, #0x7801, lsl #32
   98eb4: f2ff9749     	movk	x9, #0xfcba, lsl #48
   98eb8: 54fffee0     	b.eq	0x98e94 <.text+0x902b4>
   98ebc: eb15011f     	cmp	x8, x21
   98ec0: 54001ba0     	b.eq	0x99234 <.text+0x90654>
   98ec4: eb1a011f     	cmp	x8, x26
   98ec8: 540008a0     	b.eq	0x98fdc <.text+0x903fc>
   98ecc: eb1c011f     	cmp	x8, x28
   98ed0: 54fffe20     	b.eq	0x98e94 <.text+0x902b4>
   98ed4: eb18011f     	cmp	x8, x24
   98ed8: 540016a0     	b.eq	0x991ac <.text+0x905cc>
   98edc: eb0b011f     	cmp	x8, x11
   98ee0: 54000a80     	b.eq	0x99030 <.text+0x90450>
   98ee4: eb0a011f     	cmp	x8, x10
   98ee8: 54000bc0     	b.eq	0x99060 <.text+0x90480>
   98eec: d2809ca9     	mov	x9, #0x4e5
   98ef0: eb1b011f     	cmp	x8, x27
   98ef4: f2a46f09     	movk	x9, #0x2378, lsl #16
   98ef8: f2da44c9     	movk	x9, #0xd226, lsl #32
   98efc: f2f45449     	movk	x9, #0xa2a2, lsl #48
   98f00: 54fffca0     	b.eq	0x98e94 <.text+0x902b4>
   98f04: d28bb5a9     	mov	x9, #0x5dad
   98f08: f2a6fc29     	movk	x9, #0x37e1, lsl #16
   98f0c: f2c36989     	movk	x9, #0x1b4c, lsl #32
   98f10: f2e58549     	movk	x9, #0x2c2a, lsl #48
   98f14: eb09011f     	cmp	x8, x9
   98f18: 54000cc0     	b.eq	0x990b0 <.text+0x904d0>
   98f1c: d28582e9     	mov	x9, #0x2c17
   98f20: f2b7cfa9     	movk	x9, #0xbe7d, lsl #16
   98f24: f2d1f189     	movk	x9, #0x8f8c, lsl #32
   98f28: f2e92b69     	movk	x9, #0x495b, lsl #48
   98f2c: eb09011f     	cmp	x8, x9
   98f30: 54000f40     	b.eq	0x99118 <.text+0x90538>
   98f34: d29c4f49     	mov	x9, #0xe27a
   98f38: f2ae1de9     	movk	x9, #0x70ef, lsl #16
   98f3c: f2ddf309     	movk	x9, #0xef98, lsl #32
   98f40: f2e97649     	movk	x9, #0x4bb2, lsl #48
   98f44: eb09011f     	cmp	x8, x9
   98f48: 54000c40     	b.eq	0x990d0 <.text+0x904f0>
   98f4c: d293bda9     	mov	x9, #0x9ded
   98f50: f2aba1c9     	movk	x9, #0x5d0e, lsl #16
   98f54: f2c14d09     	movk	x9, #0xa68, lsl #32
   98f58: f2ed0109     	movk	x9, #0x6808, lsl #48
   98f5c: eb09011f     	cmp	x8, x9
   98f60: 54001140     	b.eq	0x99188 <.text+0x905a8>
   98f64: d2984c89     	mov	x9, #0xc264
   98f68: d2967aac     	mov	x12, #0xb3d5
   98f6c: f2a7a989     	movk	x9, #0x3d4c, lsl #16
   98f70: f2b7914c     	movk	x12, #0xbc8a, lsl #16
   98f74: f2dd0109     	movk	x9, #0xe808, lsl #32
   98f78: f2cff62c     	movk	x12, #0x7fb1, lsl #32
   98f7c: f2f8f0c9     	movk	x9, #0xc786, lsl #48
   98f80: f2eef5ac     	movk	x12, #0x77ad, lsl #48
   98f84: eb0c011f     	cmp	x8, x12
   98f88: 54fff860     	b.eq	0x98e94 <.text+0x902b4>
   98f8c: d28e53e9     	mov	x9, #0x729f
   98f90: f2b4e989     	movk	x9, #0xa74c, lsl #16
   98f94: f2d18c29     	movk	x9, #0x8c61, lsl #32
   98f98: f2eef649     	movk	x9, #0x77b2, lsl #48
   98f9c: eb09011f     	cmp	x8, x9
   98fa0: 54000ce0     	b.eq	0x9913c <.text+0x9055c>
   98fa4: d2977d89     	mov	x9, #0xbbec
   98fa8: f2a578a9     	movk	x9, #0x2bc5, lsl #16
   98fac: f2cd9b69     	movk	x9, #0x6cdb, lsl #32
   98fb0: f2ef7349     	movk	x9, #0x7b9a, lsl #48
   98fb4: eb09011f     	cmp	x8, x9
   98fb8: 540006e0     	b.eq	0x99094 <.text+0x904b4>
   98fbc: d2984c8c     	mov	x12, #0xc264
   98fc0: aa0803e9     	mov	x9, x8
